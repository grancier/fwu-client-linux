"""The update driver: preflight gates, then START / DATA / END.

Command codes 2, 4 and 6 were confirmed implemented on CSME 15.0.42.2384 by
`fwu.probe`, which also showed the reply sizes match the CSME 12 layout
(START 24 B, DATA 8 B). The whole sequence runs on one `FwuSession`, because
the ME tracks update state per connection.

On the UpdateEnvironment byte: the ME validates it and answers a wrong value
with a rejection, so a mis-guessed constant fails closed without starting
anything. `discover_env` tries to pin it down first regardless.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from . import fwcaps, mkhi, preflight, update
from .session import FwuSession, one_shot

# Statuses observed live on this platform. Anything absent is reported raw.
STATUS_TEXT = {
    0x000: "success",
    0x08D: "command not recognised",
    0x2BE: "busy, retry",
    0x2C0: "rejected: invalid parameters or message length",
    0x2C4: "rejected: wrong state for this command",
    0x081: "rejected: invalid UpdateEnvironment",
    0x206: "rejected: invalid image length",
}

SYSFS = "/sys/class/mei/mei0"


def status_text(status: int) -> str:
    return STATUS_TEXT.get(status, f"undocumented status 0x{status:X}")


class UpdateAborted(RuntimeError):
    """The sequence stopped. The ME has not committed anything."""


@dataclass
class Preflight:
    image: object
    running_version: tuple = ()
    updatable_size: int = 0
    local_update_enabled: bool = False
    dev_state: str = ""
    installed_iups: list = field(default_factory=list)
    problems: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def _sysfs(name):
    try:
        with open(f"{SYSFS}/{name}") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def run_preflight(image_path, device=None, expect_sha256=None) -> Preflight:
    """Every gate that can fail before a single byte is sent."""
    from . import fwu as fwu_mod

    with open(image_path, "rb") as handle:
        image = preflight.parse_image(handle.read())

    report = Preflight(image=image)
    report.problems.extend(preflight.check_structure(image))

    if expect_sha256 and image.sha256.lower() != expect_sha256.lower():
        report.problems.append(
            f"image sha256 {image.sha256} does not match expected "
            f"{expect_sha256}")

    report.dev_state = _sysfs("dev_state")
    if report.dev_state != "ENABLED":
        report.problems.append(
            f"ME device state is {report.dev_state or 'unreadable'}, "
            "expected ENABLED")

    try:
        versions = dict(mkhi.get_fw_version(device))
        running = tuple(int(x) for x in versions["operational"].split("."))
        report.running_version = running
    except Exception as exc:  # noqa: BLE001 - any failure here is a hard gate
        report.problems.append(f"cannot read running version: {exc}")
        running = None

    try:
        _, enabled = fwcaps.local_fw_update_state(device)
        report.local_update_enabled = enabled
        if not enabled:
            report.problems.append(
                "FWCAPS rule 7 reports local firmware update DISABLED")
    except Exception as exc:  # noqa: BLE001
        report.problems.append(f"cannot read FWCAPS rule 7: {exc}")

    try:
        report.updatable_size = fwu_mod.get_updatable_size(device)
    except Exception as exc:  # noqa: BLE001
        report.problems.append(f"cannot read updatable size: {exc}")

    try:
        report.installed_iups = fwu_mod.get_iup_inventory(device)
    except Exception:  # noqa: BLE001 - informational only
        report.installed_iups = []

    if running:
        report.problems.extend(preflight.check_against_platform(
            image, running, report.updatable_size or None))

    return report


def discover_env(device=None):
    """Try to pin down FWU_ENV_MANUFACTURING without starting an update.

    Sends START packets that are invalid on purpose: image_length 0 cannot
    begin an update. If the ME validates the environment byte before the
    length, a legal value produces a different status from an illegal one and
    is identified. If it validates length first, every row matches and this
    returns None, which is not fatal: a wrong environment byte is rejected.

    Returns (value_or_None, rows) where rows is a list of (env, status).
    """
    import struct

    def packet(image_length, env):
        buf = bytearray(update.START_MSG_SIZE)
        struct.pack_into("<I", buf, 0, update.CMD_FWU_START)
        struct.pack_into("<I", buf, 4, image_length)
        buf[update._START_ENV_OFFSET] = env & 0xFF
        return bytes(buf)

    rows = []
    for env in (0x00, 0x01, 0x02, 0x5A):
        with FwuSession(device=device) as session:
            reply = session.send_raw(packet(0, env))
        rows.append((env, reply.status))

    bogus = dict(rows)[0x5A]
    distinct = [env for env, status in rows
                if env != 0x5A and status != bogus]
    return (distinct[0] if len(distinct) == 1 else None), rows


def run_update(image_bytes, device=None, env=update.FWU_ENV_MANUFACTURING,
               oem_id=None, progress=None, data_timeout=10.0,
               start_timeout=10.0, end_timeout=600.0):
    """Send START, every DATA chunk, then END, on one connection.

    Raises UpdateAborted on the first non-success status. Returns the END
    reply on success.
    """
    with FwuSession(device=device) as session:
        plan = update.plan_update(image_bytes, session.max_msg,
                                  update_env=env, oem_id=oem_id)

        reply = session.send_raw(plan.start_packet(), timeout=start_timeout)
        if not reply.ok:
            raise UpdateAborted(
                f"FWU_START refused: {status_text(reply.status)} "
                f"(code 0x{reply.code:X}, status 0x{reply.status:X}). "
                "Nothing was written.")
        if progress:
            progress("start", 0, plan.chunk_count, reply)

        sent = 0
        for index, packet in enumerate(plan.iter_data_packets(), start=1):
            reply = session.send_raw(packet, timeout=data_timeout)
            if not reply.ok:
                raise UpdateAborted(
                    f"FWU_DATA chunk {index}/{plan.chunk_count} refused: "
                    f"{status_text(reply.status)} "
                    f"(status 0x{reply.status:X}) after {sent} B. "
                    "The ME has not committed; the old firmware is intact.")
            sent += len(packet) - update.DATA_HEADER_SIZE
            if progress:
                progress("data", index, plan.chunk_count, reply)

        reply = session.send_raw(update.pack_end(), timeout=end_timeout)
        if not reply.ok:
            raise UpdateAborted(
                f"FWU_END refused: {status_text(reply.status)} "
                f"(status 0x{reply.status:X}). The image was not accepted.")
        if progress:
            progress("end", plan.chunk_count, plan.chunk_count, reply)
        return reply


def poll_status(device=None, attempts=30, interval=2.0):
    """Read FWU status (command 0x12) repeatedly after END."""
    from . import fwu as fwu_mod

    seen = []
    for _ in range(attempts):
        try:
            reply = one_shot(fwu_mod.CMD_QUERY_12, device=device)
            seen.append(reply.data.hex(" "))
            if reply.data and any(reply.data):
                break
        except Exception:  # noqa: BLE001 - ME may be busy mid-verify
            seen.append("(unreachable)")
        time.sleep(interval)
    return seen
