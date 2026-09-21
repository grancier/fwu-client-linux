"""The FWU client protocol.

Unlike MKHI, the FWU client takes no group/command header. A request is a
bare little-endian u32 command, optionally followed by a payload. The reply
opens with a u32 response code and a u32 status:

    request  : <u32 command> [payload]
    reply    : <u32 response_code> <u32 status> [data]

`response_code` is `command + 1` when the command was recognised, and
`UNKNOWN_RESPONSE` when it was not. `status` is zero on success.

Recovered from FWUpdLcl64.exe, which stages the bare command word and then
validates the echo, and confirmed against CSME 15.0 hardware.
"""
import struct

from . import clients
from .mei import MeiChannel

# Reply code the ME returns for a command it does not recognise, paired with
# STATUS_UNKNOWN. Both observed live and corroborated by the binary's own
# status table, which maps 0x8D to "UNKNOWN".
UNKNOWN_RESPONSE = 0xFF
STATUS_UNKNOWN = 0x8D
STATUS_SUCCESS = 0x00

_HEADER_LEN = 8

# Commands FWUpdLcl64.exe issues to this client. Numbering is the ME's, not
# ours; no attempt is made here to guess at commands the tool does not use.
CMD_QUERY_12 = 0x12
CMD_QUERY_18 = 0x18
CMD_QUERY_1A = 0x1A

# Legacy version query. CSME 15 answers it with UNKNOWN; older generations
# returned a 48, 52 or 56-byte record whose version quad began at offset 28.
CMD_LEGACY_VERSION = 0x00
LEGACY_RESPONSE_SIZES = (48, 52, 56)
_LEGACY_VERSION_OFFSET = 28


class CommandRejected(ValueError):
    """The ME did not recognise the command."""


class FwuError(RuntimeError):
    """The ME recognised the command but reported a non-zero status."""


def transact(command, payload=b"", device=None):
    """Send one FWU command. Returns (response_code, status, data).

    Raises CommandRejected if the ME reports the command as unknown, and
    FwuError on any other non-zero status.
    """
    kwargs = {"device": device} if device else {}
    request = struct.pack("<I", command) + bytes(payload)
    with MeiChannel(clients.FWU, **kwargs) as channel:
        channel.send(request)
        reply = channel.recv()

    if len(reply) < _HEADER_LEN:
        raise ValueError(f"short reply, {len(reply)} B: {reply.hex()}")
    response_code, status = struct.unpack("<2I", reply[:_HEADER_LEN])

    if response_code == UNKNOWN_RESPONSE:
        raise CommandRejected(
            f"command 0x{command:02X} not recognised "
            f"(response 0x{response_code:02X}, status 0x{status:02X})"
        )
    if status != STATUS_SUCCESS:
        raise FwuError(
            f"command 0x{command:02X} returned status 0x{status:02X} "
            f"(response 0x{response_code:02X})"
        )
    if response_code != command + 1:
        raise ValueError(
            f"reply code 0x{response_code:02X} is not command+1 "
            f"for 0x{command:02X}"
        )
    return response_code, status, reply[_HEADER_LEN:]


def query(command, device=None):
    """Issue one of the tool's known payload-free queries."""
    if command not in (CMD_QUERY_12, CMD_QUERY_18, CMD_QUERY_1A):
        raise ValueError(
            f"0x{command:02X} is not a command FWUpdLcl64 issues; refusing to "
            "send speculative command codes to the update endpoint"
        )
    return transact(command, device=device)


# Command 0x18 alternates: a success is followed by STATUS_BUSY on the next
# call, then succeeds again. Retrying once absorbs that.
STATUS_BUSY = 0x2BE

# Command 0x1A returns a header then fixed-size IUP entries.
_IUP_COUNT_OFFSET = 12
_IUP_SIZE_OFFSET = 8
_IUP_FIRST = 16
_IUP_NAME_LEN = 4
_IUP_VERSION_OFFSET = 8


def get_updatable_size(device=None):
    """Bytes of firmware the ME will accept in an update.

    On this platform it equals the sum of the image's updatable code
    partitions - IVBP, RBEP, FTPR, NFTP, PMCP, PPHY, PCHC - with the data
    partitions excluded.
    """
    for attempt in (1, 2):
        try:
            _, _, data = transact(CMD_QUERY_18, device=device)
        except FwuError as exc:
            if f"0x{STATUS_BUSY:X}" in str(exc) and attempt == 1:
                continue
            raise
        if len(data) < 4:
            raise ValueError(f"short size reply: {data.hex()}")
        return struct.unpack("<I", data[:4])[0]
    raise FwuError("updatable size unavailable after retry")


def get_iup_inventory(device=None):
    """Installed Independent Update Partitions and their versions.

    Returns [(name, "major.minor.hotfix.build"), ...].
    """
    _, _, data = transact(CMD_QUERY_1A, device=device)
    if len(data) < _IUP_FIRST:
        raise ValueError(f"short IUP reply: {len(data)} B")
    entry_size = struct.unpack_from("<I", data, _IUP_SIZE_OFFSET)[0]
    count = struct.unpack_from("<I", data, _IUP_COUNT_OFFSET)[0]
    if not entry_size or count > 64:
        raise ValueError(f"implausible IUP header: size={entry_size} count={count}")

    entries = []
    for i in range(count):
        base = _IUP_FIRST + i * entry_size
        if base + _IUP_VERSION_OFFSET + 8 > len(data):
            break
        name = data[base:base + _IUP_NAME_LEN].decode("ascii", "replace").strip("\0")
        quad = struct.unpack_from("<4H", data, base + _IUP_VERSION_OFFSET)
        entries.append((name, ".".join(str(v) for v in quad)))
    return entries


def parse_legacy_version(record):
    """Read 'major.minor.hotfix.build' from a pre-CSME-15 version record."""
    if len(record) not in LEGACY_RESPONSE_SIZES:
        raise ValueError(
            f"unexpected record: {len(record)} B, expected one of "
            f"{LEGACY_RESPONSE_SIZES}"
        )
    minor, major, build, hotfix = struct.unpack(
        "<4H", record[_LEGACY_VERSION_OFFSET:_LEGACY_VERSION_OFFSET + 8]
    )
    return f"{major}.{minor}.{hotfix}.{build}"


def get_legacy_version(device=None):
    """Try the legacy version query. Raises CommandRejected on CSME 15+."""
    kwargs = {"device": device} if device else {}
    with MeiChannel(clients.FWU, **kwargs) as channel:
        channel.send(struct.pack("<I", CMD_LEGACY_VERSION))
        reply = channel.recv()
    if len(reply) in LEGACY_RESPONSE_SIZES:
        return parse_legacy_version(reply)
    code, status = struct.unpack("<2I", reply[:_HEADER_LEN])
    raise CommandRejected(
        f"legacy version query not served (response 0x{code:02X}, "
        f"status 0x{status:02X}); use MKHI GET_FW_VERSION instead"
    )
