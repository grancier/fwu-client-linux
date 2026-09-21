"""fwu-flash: update CSME firmware over the MEI FWU endpoint.

Without --commit this runs every gate, identifies the command space and
prints the plan, and writes nothing. --commit is the only thing that causes
a byte to be sent to the update endpoint.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from . import flash, probe, update
from .mei import DEFAULT_DEVICE

EXPECTED_SHA256 = ("e59aa061f3769fe107dd326d637ad20b02d08dfa0"
                   "ef6d69add9b933495ef4197")


def _print_preflight(report):
    image = report.image
    print("image")
    print(f"  path        : {report.image_path}")
    print(f"  size        : {image.size} bytes")
    print(f"  sha256      : {image.sha256}")
    print(f"  version     : {image.fw_version_str}")
    print(f"  code size   : {image.code_size} bytes  (this is what is sent)")
    print()
    print("platform")
    print(f"  dev_state   : {report.dev_state}")
    print(f"  running     : {'.'.join(str(v) for v in report.running_version)}")
    print(f"  updatable   : {report.updatable_size} bytes")
    print(f"  local update: {'ENABLED' if report.local_update_enabled else 'DISABLED'}")
    for name, version in report.installed_iups:
        print(f"  installed   : {name} {version}")
    print()
    if report.problems:
        print("GATES FAILED")
        for problem in report.problems:
            print(f"  - {problem}")
    else:
        print("all preflight gates PASS")
    print()


def _print_probe(device):
    print("command space")
    findings = probe.run(device)
    for finding in findings:
        mark = "implemented" if finding.implemented else finding.outcome
        print(f"  0x{finding.command:02X} {finding.label:<34} {mark}")
    if not probe.controls_valid(findings):
        print("  controls did not land as expected; classification unreliable")
        return False, findings
    triple = [f for f in findings if f.command in (0x02, 0x04, 0x06)]
    if not all(f.implemented for f in triple):
        print("  START/DATA/END are not all implemented; refusing to continue")
        return False, findings
    print("  START=0x02 DATA=0x04 END=0x06 confirmed implemented")
    return True, findings


def _progress(stage, index, total, reply):
    if stage == "start":
        print(f"  FWU_START accepted, {total} chunks to send")
    elif stage == "data":
        if index == total or index % 50 == 0:
            pct = 100.0 * index / total
            print(f"  FWU_DATA {index}/{total}  {pct:5.1f}%")
    elif stage == "end":
        print("  FWU_END accepted, ME is verifying")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="fwu-flash",
        description="Update CSME firmware over MEI. Writes nothing without --commit.")
    parser.add_argument("image", help="CSME update image (.bin)")
    parser.add_argument("--device", default=DEFAULT_DEVICE)
    parser.add_argument("--expect-sha256", default=EXPECTED_SHA256,
                        help="required image digest; pass '' to skip")
    parser.add_argument("--env", type=lambda v: int(v, 0), default=None,
                        help="UpdateEnvironment byte; default is discovered")
    parser.add_argument("--oem-id", default=None,
                        help="16-byte OEM id as 32 hex chars")
    parser.add_argument("--commit", action="store_true",
                        help="actually send the update")
    parser.add_argument("--skip-probe", action="store_true",
                        help="do not re-probe the command space")
    args = parser.parse_args(argv)

    if os.geteuid() != 0:
        print(f"{args.device} is mode 0600 root:root; run as root",
              file=sys.stderr)
        return 2

    report = flash.run_preflight(args.image, args.device,
                                 args.expect_sha256 or None)
    report.image_path = args.image
    _print_preflight(report)
    if not report.ok:
        print("refusing to continue with failed gates")
        return 1

    if not args.skip_probe:
        ok, _ = _print_probe(args.device)
        print()
        if not ok:
            return 1

    env = args.env
    if env is None:
        discovered, rows = flash.discover_env(args.device)
        print("UpdateEnvironment probe (all rows are deliberate rejections)")
        for value, status in rows:
            print(f"  env 0x{value:02X} -> status 0x{status:X} "
                  f"{flash.status_text(status)}")
        if discovered is None:
            env = update.FWU_ENV_MANUFACTURING
            print(f"  indeterminate; using {env} from the CSME 12 reference.")
            print("  A wrong value is rejected by the ME, so this fails closed.")
        else:
            env = discovered
            print(f"  identified FWU_ENV_MANUFACTURING = {env}")
        print()

    oem = bytes.fromhex(args.oem_id) if args.oem_id else None

    payload, used = report.image.update_stream()
    print("update stream (concatenated code partitions, no header)")
    for name, offset, length in used:
        print(f"  {name:<5} src {offset:#09x}  {length:>8} B")
    print(f"  total       : {len(payload)} bytes, "
          f"from a {report.image.size} byte file")
    print()

    plan = update.plan_update(payload, 4096, update_env=env, oem_id=oem)
    print("plan")
    print(f"  chunk size  : {plan.chunk_size} bytes")
    print(f"  chunks      : {plan.chunk_count}")
    print(f"  env byte    : {env}")
    print()

    if not args.commit:
        print("DRY RUN. Nothing was sent to the update endpoint.")
        print("Re-run with --commit to perform the update.")
        return 0

    print("COMMITTING. Do not power off the machine.")
    started = time.time()
    try:
        flash.run_update(payload, device=args.device, env=env, oem_id=oem,
                         progress=_progress)
    except flash.UpdateAborted as exc:
        print(f"\nABORTED: {exc}")
        return 1

    print(f"\nupdate accepted in {time.time() - started:.1f}s")
    print("post-update status polls:")
    for line in flash.poll_status(args.device):
        print(f"  {line}")
    print()
    print("Reboot to run the new firmware, then check "
          "/sys/class/mei/mei0/fw_ver")
    return 0


if __name__ == "__main__":
    sys.exit(main())
