"""Command line entry point.

Reports CSME state and MEI client reachability. Read-only throughout: the FWU
client is opened to read its negotiated limits, and the only messages written
to the ME are the MKHI version query and the FWU state query.
"""
import argparse
import os
import sys

from . import __version__, clients, fwcaps, fwu, mkhi
from .mei import DEFAULT_DEVICE, MeiError, probe

SYSFS = "/sys/class/mei/mei0"


def _sysfs(name):
    try:
        with open(os.path.join(SYSFS, name)) as handle:
            return handle.read().strip()
    except OSError:
        return "(unavailable)"


def _report_sysfs():
    print("sysfs")
    print(f"  dev_state : {_sysfs('dev_state')}")
    print(f"  fw_ver    : {' '.join(_sysfs('fw_ver').split())}")
    print(f"  hbm_ver   : {_sysfs('hbm_ver')}")


def _report_clients(device):
    print("\nMEI clients")
    for name in ("fwu", "mkhi"):
        try:
            max_msg, proto = probe(clients.BY_NAME[name], device)
            print(f"  {name:<5}: max_msg={max_msg} B  proto_ver={proto}")
        except MeiError as exc:
            print(f"  {name:<5}: unreachable - {exc}")


def _report_mkhi(device):
    print("\nMKHI GET_FW_VERSION")
    first = None
    try:
        for label, version in mkhi.get_fw_version(device):
            print(f"  {label:<12}: {version}")
            first = first or version
    except (MeiError, ValueError) as exc:
        print(f"  failed - {exc}")
    return first


def _report_fwu(device):
    print("\nFWU GET_VERSION (legacy command 0)")
    try:
        version = fwu.parse_version(fwu.get_version_raw(device))
        print(f"  version     : {version}")
    except fwu.CommandRejected as exc:
        print(f"  not served on this generation - {exc}")
    except (MeiError, ValueError) as exc:
        print(f"  failed - {exc}")

    print("\nGroup 0x0A command 8 over MKHI (read-only)")
    try:
        header, raw = fwu.get_update_state(device)
        print(f"  raw         : {raw.hex(' ')}")
        print(f"  group       : 0x{header['group']:02X}   command: {header['command']}"
              f"   is_response: {header['is_response']}")
        print(f"  result      : 0x{header['result']:02X}")
        print("  header layout validated: yes (group and command echoed)")
    except (MeiError, ValueError) as exc:
        print(f"  failed - {exc}")


def _report_fwcaps(device):
    """Report the rule Intel's updater checks before touching the FWU client."""
    print("\nFWCAPS rule 7 - local firmware update")
    try:
        value, enabled = fwcaps.local_fw_update_state(device)
        print(f"  raw value   : {value} (0x{value:04X})")
        print(f"  local FW update: {'ENABLED' if enabled else 'DISABLED'}")
        if not enabled:
            print("  -> explains FWU refusing every command")
    except (MeiError, fwcaps.FwCapsError) as exc:
        print(f"  failed - {exc}")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="fwu-info", description=__doc__)
    parser.add_argument("--device", default=DEFAULT_DEVICE,
                        help=f"MEI character device (default {DEFAULT_DEVICE})")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    if os.geteuid() != 0:
        print(f"warning: {args.device} is normally mode 0600 root:root; "
              "run as root for the MEI queries", file=sys.stderr)

    _report_sysfs()
    _report_clients(args.device)
    _report_mkhi(args.device)
    _report_fwcaps(args.device)
    _report_fwu(args.device)
    return 0


if __name__ == "__main__":
    sys.exit(main())
