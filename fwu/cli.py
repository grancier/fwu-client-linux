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
    print("\nFWU client - legacy version query (command 0)")
    try:
        print(f"  version     : {fwu.get_legacy_version(device)}")
    except fwu.CommandRejected as exc:
        print(f"  not served on this generation - {exc}")
    except (MeiError, ValueError) as exc:
        print(f"  failed - {exc}")

    print("\nFWU client - queries issued by FWUpdLcl64")
    for command in (fwu.CMD_QUERY_12, fwu.CMD_QUERY_18, fwu.CMD_QUERY_1A):
        try:
            code, status, data = fwu.query(command, device)
            print(f"  0x{command:02X} -> response 0x{code:02X}  status 0x{status:02X}  "
                  f"data {len(data)} B  {data[:12].hex(' ')}")
        except fwu.CommandRejected as exc:
            print(f"  0x{command:02X} -> rejected: {exc}")
        except (fwu.FwuError, MeiError, ValueError) as exc:
            print(f"  0x{command:02X} -> {exc}")


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
