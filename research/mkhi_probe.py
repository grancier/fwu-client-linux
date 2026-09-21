#!/usr/bin/env python3
"""Send one MKHI request and dump the raw reply.

Deliberately single-shot. It takes exactly the group and command you name and
sends them once - it does not sweep, retry or enumerate. Sweeping command
space against an ME is how a malformed firmware-update message gets sent by
accident, so use this only with a command whose semantics are already known
from the disassembly.

    ./mkhi_probe.py --group 0x0a --command 8
    ./mkhi_probe.py --group 0xff --command 2          # known GET_FW_VERSION
    ./mkhi_probe.py --group 0x03 --command 2 --payload 07000000
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from fwu import clients
from fwu.mei import MeiChannel, MeiError

RESPONSE_BIT = 0x80


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--group", required=True, help="e.g. 0x0a")
    parser.add_argument("--command", required=True, help="e.g. 8")
    parser.add_argument("--payload", default="", help="extra request bytes, hex")
    parser.add_argument("--client", default="mkhi", choices=sorted(clients.BY_NAME))
    args = parser.parse_args()

    group = int(args.group, 0)
    command = int(args.command, 0)
    header = struct.pack("<I", (group & 0xFF) | ((command & 0x7F) << 8))
    request = header + bytes.fromhex(args.payload)

    print(f"client  : {args.client}")
    print(f"request : {request.hex(' ')}  (group 0x{group:02X}, command {command})")

    try:
        with MeiChannel(clients.BY_NAME[args.client]) as channel:
            print(f"channel : max_msg={channel.max_msg} proto_ver={channel.proto_ver}")
            channel.send(request)
            reply = channel.recv()
    except MeiError as exc:
        print(f"failed  : {exc}")
        return 1

    print(f"reply   : {len(reply)} B  {reply.hex(' ')}")
    if len(reply) >= 4:
        word = struct.unpack("<I", reply[:4])[0]
        print(f"  header word : 0x{word:08X}")
        print(f"  group       : 0x{reply[0]:02X}")
        print(f"  command     : {reply[1] & 0x7F}   is_response: {bool(reply[1] & RESPONSE_BIT)}")
        print(f"  result      : 0x{reply[3]:02X}")
        if len(reply) > 4:
            print(f"  payload     : {reply[4:].hex(' ')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
