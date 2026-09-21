#!/usr/bin/env python3
"""Dump the raw FWU reply to GET_VERSION, with candidate interpretations.

Read-only: sends only command 0 and reads what comes back. Used to work out
the CSME 15 record shape, which differs from the 48/52/56-byte layouts in
Intel's older tooling.
"""
import os
import select
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from fwu import clients
from fwu.mei import MeiChannel


def main():
    with MeiChannel(clients.FWU) as channel:
        print(f"max_msg={channel.max_msg}  proto_ver={channel.proto_ver}")
        channel.send(struct.pack("<I", 0))

        chunks = []
        while True:
            ready, _, _ = select.select([channel.fd], [], [], 2.0)
            if not ready:
                break
            data = os.read(channel.fd, channel.max_msg)
            if not data:
                break
            chunks.append(data)

    if not chunks:
        print("no reply")
        return 1

    for n, data in enumerate(chunks):
        print(f"\nreply[{n}]  {len(data)} bytes")
        print(f"  hex : {data.hex(' ')}")
        if len(data) % 4 == 0:
            words = struct.unpack(f"<{len(data)//4}I", data)
            print(f"  u32 : {[hex(w) for w in words]}")
        if len(data) % 2 == 0:
            shorts = struct.unpack(f"<{len(data)//2}H", data)
            print(f"  u16 : {list(shorts)}")
        print(f"  u8  : {list(data)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
