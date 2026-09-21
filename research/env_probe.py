#!/usr/bin/env python3
"""Identify the FWU_ENV_MANUFACTURING constant without starting an update.

Every packet this sends is invalid on purpose:

  * image_length 0 cannot begin an update, so the ME must reject it.
  * env 0x5A and 0x03 are not defined UpdateEnvironment values.

The ME answers a dispatched-but-rejected START with response 0x03 and a
status describing what it disliked. Comparing statuses across the matrix
shows which field the ME validated, and therefore which env value it
considers legal, while every row remains a rejection.
"""
import struct
import sys

sys.path.insert(0, "/home/ubuntu/projects/fwu-client-linux")

from fwu.session import FwuSession

REAL_IMAGE_LENGTH = 3272704


def start_packet(image_length, env, oem=b"\x00" * 16):
    buf = bytearray(90)
    struct.pack_into("<I", buf, 0, 0x02)          # FWU_START
    struct.pack_into("<I", buf, 4, image_length & 0xFFFFFFFF)
    buf[12] = env & 0xFF                          # UpdateEnvironment
    struct.pack_into("<I", buf, 46, 0)            # flags
    buf[58:74] = oem                              # OEM id
    return bytes(buf)


MATRIX = [
    (0, 0x00, "len=0     env=0"),
    (0, 0x01, "len=0     env=1"),
    (0, 0x02, "len=0     env=2"),
    (0, 0x5A, "len=0     env=0x5A bogus"),
    (REAL_IMAGE_LENGTH, 0x5A, "len=real  env=0x5A bogus"),
    (REAL_IMAGE_LENGTH, 0x03, "len=real  env=3    bogus"),
]


def main():
    print(f"{'case':<28} {'code':<7} {'status':<9} reply")
    for length, env, label in MATRIX:
        with FwuSession() as session:
            reply = session.send_raw(start_packet(length, env))
        print(f"{label:<28} 0x{reply.code:<5X} 0x{reply.status:<7X} "
              f"{reply.raw.hex(' ')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
