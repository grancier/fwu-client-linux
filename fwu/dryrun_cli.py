"""fwu-dryrun: analyse an FWU update plan without touching hardware.

Constructs FWU_START, every FWU_DATA chunk and FWU_END for the supplied
image, then reports sizes, headers, and consistency checks. No MEI device
is opened. Intended for validating the encoder against a reference
implementation before ever thinking about live hardware.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys

from . import update


def _hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  +{offset:04x}  {hex_part:<{width * 3}}  {asc_part}")
    return "\n".join(lines)


def _summarise_start(packet: bytes) -> str:
    cmd = struct.unpack_from("<I", packet, 0)[0]
    image_len = struct.unpack_from("<I", packet, 4)[0]
    env = packet[12]
    flags = struct.unpack_from("<I", packet, 46)[0]
    oem = packet[58:74]
    return (
        f"    cmd @+0   : {cmd}  (FWU_START = 2)\n"
        f"    image_len : {image_len}  (0x{image_len:X})\n"
        f"    env  @+12 : {env}  (FWU_ENV_MANUFACTURING = 0)\n"
        f"    flags@+46 : {flags}\n"
        f"    oem  @+58 : {oem.hex()}"
    )


def _summarise_data_header(header: bytes) -> str:
    cmd = struct.unpack_from("<I", header, 0)[0]
    length = struct.unpack_from("<I", header, 4)[0]
    return f"    cmd={cmd} (FWU_DATA=4)  chunk_len={length}  pad={header[8:11].hex()}"


def _summarise_end(packet: bytes) -> str:
    cmd = struct.unpack_from("<I", packet, 0)[0]
    return f"    cmd={cmd} (FWU_END=6)"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="fwu-dryrun",
        description=(
            "Encode an FWU update sequence to bytes and report the plan. "
            "Does not open /dev/mei0."))
    parser.add_argument("image", help="path to a CSME firmware image (.bin)")
    parser.add_argument("--max-msg", type=int, default=4096,
                        help="MEI channel max_msg (default 4096)")
    parser.add_argument("--env", type=int, default=update.FWU_ENV_MANUFACTURING,
                        help="UpdateEnvironment byte (default 0 = MANUFACTURING)")
    parser.add_argument("--oem-id", type=str, default=None,
                        help="16-byte OEM id as 32 hex chars (default all zero)")
    parser.add_argument("--dump-start", action="store_true",
                        help="hex-dump the full FWU_START packet")
    parser.add_argument("--dump-first", action="store_true",
                        help="hex-dump the first FWU_DATA header")
    parser.add_argument("--dump-last", action="store_true",
                        help="hex-dump the last FWU_DATA header")
    args = parser.parse_args(argv)

    with open(args.image, "rb") as handle:
        image = handle.read()

    print(f"image        : {args.image}")
    print(f"  size       : {len(image)} bytes (0x{len(image):X})")
    print(f"  sha256     : {hashlib.sha256(image).hexdigest()}")
    print()

    oem = bytes.fromhex(args.oem_id) if args.oem_id else None
    plan = update.plan_update(image, max_msg=args.max_msg,
                              update_env=args.env, oem_id=oem)

    print("channel")
    print(f"  max_msg    : {plan.max_msg} bytes")
    print(f"  chunk size : {plan.chunk_size} bytes (= max_msg - 12)")
    print()

    print("upload plan")
    print(f"  chunk count: {plan.chunk_count}")
    print(f"  tail bytes : {plan.tail_bytes}")

    packets = list(plan.iter_data_packets())
    total_data = sum(len(p) for p in packets)
    wire = update.START_MSG_SIZE + total_data + update.END_MSG_SIZE
    print(f"  wire bytes : {wire} "
          f"(START {update.START_MSG_SIZE} + DATAx{len(packets)} "
          f"{total_data} + END {update.END_MSG_SIZE})")
    print()

    start = plan.start_packet()
    print("FWU_START packet")
    print(_summarise_start(start))
    if args.dump_start:
        print(_hexdump(start))
    print()

    if packets:
        print("FWU_DATA (first)")
        print(_summarise_data_header(packets[0][:update.DATA_HEADER_SIZE]))
        if args.dump_first:
            print(_hexdump(packets[0][:update.DATA_HEADER_SIZE]))
        print()

        print("FWU_DATA (last)")
        print(_summarise_data_header(packets[-1][:update.DATA_HEADER_SIZE]))
        if args.dump_last:
            print(_hexdump(packets[-1][:update.DATA_HEADER_SIZE]))
        print(f"    tail size: {len(packets[-1]) - update.DATA_HEADER_SIZE}")
        print()

    print("FWU_END packet")
    print(_summarise_end(update.pack_end()))
    print()

    # Consistency: every byte of the image should be covered exactly once.
    reconstructed = b"".join(p[update.DATA_HEADER_SIZE:] for p in packets)
    ok = reconstructed == image
    print(f"reconstructed image matches source: {'yes' if ok else 'NO'}")
    if not ok:
        return 1

    print()
    print("This is a DRY RUN. No MEI transaction was performed.")
    print("The command codes 2/4/6 are transferred from CSME 12.0 tooling")
    print("and have not been proven on the target CSME generation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
