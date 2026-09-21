#!/usr/bin/env python3
"""Parse the $FPT partition table of a CSME firmware image.

Used to check an image is stitched with the Independent Update Partitions that
CSME 12 and later require - PMCP, PPHY and PCHC alongside FTPR and NFTP.

    ./parse_fpt.py 15.0.56.2834.bin
"""
import argparse
import hashlib
import struct
import sys

# Obligatory IUPs for CSME 12+. An image lacking these is not update-ready.
REQUIRED_IUPS = ("PMCP", "PPHY", "PCHC")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    args = parser.parse_args()

    with open(args.image, "rb") as handle:
        data = handle.read()

    print(f"size   : {len(data)} bytes")
    print(f"sha256 : {hashlib.sha256(data).hexdigest()}")

    start = data.find(b"$FPT")
    if start < 0:
        sys.exit("no $FPT found - not a CSME region image")
    count = struct.unpack_from("<I", data, start + 4)[0]
    header_len = data[start + 10]
    print(f"$FPT   : offset {start}, {count} partitions, header {header_len} B\n")

    names = []
    base = start + header_len
    for i in range(count):
        entry = base + i * 32
        name = data[entry:entry + 4].decode("ascii", "replace").strip("\0")
        offset, length = struct.unpack_from("<2I", data, entry + 8)
        if name.strip():
            names.append(name)
            print(f"  {name:<6} off={offset:<10} len={length}")

    missing = [p for p in REQUIRED_IUPS if p not in names]
    print()
    if missing:
        print(f"MISSING required IUPs: {missing} - not stitched for CSME 12+")
        return 1
    print(f"all required IUPs present: {', '.join(REQUIRED_IUPS)}")

    # Manifest versions, for cross-checking the image against its filename.
    versions = []
    pos = 0
    while True:
        i = data.find(b"$MN2", pos)
        if i < 0:
            break
        manifest = i - 0x1C
        if manifest >= 0:
            quad = struct.unpack_from("<4H", data, manifest + 0x24)
            versions.append(".".join(str(v) for v in quad))
        pos = i + 4
    print(f"\n$MN2 manifest versions: {sorted(set(versions))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
