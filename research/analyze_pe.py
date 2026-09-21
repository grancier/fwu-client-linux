#!/usr/bin/env python3
"""Regenerate the FWU protocol findings from Intel's updater binary.

Every claim in PROTOCOL.md comes from one of these subcommands. Supply your
own copy of FWUpdLcl64.exe; nothing Intel ships is redistributed here.

    ./analyze_pe.py sections  FWUpdLcl64.exe
    ./analyze_pe.py guids     FWUpdLcl64.exe
    ./analyze_pe.py imports   FWUpdLcl64.exe
    ./analyze_pe.py strings   FWUpdLcl64.exe
    ./analyze_pe.py transact  FWUpdLcl64.exe --asm fwupd.asm

Produce the disassembly with:

    objdump -d -M intel FWUpdLcl64.exe > fwupd.asm
"""
import argparse
import re
import struct
import subprocess
import sys
import uuid

# MEI clients worth looking for, as published in kernel and coreboot sources.
KNOWN_GUIDS = {
    "MKHI": "8e6a6715-9abc-4043-88ef-9e39c6f63e0f",
    "MKHI-fixed": "55213584-9a29-4916-badf-0fb7ed682aeb",
    "AMTHI": "12f80028-b4b7-4b2d-aca8-46e0ff65814c",
    "FWU": "309dcde8-ccb1-4062-8f78-600115a34327",
}

TRANSACT_DEFAULT = "0x14001ff00"
FWU_CLIENT_SELECTOR = 0x17


def load(path):
    with open(path, "rb") as handle:
        return handle.read()


def sections(data):
    """Yield (name, vma, file_offset, size) from the PE section table."""
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE image")
    count = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    table = pe + 24 + opt_size
    out = []
    for i in range(count):
        entry = table + i * 40
        name = data[entry:entry + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, vma, rawsize, raw = struct.unpack_from("<4I", data, entry + 8)
        out.append((name, vma, raw, max(vsize, rawsize)))
    return out


def image_base(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    return struct.unpack_from("<Q", data, pe + 24 + 24)[0]


def to_vma(secs, base, offset):
    for name, vma, raw, size in secs:
        if raw <= offset < raw + size:
            return name, base + vma + (offset - raw)
    return None, None


def cmd_sections(args):
    data = load(args.binary)
    base = image_base(data)
    print(f"image base 0x{base:x}")
    for name, vma, raw, size in sections(data):
        print(f"  {name:<10} vma=0x{base + vma:<12x} file=0x{raw:<8x} size=0x{size:x}")


def cmd_guids(args):
    data = load(args.binary)
    print("known MEI client GUIDs present as little-endian bytes:")
    for label, text in KNOWN_GUIDS.items():
        needle = uuid.UUID(text).bytes_le
        hits = [m.start() for m in re.finditer(re.escape(needle), data)]
        mark = "yes" if hits else "no "
        print(f"  {mark}  {label:<11} {text}  at {hits[:4]}")


def cmd_imports(args):
    """Report imported DLLs. Absence of crypto here is the key finding."""
    out = subprocess.run(
        ["objdump", "-p", args.binary], capture_output=True, text=True, check=False
    ).stdout
    dlls = sorted({m.group(1) for m in re.finditer(r"DLL Name:\s*(\S+)", out)})
    print("imported DLLs:")
    for dll in dlls:
        print(f"  {dll}")
    crypto = [d for d in dlls if re.search(r"crypt|bcrypt|ncrypt", d, re.IGNORECASE)]
    print(f"\ncrypto imports: {crypto if crypto else 'none'}")


def cmd_strings(args):
    data = load(args.binary)
    secs, base = sections(data), image_base(data)
    patterns = [rb"FWU_[A-Z_]+", rb"Sending [A-Za-z_ ]+", rb"UpdateEnvironment",
                rb"Local FWUpdate is [A-Za-z]+"]
    seen = {}
    for pattern in patterns:
        for match in re.finditer(pattern, data):
            text = match.group().decode("ascii", "replace")
            name, vma = to_vma(secs, base, match.start())
            if vma and text not in seen:
                seen[text] = (name, vma, match.start())
    for text, (name, vma, off) in sorted(seen.items(), key=lambda kv: kv[1][1]):
        print(f"  {name:<8} vma=0x{vma:x}  off={off:<9} {text[:64]}")


def cmd_transact(args):
    """Enumerate HECI transact call sites and their FWU command words."""
    with open(args.asm) as handle:
        lines = handle.read().splitlines()
    addr_re = re.compile(r"^\s*([0-9a-f]+):")
    call_re = re.compile(rf"call\s+{re.escape(args.transact)}\b")
    sel_re = re.compile(rf"mov\s+(?:ecx|ebx|r\d+d),0x{FWU_CLIENT_SELECTOR:x}\b")
    zero_re = re.compile(r"xor\s+ecx,ecx")
    imm_re = re.compile(r"mov\s+(?:DWORD PTR \[[^\]]+\]|e[a-z0-9]+),(0x[0-9a-f]+)")
    size_re = re.compile(r"mov\s+r8d,(0x[0-9a-f]+)")

    sites = [i for i, line in enumerate(lines) if call_re.search(line)]
    print(f"transact sites at {args.transact}: {len(sites)}\n")
    print("addr         sel   req   command words seen")
    fwu_count = 0
    for i in sites:
        match = addr_re.match(lines[i])
        addr = match.group(1) if match else "?"
        window = [lines[j] for j in range(max(0, i - 45), i)]
        text = "\n".join(window)
        is_fwu = bool(sel_re.search(text)) and not zero_re.search("\n".join(window[-12:]))
        if not is_fwu:
            continue
        fwu_count += 1
        cmds = sorted({int(v, 16) for v in imm_re.findall(text)
                       if int(v, 16) & 0xFF == 0x0A and 0x100 <= int(v, 16) < 0x8000})
        sizes = size_re.findall(text)
        print(f"0x{addr}  0x{FWU_CLIENT_SELECTOR:02x}  "
              f"{sizes[-1] if sizes else 'reg':<5} "
              f"{[hex(c) for c in cmds] if cmds else '(runtime-resolved)'}")
    print(f"\nFWU-client sites: {fwu_count} of {len(sites)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, func in (("sections", cmd_sections), ("guids", cmd_guids),
                       ("imports", cmd_imports), ("strings", cmd_strings)):
        p = sub.add_parser(name)
        p.add_argument("binary")
        p.set_defaults(func=func)
    p = sub.add_parser("transact")
    p.add_argument("binary")
    p.add_argument("--asm", required=True, help="objdump -d -M intel output")
    p.add_argument("--transact", default=TRANSACT_DEFAULT)
    p.set_defaults(func=cmd_transact)

    args = parser.parse_args()
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
