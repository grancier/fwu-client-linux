"""Image parsing and pre-write gates.

Pure functions over a CSME firmware image plus values read from the ME. No
device access happens here, so every gate is unit-testable offline.

A wrong image fails closed, because the ME verifies manifests before it
commits. A malformed *sequence* has no such protection, which is why these
gates run before anything is sent.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

FPT_SIGNATURE = b"$FPT"
MN2_SIGNATURE = b"$MN2"

# Partitions the ME requires in a full-update image.
MANDATORY = ("FTPR", "NFTP", "RBEP")

# Independent Update Partitions that must be stitched in for CSME 12+.
REQUIRED_IUPS = ("PMCP", "PCHC")

# Partitions making up the updatable code the ME reports via FWU command 0x18.
CODE_PARTITIONS = ("IVBP", "RBEP", "FTPR", "NFTP", "PMCP", "PPHY", "PCHC")

_FPT_ENTRY_LEN = 0x20


class ImageError(ValueError):
    """The image is not a usable CSME update image."""


@dataclass
class Partition:
    name: str
    offset: int
    length: int
    flags: int

    @property
    def present(self) -> bool:
        """Zero-length or 0xFF-flagged entries are placeholders, not data."""
        return self.length > 0 and (self.flags >> 24) != 0xFF


@dataclass
class Manifest:
    offset: int
    version: tuple
    date: int

    @property
    def version_str(self) -> str:
        return ".".join(str(v) for v in self.version)


@dataclass
class Image:
    data: bytes
    partitions: list = field(default_factory=list)
    manifests: list = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    def partition(self, name):
        for p in self.partitions:
            if p.name == name and p.present:
                return p
        return None

    @property
    def code_size(self) -> int:
        """Sum of updatable code partitions, as FWU command 0x18 reports it."""
        return sum(p.length for p in self.partitions
                   if p.name in CODE_PARTITIONS and p.present)

    @property
    def fw_version(self) -> tuple:
        """Operational firmware version, from the manifest inside FTPR."""
        ftpr = self.partition("FTPR")
        if ftpr is None:
            raise ImageError("no FTPR partition, cannot determine version")
        for m in self.manifests:
            if ftpr.offset <= m.offset < ftpr.offset + ftpr.length:
                return m.version
        raise ImageError("no manifest inside FTPR")

    @property
    def fw_version_str(self) -> str:
        return ".".join(str(v) for v in self.fw_version)

    def update_stream(self):
        """Assemble the bytes the ME expects to receive.

        The ME is not sent the image file. Intel's own tool allocates a buffer
        the size of the summed partition lengths and concatenates the selected
        partitions into it, with no header, then declares that total as the
        FWU_START image length. In the v15 Linux build this is the loop at
        0x16f4d (sum the sizes), the malloc at 0x16fe9, and the copy loop at
        0x17048.

        Sending the raw file instead is what earns "Wrong structure of Update
        Image" (status 0x2C9) at FWU_END: every chunk is accepted, because the
        ME only parses the assembled result once it has all of it.

        Returns (payload, [(name, offset, length), ...]).
        """
        chunks = []
        used = []
        for part in self.partitions:
            if part.name not in CODE_PARTITIONS or not part.present:
                continue
            end = part.offset + part.length
            if end > self.size:
                # Intel refuses the same way, its error 0x1F9, at 0x170a0.
                raise ImageError(
                    f"partition {part.name} runs past end of image "
                    f"({end} > {self.size})")
            chunks.append(self.data[part.offset:end])
            used.append((part.name, part.offset, part.length))

        if not chunks:
            raise ImageError("no updatable code partitions found in image")

        payload = b"".join(chunks)
        if len(payload) != self.code_size:
            raise ImageError(
                f"assembled {len(payload)} B but code partitions total "
                f"{self.code_size} B")
        return payload, used


def _parse_manifest_at(data, sig_offset):
    """Decode the manifest header whose $MN2 signature sits at sig_offset."""
    start = sig_offset - 0x1C
    if start < 0 or start + 0x34 > len(data):
        return None
    date = struct.unpack_from("<I", data, start + 0x14)[0]
    major, minor, hotfix, build = struct.unpack_from("<4H", data, start + 0x24)
    return Manifest(offset=start, version=(major, minor, hotfix, build), date=date)


def parse_image(data: bytes) -> Image:
    """Parse the $FPT partition table and every $MN2 manifest."""
    if not data:
        raise ImageError("image is empty")

    fpt = data.find(FPT_SIGNATURE)
    if fpt < 0:
        raise ImageError("no $FPT partition table found")

    count = struct.unpack_from("<I", data, fpt + 4)[0]
    header_len = data[fpt + 10]
    if not 0 < count <= 128:
        raise ImageError(f"implausible $FPT entry count {count}")
    if header_len < 0x20:
        raise ImageError(f"implausible $FPT header length {header_len}")

    partitions = []
    for i in range(count):
        off = fpt + header_len + i * _FPT_ENTRY_LEN
        if off + _FPT_ENTRY_LEN > len(data):
            break
        name = data[off:off + 4].rstrip(b"\x00\xff").decode("ascii", "replace")
        p_off, p_len = struct.unpack_from("<II", data, off + 8)
        flags = struct.unpack_from("<I", data, off + 28)[0]
        partitions.append(Partition(name, p_off, p_len, flags))

    manifests = []
    pos = 0
    while True:
        pos = data.find(MN2_SIGNATURE, pos)
        if pos < 0:
            break
        m = _parse_manifest_at(data, pos)
        if m is not None:
            manifests.append(m)
        pos += 4

    return Image(data=data, partitions=partitions, manifests=manifests)


def check_structure(image: Image) -> list:
    """Structural gates. Returns failure strings; empty list means pass."""
    problems = []

    for name in MANDATORY:
        if image.partition(name) is None:
            problems.append(f"mandatory partition {name} missing")

    for name in REQUIRED_IUPS:
        if image.partition(name) is None:
            problems.append(f"required IUP {name} not stitched into the image")

    for p in image.partitions:
        if p.present and p.offset + p.length > image.size:
            problems.append(
                f"partition {p.name} runs past end of image "
                f"({p.offset + p.length} > {image.size})")

    if not image.manifests:
        problems.append("no $MN2 manifests found")

    return problems


def check_against_platform(image: Image, running_version, updatable_size) -> list:
    """Gates comparing the image against what the ME reports.

    running_version is the operational version as a 4-tuple. updatable_size is
    the value FWU command 0x18 returned, or None to skip that gate.
    """
    problems = []
    img = image.fw_version
    running = tuple(running_version)

    if img[0] != running[0]:
        problems.append(
            f"major version differs: image {img[0]}, running {running[0]}; "
            "the ME rejects cross-major updates")

    if img <= running:
        problems.append(
            f"image {image.fw_version_str} is not newer than running "
            f"{'.'.join(str(v) for v in running)}; same-or-older needs the "
            "allow-same-version path, which is not implemented")

    if updatable_size is not None and image.code_size != updatable_size:
        problems.append(
            f"code partitions total {image.code_size} B but the ME reports "
            f"{updatable_size} B updatable; image does not match this platform")

    return problems
