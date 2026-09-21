"""Gates over a synthetic CSME image. No hardware required."""
import struct

import pytest

from fwu import preflight


def build_image(partitions, versions=None, total=0x40000):
    """Construct a minimal but structurally valid $FPT image."""
    data = bytearray(b"\xff" * total)
    fpt = 0x10
    data[fpt:fpt + 4] = b"$FPT"
    struct.pack_into("<I", data, fpt + 4, len(partitions))
    data[fpt + 10] = 0x20

    for i, (name, off, length) in enumerate(partitions):
        base = fpt + 0x20 + i * 0x20
        data[base:base + 4] = name.encode()
        struct.pack_into("<II", data, base + 8, off, length)
        struct.pack_into("<I", data, base + 28, 0)

    for off, version in (versions or {}).items():
        start = off
        data[start + 0x1C:start + 0x20] = b"$MN2"
        struct.pack_into("<I", data, start + 0x14, 0x20260219)
        struct.pack_into("<4H", data, start + 0x24, *version)
    return bytes(data)


FULL = [("IVBP", 0x2000, 0x4000), ("RBEP", 0x8000, 0x1000),
        ("FTPR", 0x9000, 0x2000), ("NFTP", 0xB000, 0x1000),
        ("PMCP", 0xC000, 0x1000), ("PPHY", 0xD000, 0x1000),
        ("PCHC", 0xE000, 0x1000)]


def test_parses_partitions_and_version():
    image = preflight.parse_image(
        build_image(FULL, {0x9000: (15, 0, 56, 2834)}))
    assert image.partition("FTPR").length == 0x2000
    assert image.fw_version == (15, 0, 56, 2834)
    assert image.fw_version_str == "15.0.56.2834"


def test_code_size_sums_only_code_partitions():
    image = preflight.parse_image(
        build_image(FULL + [("MFS", 0x20000, 0x5000)],
                    {0x9000: (15, 0, 56, 2834)}))
    assert image.code_size == sum(length for _, _, length in FULL)
    assert image.partition("MFS").length == 0x5000


def test_structure_passes_on_complete_image():
    image = preflight.parse_image(
        build_image(FULL, {0x9000: (15, 0, 56, 2834)}))
    assert preflight.check_structure(image) == []


def test_missing_mandatory_partition_is_caught():
    image = preflight.parse_image(
        build_image([p for p in FULL if p[0] != "NFTP"],
                    {0x9000: (15, 0, 56, 2834)}))
    assert any("NFTP" in p for p in preflight.check_structure(image))


def test_missing_iup_is_caught():
    """CSME 12+ requires the image be stitched with its IUPs."""
    image = preflight.parse_image(
        build_image([p for p in FULL if p[0] != "PMCP"],
                    {0x9000: (15, 0, 56, 2834)}))
    assert any("PMCP" in p for p in preflight.check_structure(image))


def test_partition_running_past_end_is_caught():
    image = preflight.parse_image(
        build_image(FULL + [("HUGE", 0x3F000, 0x9000)],
                    {0x9000: (15, 0, 56, 2834)}))
    assert any("past end" in p for p in preflight.check_structure(image))


def test_rejects_data_without_fpt():
    with pytest.raises(preflight.ImageError):
        preflight.parse_image(b"\x00" * 1024)


def test_rejects_empty_image():
    with pytest.raises(preflight.ImageError):
        preflight.parse_image(b"")


# --- platform gates ---------------------------------------------------------

def _image_1500(version=(15, 0, 56, 2834)):
    return preflight.parse_image(build_image(FULL, {0x9000: version}))


def test_platform_gate_passes_for_a_genuine_upgrade():
    image = _image_1500()
    assert preflight.check_against_platform(
        image, (15, 0, 42, 2384), image.code_size) == []


def test_downgrade_is_refused():
    image = _image_1500((15, 0, 20, 1466))
    problems = preflight.check_against_platform(
        image, (15, 0, 42, 2384), image.code_size)
    assert any("not newer" in p for p in problems)


def test_same_version_is_refused():
    image = _image_1500((15, 0, 42, 2384))
    problems = preflight.check_against_platform(
        image, (15, 0, 42, 2384), image.code_size)
    assert any("not newer" in p for p in problems)


def test_cross_major_is_refused():
    image = _image_1500((16, 1, 0, 100))
    problems = preflight.check_against_platform(
        image, (15, 0, 42, 2384), image.code_size)
    assert any("major version differs" in p for p in problems)


def test_code_size_mismatch_is_refused():
    """The ME's own updatable size must equal the image's code partitions."""
    image = _image_1500()
    problems = preflight.check_against_platform(
        image, (15, 0, 42, 2384), image.code_size + 4096)
    assert any("does not match this platform" in p for p in problems)


def test_updatable_size_gate_can_be_skipped():
    image = _image_1500()
    assert preflight.check_against_platform(
        image, (15, 0, 42, 2384), None) == []
