"""The assembled update stream.

The ME is sent the concatenated code partitions, not the image file. Intel's
v15 Linux build sums the partition sizes at 0x16f4d, allocates that at
0x16fe9, and concatenates into it at 0x17048. Sending the file instead is
what returns 0x2C9, "Wrong structure of Update Image", at FWU_END.
"""
import pytest

from fwu import preflight

from .test_preflight import FULL, build_image


def image_with(parts, versions=None, total=0x40000):
    return preflight.parse_image(build_image(parts, versions, total))


def test_stream_length_equals_code_size():
    image = image_with(FULL, {0x9000: (15, 0, 56, 2834)})
    payload, _ = image.update_stream()
    assert len(payload) == image.code_size


def test_stream_excludes_data_partitions():
    """A data partition must not lengthen the stream."""
    without = image_with(FULL, {0x9000: (15, 0, 56, 2834)})
    with_data = image_with(FULL + [("MFS", 0x20000, 0x5000)],
                           {0x9000: (15, 0, 56, 2834)})
    assert len(with_data.update_stream()[0]) == len(without.update_stream()[0])
    assert with_data.partition("MFS") is not None


def test_stream_is_a_plain_concatenation_with_no_header():
    """Each partition's bytes land end to end, in partition-table order."""
    data = bytearray(build_image(FULL, {0x9000: (15, 0, 56, 2834)}))
    for i, (_, off, length) in enumerate(FULL):
        data[off:off + length] = bytes([i + 1]) * length
    image = preflight.parse_image(bytes(data))
    payload, used = image.update_stream()

    cursor = 0
    for i, (name, _, length) in enumerate(FULL):
        assert used[i][0] == name
        assert payload[cursor:cursor + length] == bytes([i + 1]) * length
        cursor += length
    assert cursor == len(payload)


def test_stream_order_follows_the_partition_table():
    image = image_with(FULL, {0x9000: (15, 0, 56, 2834)})
    _, used = image.update_stream()
    assert [n for n, _, _ in used] == [n for n, _, _ in FULL]


def test_stream_reports_source_offsets():
    image = image_with(FULL, {0x9000: (15, 0, 56, 2834)})
    _, used = image.update_stream()
    for name, offset, length in used:
        part = image.partition(name)
        assert (part.offset, part.length) == (offset, length)


def test_partition_past_end_of_image_is_refused():
    """Intel refuses the same way, its error 0x1F9 at 0x170a0."""
    image = image_with(FULL + [("PCHC", 0x3F000, 0x9000)],
                       {0x9000: (15, 0, 56, 2834)})
    with pytest.raises(preflight.ImageError, match="past end"):
        image.update_stream()


def test_image_with_no_code_partitions_is_refused():
    image = image_with([("MFS", 0x2000, 0x1000)])
    with pytest.raises(preflight.ImageError, match="no updatable code"):
        image.update_stream()


def test_stream_matches_the_size_gate_the_me_reports():
    """The platform gate and the stream must agree, or one of them is wrong."""
    image = image_with(FULL, {0x9000: (15, 0, 56, 2834)})
    payload, _ = image.update_stream()
    assert preflight.check_against_platform(
        image, (15, 0, 42, 2384), len(payload)) == []
