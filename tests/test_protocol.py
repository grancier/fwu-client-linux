"""Protocol unit tests. No MEI hardware required."""
import struct

import pytest

from fwu import clients, mkhi
from fwu import fwu as fwu_mod


def test_client_guids_match_published_values():
    assert str(clients.FWU) == "309dcde8-ccb1-4062-8f78-600115a34327"
    assert str(clients.MKHI) == "8e6a6715-9abc-4043-88ef-9e39c6f63e0f"
    assert set(clients.BY_NAME) == {"fwu", "mkhi", "amthi"}


def test_guid_serialises_little_endian():
    """The MEI ioctl takes bytes_le, not big-endian UUID order."""
    assert clients.FWU.bytes_le[:4] == bytes.fromhex("e8cd9d30")


def test_pack_header_places_group_and_command():
    assert fwu_mod.pack_header(8) == struct.pack("<I", 0x080A)
    assert fwu_mod.pack_header(4) == struct.pack("<I", 0x040A)
    assert fwu_mod.pack_header(27) == struct.pack("<I", 0x1B0A)


def test_parse_header_round_trips():
    word = struct.unpack("<I", fwu_mod.pack_header(8))[0]
    fields = fwu_mod.parse_header(word)
    assert fields["group"] == fwu_mod.GROUP
    assert fields["command"] == 8
    assert fields["is_response"] is False
    assert fields["result"] == 0


def test_parse_header_reads_response_bit_and_result():
    fields = fwu_mod.parse_header(0x2A00880A)
    assert fields["command"] == 8
    assert fields["is_response"] is True
    assert fields["result"] == 0x2A


def test_version_record_offset_is_generation_independent():
    """All three record lengths open with seven u32, so the quad is at 28."""
    for size in fwu_mod.RESPONSE_SIZES:
        record = bytearray(size)
        struct.pack_into("<4H", record, 28, 0, 15, 2834, 56)
        assert fwu_mod.parse_version(bytes(record)) == "15.0.56.2834"


def test_parse_version_rejects_unknown_length():
    with pytest.raises(ValueError):
        fwu_mod.parse_version(b"\x00" * 40)


def test_csme15_refusal_envelope_is_recognised():
    """Observed live: command 0 and command 8 both return this."""
    refusal = bytes.fromhex("ff0000008d000000")
    assert len(refusal) == fwu_mod.REJECTION_SIZE
    with pytest.raises(fwu_mod.CommandRejected):
        fwu_mod.parse_version(refusal)


def test_mkhi_request_matches_intel_encoding():
    """Intel's own tool sends 0x000002FF for GET_FW_VERSION."""
    header = mkhi._header(mkhi.GEN_GROUP, mkhi.CMD_GET_FW_VERSION)
    assert struct.unpack("<I", header)[0] == 0x000002FF


def test_mkhi_block_order_is_minor_major_build_hotfix():
    body = struct.pack("<4H", 0, 15, 2384, 42)
    reply = bytes([mkhi.GEN_GROUP, mkhi.CMD_GET_FW_VERSION | mkhi.RESPONSE_BIT, 0, 0]) + body
    minor, major, build, hotfix = struct.unpack("<4H", reply[4:12])
    assert f"{major}.{minor}.{hotfix}.{build}" == "15.0.42.2384"
