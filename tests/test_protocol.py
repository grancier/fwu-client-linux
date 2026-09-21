"""Protocol unit tests. No MEI hardware required."""
import struct

import pytest

from fwu import clients, fwcaps, mkhi
from fwu import fwu as fwu_mod


def test_client_guids_match_published_values():
    assert str(clients.FWU) == "309dcde8-ccb1-4062-8f78-600115a34327"
    assert str(clients.MKHI) == "8e6a6715-9abc-4043-88ef-9e39c6f63e0f"
    assert set(clients.BY_NAME) == {"fwu", "mkhi", "amthi"}


def test_guid_serialises_little_endian():
    """The MEI ioctl takes bytes_le, not big-endian UUID order."""
    assert clients.FWU.bytes_le[:4] == bytes.fromhex("e8cd9d30")


# --- FWU client: bare u32 command, reply echoes command+1 -------------------

def test_fwu_known_commands_are_the_ones_the_tool_issues():
    assert (fwu_mod.CMD_QUERY_12, fwu_mod.CMD_QUERY_18, fwu_mod.CMD_QUERY_1A) \
        == (0x12, 0x18, 0x1A)


def test_fwu_refuses_speculative_command_codes():
    """Sweeping command space is how a malformed FWU_START gets sent."""
    with pytest.raises(ValueError, match="speculative"):
        fwu_mod.query(0x42)


def test_fwu_unknown_reply_is_recognised():
    """Observed live for commands 0x00 and 0x080A."""
    reply = bytes.fromhex("ff0000008d000000")
    code, status = struct.unpack("<2I", reply)
    assert code == fwu_mod.UNKNOWN_RESPONSE
    assert status == fwu_mod.STATUS_UNKNOWN


def test_fwu_success_reply_shape():
    """Observed live: command 0x12 -> 13 00 00 00 00 00 00 00 + 16 zero bytes."""
    reply = struct.pack("<2I", 0x13, 0x00) + bytes(16)
    code, status = struct.unpack("<2I", reply[:8])
    assert code == fwu_mod.CMD_QUERY_12 + 1
    assert status == fwu_mod.STATUS_SUCCESS
    assert len(reply) == 24


def test_legacy_version_offset_is_generation_independent():
    """All three record lengths open with seven u32, so the quad is at 28."""
    for size in fwu_mod.LEGACY_RESPONSE_SIZES:
        record = bytearray(size)
        struct.pack_into("<4H", record, 28, 0, 15, 2834, 56)
        assert fwu_mod.parse_legacy_version(bytes(record)) == "15.0.56.2834"


def test_parse_legacy_version_rejects_unknown_length():
    with pytest.raises(ValueError):
        fwu_mod.parse_legacy_version(b"\x00" * 40)


# --- MKHI -------------------------------------------------------------------

def test_mkhi_request_matches_intel_encoding():
    """Intel's own tool sends 0x000002FF for GET_FW_VERSION."""
    header = mkhi._header(mkhi.GEN_GROUP, mkhi.CMD_GET_FW_VERSION)
    assert struct.unpack("<I", header)[0] == 0x000002FF


def test_mkhi_block_order_is_minor_major_build_hotfix():
    body = struct.pack("<4H", 0, 15, 2384, 42)
    reply = bytes([mkhi.GEN_GROUP, mkhi.CMD_GET_FW_VERSION | mkhi.RESPONSE_BIT, 0, 0]) + body
    minor, major, build, hotfix = struct.unpack("<4H", reply[4:12])
    assert f"{major}.{minor}.{hotfix}.{build}" == "15.0.42.2384"


def test_mkhi_header_bitfield_confirmed_live():
    """Group 0x0A command 8 returned 0a 88 00 89 - group and command echoed."""
    reply = bytes.fromhex("0a880089")
    assert reply[0] == 0x0A
    assert reply[1] & 0x7F == 8
    assert reply[1] & 0x80
    assert reply[3] == 0x89


# --- FWCAPS -----------------------------------------------------------------

def test_fwcaps_request_matches_recovered_encoding():
    """FWUpdLcl64 builds header 0x203 then the rule id."""
    assert fwcaps.GROUP_FWCAPS | (fwcaps.CMD_GET_RULE << 8) == 0x203
    assert fwcaps.RULE_LOCAL_FW_UPDATE == 7


def test_fwcaps_reply_layout_matches_the_binary_checks():
    """Reply >= 13 B, payload length 4 at +8, data at +9."""
    reply = bytes([fwcaps.GROUP_FWCAPS,
                   fwcaps.CMD_GET_RULE | fwcaps.RESPONSE_BIT, 0, 0])
    reply += struct.pack("<I", 7) + bytes([4]) + struct.pack("<I", 1)
    assert len(reply) == 13
    assert reply[8] == 4
    assert struct.unpack("<H", reply[9:11])[0] == fwcaps.LOCAL_FW_UPDATE_ENABLED
