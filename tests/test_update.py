"""Encoder tests for the FWU_START / FWU_DATA / FWU_END packets.

Every assertion here validates a specific claim about the reference
disassembly (CSME 12.0 Linux FWUpdLcl). None of these tests touches
hardware.
"""
import struct

import pytest

from fwu import update

# --- FWU_START --------------------------------------------------------------

def test_start_packet_is_exactly_90_bytes():
    """Disassembly: `mov edx,0x5a` before the memset call."""
    packet = update.pack_start(image_length=1)
    assert len(packet) == 90
    assert update.START_MSG_SIZE == 90


def test_start_command_at_offset_zero_is_2():
    """Disassembly: `mov DWORD PTR [rsp+0x70],0x2`."""
    packet = update.pack_start(image_length=1)
    assert struct.unpack("<I", packet[0:4])[0] == 2


def test_start_carries_image_length_at_offset_4():
    """Disassembly: `mov DWORD PTR [rsp+0x74],r12d` (r12 = image length)."""
    packet = update.pack_start(image_length=3_272_704)
    assert struct.unpack("<I", packet[4:8])[0] == 3_272_704


def test_start_carries_update_environment_at_offset_12():
    """Disassembly: `mov BYTE PTR [rsp+0x7c],r14b` (r14 = UpdateEnvironment)."""
    packet = update.pack_start(image_length=1, update_env=0)
    assert packet[12] == 0
    packet_ifu = update.pack_start(image_length=1, update_env=1)
    assert packet_ifu[12] == 1


def test_start_flags_word_at_offset_46_defaults_to_zero():
    """Disassembly: `mov DWORD PTR [rsp+0xa2],0x0`."""
    packet = update.pack_start(image_length=1)
    assert struct.unpack("<I", packet[46:50])[0] == 0


def test_start_carries_16_byte_oem_id_at_offset_58():
    """Disassembly: `lea rdi,[rbx+0x3a]; mov ecx,0x10` (16-byte copy)."""
    oem = bytes(range(16))
    packet = update.pack_start(image_length=1, oem_id=oem)
    assert packet[58:74] == oem


def test_start_oem_defaults_to_all_zero():
    packet = update.pack_start(image_length=1)
    assert packet[58:74] == b"\x00" * 16


def test_start_background_is_zero_between_declared_fields():
    """memset(buf, 0, 90) means every byte we haven't written is zero."""
    packet = update.pack_start(image_length=0xDEADBEEF, update_env=0)
    written = set(range(8)) | {12} | set(range(46, 50)) | set(range(58, 74))
    for i in range(90):
        if i in written:
            continue
        assert packet[i] == 0, f"byte {i} not zero"


def test_start_rejects_wrong_oem_length():
    with pytest.raises(ValueError, match="16"):
        update.pack_start(image_length=1, oem_id=b"\x00" * 15)


def test_start_rejects_non_positive_image_length():
    with pytest.raises(ValueError):
        update.pack_start(image_length=0)
    with pytest.raises(ValueError):
        update.pack_start(image_length=-1)


def test_start_rejects_oversize_update_env():
    with pytest.raises(ValueError):
        update.pack_start(image_length=1, update_env=256)


# --- FWU_DATA ---------------------------------------------------------------

def test_data_header_is_11_bytes():
    """Disassembly: `lea rax,[rbx+0xb]` — payload starts at +11."""
    packet = update.pack_data(b"x")
    assert len(packet) == 11 + 1
    assert update.DATA_HEADER_SIZE == 11


def test_data_command_at_offset_zero_is_4():
    """Disassembly: `mov DWORD PTR [rbx],0x4`."""
    packet = update.pack_data(b"x")
    assert struct.unpack("<I", packet[0:4])[0] == 4


def test_data_chunk_length_at_offset_4():
    """Disassembly: `mov DWORD PTR [rbx+0x4],r10d`."""
    packet = update.pack_data(b"abcdef")
    assert struct.unpack("<I", packet[4:8])[0] == 6


def test_data_padding_bytes_8_9_10_are_zero():
    packet = update.pack_data(b"payload")
    assert packet[8:11] == b"\x00\x00\x00"


def test_data_payload_starts_at_offset_11():
    payload = b"\x11\x22\x33\x44"
    packet = update.pack_data(payload)
    assert packet[11:] == payload


def test_data_rejects_empty_chunk():
    with pytest.raises(ValueError):
        update.pack_data(b"")


def test_chunk_size_matches_intel_subtraction():
    """Intel's tool: `sub r10d,0xc` -> usable = max_msg - 12."""
    assert update.chunk_size_for(4096) == 4084
    assert update.chunk_size_for(2048) == 2036


def test_chunk_size_rejects_undersized_channel():
    with pytest.raises(ValueError):
        update.chunk_size_for(12)


# --- FWU_END ----------------------------------------------------------------

def test_end_packet_is_exactly_4_bytes():
    """Disassembly: `mov edx,0x4` before the heci_write call."""
    packet = update.pack_end()
    assert len(packet) == 4


def test_end_command_is_6():
    """Disassembly: `mov DWORD PTR [rsp+0x48],0x6`."""
    packet = update.pack_end()
    assert struct.unpack("<I", packet)[0] == 6


# --- UpdatePlan / dry-run ---------------------------------------------------

def test_plan_computes_correct_chunk_count():
    image = b"\x00" * 10_000
    plan = update.plan_update(image, max_msg=4096)
    # chunk = 4084, so 3 chunks of 4084 covers 12252, need 3 full chunks
    # but 10000 / 4084 = 2 full + tail of 1832
    assert plan.chunk_size == 4084
    assert plan.chunk_count == 3
    assert plan.tail_bytes == 10_000 - 2 * 4084


def test_plan_handles_image_that_divides_evenly():
    image = b"\x00" * (4084 * 5)
    plan = update.plan_update(image, max_msg=4096)
    assert plan.chunk_count == 5
    assert plan.tail_bytes == 4084


def test_plan_iterates_every_byte_exactly_once():
    image = bytes(range(256)) * 20
    plan = update.plan_update(image, max_msg=4096)
    payloads = [pkt[update.DATA_HEADER_SIZE:] for pkt in plan.iter_data_packets()]
    assert b"".join(payloads) == image


def test_plan_last_packet_carries_the_tail():
    image = b"\x00" * 9000
    plan = update.plan_update(image, max_msg=4096)
    packets = list(plan.iter_data_packets())
    # 2 full chunks of 4084 + tail of 832
    assert len(packets[-1]) == update.DATA_HEADER_SIZE + 832


def test_dry_run_summary_reports_wire_size_correctly():
    image = b"\x00" * 8000
    summary = update.dry_run_summary(image, max_msg=4096)
    plan = update.plan_update(image, max_msg=4096)
    packets = list(plan.iter_data_packets())
    expected = 90 + sum(len(p) for p in packets) + 4
    assert summary["total_bytes_over_wire"] == expected


def test_dry_run_summary_shows_start_at_2_and_end_at_6():
    image = b"x"
    summary = update.dry_run_summary(image, max_msg=4096)
    start = bytes.fromhex(summary["start_hex"])
    end = bytes.fromhex(summary["end_hex"])
    assert struct.unpack("<I", start[:4])[0] == 2
    assert struct.unpack("<I", end)[0] == 6
    first = bytes.fromhex(summary["first_data_header_hex"])
    assert struct.unpack("<I", first[:4])[0] == 4


def test_reply_convention_constants():
    """Reply code = command + 1; unknown = 0xFF/0x8D."""
    assert update.UNKNOWN_RESPONSE == 0xFF
    assert update.STATUS_UNKNOWN == 0x8D
    assert update.STATUS_SUCCESS == 0
