"""Constants checked against Intel's native CSME 15.0 Linux FWUpdLcl.

Reference binary: `FWUpdate/LINUX64/FWUpdLcl` from CSME System Tools v15.0
r15, tool version 15.0.35.1951, sha256
3f9be283b46ac1f9bdd883e05bf71e9d6ace553755fbf3c45b95d1e624f52757.

Each test names the instruction it encodes. These are regression guards: if
someone changes a constant, the test says which line of Intel's own code it
contradicts.
"""
import struct

import pytest

from fwu import update

# --- FWU_START, built at 0x16343..0x163f5 -----------------------------------

def test_start_buffer_is_90_bytes():
    """0x1634a: mov edx, 0x5a  -- memset of the request buffer."""
    assert update.START_MSG_SIZE == 0x5A  # 90
    assert len(update.pack_start(image_length=1)) == 90


def test_start_command_is_2():
    """0x16371: mov dword ptr [rsp + 0x60], 0x2  -- buffer base is rsp+0x60."""
    assert update.CMD_FWU_START == 2
    assert struct.unpack_from("<I", update.pack_start(image_length=1), 0)[0] == 2


def test_start_image_length_at_offset_4():
    """0x16368: mov dword ptr [rsp + 0x64], ebx  -- 0x64 - 0x60 = 4."""
    packet = update.pack_start(image_length=3_272_704)
    assert struct.unpack_from("<I", packet, 4)[0] == 3_272_704


def test_start_environment_is_one_byte_at_offset_12():
    """0x16379: mov byte ptr [rsp + 0x6c], r15b  -- 0x6c - 0x60 = 12."""
    assert update._START_ENV_OFFSET == 12
    assert update.pack_start(image_length=1, update_env=0)[12] == 0
    assert update.pack_start(image_length=1, update_env=1)[12] == 1


def test_start_flags_dword_at_offset_46():
    """0x1637e: mov dword ptr [rsp + 0x8e], r14d  -- 0x8e - 0x60 = 46."""
    assert update._START_FLAGS_OFFSET == 46
    packet = update.pack_start(image_length=1)
    assert struct.unpack_from("<I", packet, 46)[0] == 0


def test_start_oem_id_is_16_bytes_at_offset_58():
    """0x16388: lea rdi, [rsp + 0x9a]; mov ecx, 0x10  -- 0x9a - 0x60 = 58."""
    assert update._START_OEM_OFFSET == 58
    assert update._START_OEM_LEN == 0x10  # 16
    oem = bytes(range(16))
    assert update.pack_start(image_length=1, oem_id=oem)[58:74] == oem


def test_start_reply_is_24_bytes_with_code_3():
    """0x1634f: mov qword ptr [rsp+0x38], 0x18; 0x163f5: cmp [rsp+0x40], 0x3."""
    assert update.START_REPLY_SIZE == 0x18  # 24
    assert update.START_RESPONSE_CODE == 3


# --- FWU_DATA, built at 0x16543..0x16650 ------------------------------------

def test_data_command_is_4():
    """0x1654c: mov dword ptr [rax], 0x4."""
    assert update.CMD_FWU_DATA == 4
    assert struct.unpack_from("<I", update.pack_data(b"x"), 0)[0] == 4


def test_data_payload_starts_at_offset_11():
    """0x16552: add rax, 0xb  -- payload pointer is buffer + 11."""
    assert update.DATA_HEADER_SIZE == 0xB  # 11
    assert update.pack_data(b"abcd")[11:] == b"abcd"


def test_data_chunk_length_at_offset_4():
    """0x1659f: mov dword ptr [rax + 0x4], r13d."""
    assert struct.unpack_from("<I", update.pack_data(b"abcdef"), 4)[0] == 6


def test_data_request_size_is_chunk_plus_11():
    """0x165f5: lea rdx, [r15 + 0xb]  -- r15 is the chunk length."""
    for n in (1, 100, 4084):
        assert len(update.pack_data(b"\x00" * n)) == n + 11


def test_data_reply_is_8_bytes_with_code_5():
    """0x165a3: mov qword ptr [rsp+0x30], 0x8; 0x16650: cmp [rsp+0x38], 0x5."""
    assert update.DATA_REPLY_SIZE == 8
    assert update.DATA_RESPONSE_CODE == 5


def test_chunk_size_is_max_msg_minus_12():
    """0x16548: lea r13d, [r11 - 0xc]  -- r11 is the channel max_msg."""
    assert update.DATA_CHUNK_OVERHEAD == 0xC  # 12
    assert update.chunk_size_for(4096) == 4084


def test_channel_too_small_is_refused():
    """0x16539: cmp r11, 0xc; jbe <error 0x23>  -- Intel bails the same way."""
    with pytest.raises(ValueError):
        update.chunk_size_for(12)


# --- FWU_END, built at 0x166e2..0x16705 -------------------------------------

def test_end_command_is_6_in_a_4_byte_message():
    """0x16705: mov dword ptr [rsp+0x38], 0x6, sent with mov edx, 0x4."""
    assert update.CMD_FWU_END == 6
    assert update.END_MSG_SIZE == 4
    assert update.pack_end() == struct.pack("<I", 6)


def test_end_response_code_is_7():
    """The response = command + 1 convention, confirmed live for 0x06 -> 0x07."""
    assert update.END_RESPONSE_CODE == 7


# --- environment constant, confirmed live -----------------------------------

def test_manufacturing_environment_is_zero():
    """Live: env 0 -> status 0x206 (bad length), 1/2/0x5A -> 0x81 (bad env)."""
    assert update.FWU_ENV_MANUFACTURING == 0


# --- the real image plans as Intel's tool would ------------------------------

def test_real_image_plan_matches_intel_arithmetic():
    """3,272,704 B over a 4096 B channel: 801 full chunks plus a 1420 tail."""
    plan = update.plan_update(b"\x00" * 3_272_704, max_msg=4096)
    assert plan.chunk_size == 4084
    assert plan.chunk_count == 802
    assert plan.tail_bytes == 1420
    assert 801 * 4084 + 1420 == 3_272_704
