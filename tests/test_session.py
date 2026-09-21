"""Reply classification, checked against bytes observed on live hardware.

Every hex string here was returned by CSME 15.0.42.2384 on an ASUS PRIME
H510M-A during the command-space probe.
"""
import struct

from fwu.session import Reply


def reply_from(command, hexstr):
    raw = bytes.fromhex(hexstr)
    code, status = struct.unpack_from("<2I", raw, 0)
    return Reply(command=command, code=code, status=status,
                 data=raw[8:], raw=raw)


# --- observed live ----------------------------------------------------------

def test_command_0_is_classified_unknown():
    """Legacy version query: the ME's refusal envelope."""
    r = reply_from(0x00, "ff0000008d000000")
    assert r.unknown and not r.ok and not r.echoed


def test_command_18_is_recognised_but_busy():
    """0x18 alternates success and busy; busy is still a dispatched reply."""
    r = reply_from(0x18, "19000000be02000000000000")
    assert r.echoed and not r.unknown
    assert r.status == 0x2BE and not r.ok


def test_start_header_only_is_recognised_and_rejected():
    """Command 2 exists on CSME 15: response 0x03, 24-byte reply."""
    r = reply_from(0x02, "03000000c002" + "0000" + "00" * 16)
    assert r.echoed and not r.unknown
    assert r.code == 0x03 and r.status == 0x2C0
    assert not r.ok
    assert len(r.raw) == 24


def test_data_header_only_is_recognised_and_rejected():
    """Command 4 exists: response 0x05, 8-byte reply."""
    r = reply_from(0x04, "05000000c0020000")
    assert r.echoed and r.code == 0x05 and r.status == 0x2C0
    assert len(r.raw) == 8


def test_end_header_only_is_recognised_and_rejected():
    """Command 6 exists: response 0x07, distinct wrong-state status."""
    r = reply_from(0x06, "07000000c402" + "0000" + "00" * 20)
    assert r.echoed and r.code == 0x07
    assert r.status == 0x2C4
    assert r.status != 0x2C0


def test_reply_sizes_match_the_csme12_layout():
    """Independent corroboration: START 24 B, DATA 8 B, as in the reference."""
    from fwu import update
    start = reply_from(0x02, "03000000c002" + "0000" + "00" * 16)
    data = reply_from(0x04, "05000000c0020000")
    assert len(start.raw) == update.START_REPLY_SIZE
    assert len(data.raw) == update.DATA_REPLY_SIZE


# --- success shape ----------------------------------------------------------

def test_success_reply_is_ok():
    r = reply_from(0x12, "13000000" + "00000000" + "00" * 16)
    assert r.ok and r.echoed and not r.unknown
    assert len(r.data) == 16


def test_wrong_echo_is_neither_ok_nor_unknown():
    """A reply that is not command+1 and not the refusal envelope."""
    r = reply_from(0x02, "4200000000000000")
    assert not r.ok and not r.unknown and not r.echoed


def test_describe_distinguishes_the_three_outcomes():
    assert "UNKNOWN" in reply_from(0x00, "ff0000008d000000").describe()
    assert "RECOGNISED" in reply_from(0x04, "05000000c0020000").describe()
    assert "OK" in reply_from(0x12, "1300000000000000").describe()
