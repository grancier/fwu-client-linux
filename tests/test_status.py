"""The FWU status table decoded from Intel's message block."""
from fwu import status


def test_success_is_named():
    assert status.describe(0x000) == "success"


def test_the_end_failure_that_prompted_this_table():
    """0x2C9 is what a raw image file earns at FWU_END."""
    assert status.describe(0x2C9) == "Wrong structure of Update Image."


def test_probe_statuses_decode_to_what_the_probes_should_provoke():
    """Self-validation: header-only probes hit exactly these two errors."""
    assert "length is not as expected" in status.describe(0x2C0)
    assert "no FWU_DATA command before it" in status.describe(0x2C4)


def test_environment_error_has_its_own_code():
    text = status.describe(0x2C1)
    assert "UpdateEnvironment" in text
    assert "FWU_ENV_MANUFACTURING" in text


def test_short_payload_error_is_present():
    assert "shorter than the update image length" in status.describe(0x2F2)


def test_unknown_command_decodes_to_intels_own_wording():
    """The 0xFF / 0x8D refusal envelope the probe relies on."""
    assert status.describe(0x08D) == (
        "FW Update process received Heci command message with unknown "
        "command type.")


def test_undocumented_codes_fall_back_to_the_raw_value():
    assert status.describe(0x999) == "undocumented status 0x999"


def test_table_is_substantial_and_well_formed():
    assert len(status.STATUS_TEXT) > 200
    for code, text in status.STATUS_TEXT.items():
        assert isinstance(code, int) and 0 < code < 0x1000
        assert text and text == text.strip()
        assert "\n" not in text
