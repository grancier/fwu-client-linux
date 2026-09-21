"""FWU client queries.

The FWU client carries no message header, unlike MKHI: a request is a bare
little-endian u32 command code. That difference is what `proto_ver` 1 against
MKHI's 2 signals.

Command 0 returns a fixed-size version record whose length identifies the ME
generation - 48, 52 or 56 bytes. All three layouts open with seven u32, so the
version quad always begins at offset 28 and can be read without branching on
size.
"""
import struct

from . import clients
from .mei import MeiChannel

CMD_GET_VERSION = 0x00000000

# Record lengths for ME generations 6, 7 and 8+.
RESPONSE_SIZES = (48, 52, 56)

# CSME 15 answers command 0 with two u32 instead of a record.
REJECTION_SIZE = 8

_VERSION_OFFSET = 28


class CommandRejected(ValueError):
    """The ME returned a rejection rather than a version record."""


def get_version_raw(device=None):
    """Return the raw version record from the FWU client."""
    kwargs = {"device": device} if device else {}
    with MeiChannel(clients.FWU, **kwargs) as channel:
        channel.send(struct.pack("<I", CMD_GET_VERSION))
        return channel.recv()


def parse_version(record):
    """Pull 'major.minor.hotfix.build' out of a raw FWU version record."""
    if len(record) == REJECTION_SIZE:
        status, code = struct.unpack("<2I", record)
        raise CommandRejected(
            f"command 0 rejected (status 0x{status:02X}, code 0x{code:02X}); "
            "CSME 15 and later serve version data from MKHI instead"
        )
    if len(record) not in RESPONSE_SIZES:
        raise ValueError(
            f"unexpected FWU version record: {len(record)} B, "
            f"expected one of {RESPONSE_SIZES}"
        )
    minor, major, build, hotfix = struct.unpack(
        "<4H", record[_VERSION_OFFSET:_VERSION_OFFSET + 8]
    )
    return f"{major}.{minor}.{hotfix}.{build}"


def get_version(device=None):
    """Query the FWU client for the running firmware version."""
    return parse_version(get_version_raw(device))
