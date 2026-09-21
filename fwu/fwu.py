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

# CSME 15 answers with two u32 instead of a record. Observed identically for
# command 0 and command 8, so it is a generic refusal, not a per-command reply.
REJECTION_SIZE = 8
REJECTION_STATUS = 0xFF

_VERSION_OFFSET = 28


# Header bitfield, recovered from FWUpdLcl64.exe: the tool stages a u32 at the
# head of every request and decomposes replies with the same shifts.
GROUP = 0x0A
RESPONSE_BIT = 1 << 15

# Read-only state query. 4-byte request, 8-byte reply, two meaningful bits.
CMD_GET_UPDATE_STATE = 8
_STATE_REPLY_SIZE = 8


class CommandRejected(ValueError):
    """The ME returned a rejection rather than a version record."""


def pack_header(command, group=GROUP):
    """Build the u32 request header for a FWU command."""
    return struct.pack("<I", (group & 0xFF) | ((command & 0x7F) << 8))


def parse_header(word):
    """Split a reply header word into its fields."""
    return {
        "group": word & 0xFF,
        "command": (word >> 8) & 0x7F,
        "is_response": bool(word & RESPONSE_BIT),
        "result": (word >> 24) & 0xFF,
    }


def get_update_state(device=None):
    """Query FWU command 8 for the update state.

    Read-only: the request is the bare header and the reply carries a
    two-bit state. Returns (header_fields, state, raw_reply).
    """
    kwargs = {"device": device} if device else {}
    with MeiChannel(clients.FWU, **kwargs) as channel:
        channel.send(pack_header(CMD_GET_UPDATE_STATE))
        reply = channel.recv()

    if len(reply) != _STATE_REPLY_SIZE:
        raise ValueError(
            f"expected {_STATE_REPLY_SIZE} B reply, got {len(reply)} B: {reply.hex()}"
        )
    word, payload = struct.unpack("<2I", reply)
    if word == REJECTION_STATUS:
        raise CommandRejected(
            f"command {CMD_GET_UPDATE_STATE} refused (status 0x{word:02X}, "
            f"code 0x{payload:02X}) - same envelope as command 0, so the client "
            "is refusing before it reaches command dispatch"
        )
    return parse_header(word), payload & 0x3, reply


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
