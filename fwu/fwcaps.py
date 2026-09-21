"""MKHI FWCAPS rule queries.

FWCAPS is MKHI group 3. Command 2 reads one capability rule by id and returns
its value, which is how Intel's updater decides whether local firmware update
is permitted before it talks to the FWU client at all.

Recovered from FWUpdLcl64.exe: the request is an 8-byte
`{u32 header, u32 rule_id}` with header 0x203, and the reply is validated as
at least 13 bytes with a 4-byte rule payload at offset 9.
"""
import struct

from . import clients
from .mei import MeiChannel

GROUP_FWCAPS = 0x03
CMD_GET_RULE = 0x02
RESPONSE_BIT = 0x80

# Rule 7 carries the local-firmware-update permission.
RULE_LOCAL_FW_UPDATE = 7

_MIN_REPLY = 13
_RULE_DATA_LEN = 4
_RULE_DATA_OFFSET = 9
_RULE_LEN_OFFSET = 8

# Values the updater distinguishes for rule 7.
LOCAL_FW_UPDATE_ENABLED = 1


class FwCapsError(RuntimeError):
    """The ME declined or malformed a FWCAPS reply."""


def get_rule(rule_id, device=None):
    """Read one FWCAPS rule. Returns its 4 raw payload bytes."""
    kwargs = {"device": device} if device else {}
    request = struct.pack("<2I", GROUP_FWCAPS | (CMD_GET_RULE << 8), rule_id)
    with MeiChannel(clients.MKHI, **kwargs) as channel:
        channel.send(request)
        reply = channel.recv()

    if len(reply) < _MIN_REPLY:
        raise FwCapsError(
            f"reply {len(reply)} B is shorter than {_MIN_REPLY}: {reply.hex()}"
        )

    group, command, _, result = reply[0], reply[1], reply[2], reply[3]
    if group != GROUP_FWCAPS or not command & RESPONSE_BIT:
        raise FwCapsError(f"unexpected FWCAPS header: {reply[:4].hex()}")
    if result != 0:
        raise FwCapsError(f"FWCAPS result 0x{result:02X} for rule {rule_id}")

    length = reply[_RULE_LEN_OFFSET]
    if length != _RULE_DATA_LEN:
        raise FwCapsError(f"rule {rule_id} payload length {length}, expected 4")
    return reply[_RULE_DATA_OFFSET:_RULE_DATA_OFFSET + _RULE_DATA_LEN]


def local_fw_update_state(device=None):
    """Return (raw_u16, enabled) for the local firmware-update rule."""
    data = get_rule(RULE_LOCAL_FW_UPDATE, device)
    value = struct.unpack("<H", data[:2])[0]
    return value, value == LOCAL_FW_UPDATE_ENABLED
