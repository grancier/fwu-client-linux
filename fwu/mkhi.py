"""MKHI informational queries.

Header is 4 bytes: group_id, command with bit 7 set on replies, reserved,
result. Verified against /sys/class/mei/mei0/fw_ver on CSME 15.0.
"""
import struct

from . import clients
from .mei import MeiChannel

GEN_GROUP = 0xFF
CMD_GET_FW_VERSION = 0x02
RESPONSE_BIT = 0x80

# Blocks arrive in this order; each is four little-endian u16.
BLOCK_NAMES = ("operational", "recovery", "fitc")


def _header(group, command):
    return bytes([group, command, 0x00, 0x00])


def get_fw_version(device=None):
    """Return [(name, 'major.minor.hotfix.build'), ...] straight from the ME."""
    kwargs = {"device": device} if device else {}
    with MeiChannel(clients.MKHI, **kwargs) as channel:
        channel.send(_header(GEN_GROUP, CMD_GET_FW_VERSION))
        reply = channel.recv()

    if len(reply) < 4:
        raise ValueError(f"short MKHI reply: {reply.hex()}")

    group, command, result = reply[0], reply[1], reply[3]
    if group != GEN_GROUP or not command & RESPONSE_BIT:
        raise ValueError(f"unexpected MKHI header: {reply[:4].hex()}")
    if result != 0:
        raise ValueError(f"MKHI result {result}")

    body = reply[4:]
    versions = []
    for i in range(len(body) // 8):
        minor, major, build, hotfix = struct.unpack("<4H", body[i * 8:i * 8 + 8])
        name = BLOCK_NAMES[i] if i < len(BLOCK_NAMES) else f"block{i}"
        versions.append((name, f"{major}.{minor}.{hotfix}.{build}"))
    return versions
