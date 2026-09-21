"""FWU update-packet encoder.

Pure encoder: constructs the bytes for FWU_START, FWU_DATA and FWU_END
without opening any device. Sending is deliberately not implemented in this
module - see the CSME-15 caveats below.

Layouts recovered from the native Linux FWUpdLcl (CSME 12.0 build):

    FWU_START  (90 bytes, memset zero first)
      +0    u32 command = 2
      +4    u32 total_image_length
      +12   u8  UpdateEnvironment
      +46   u32 caller-supplied flags word (0 in direct-update path)
      +58   16-byte OEM id (optional, all-zero when omitted)

    FWU_DATA   (DATA_HEADER_SIZE + chunk bytes)
      +0    u32 command = 4
      +4    u32 chunk_length
      +8    3 bytes padding
      +11   chunk payload

    FWU_END    (4 bytes)
      +0    u32 command = 6

Chunk ceiling matches Intel's own arithmetic: max_msg - 12.

## CSME-15 caveats (unverified assumptions transferred from CSME 12.0)

  1. Command codes 2 / 4 / 6 have not been proven to mean START / DATA / END
     on CSME 15.x. Live probes established that the FWU client accepts
     commands 0x12, 0x18, 0x1A on this platform and rejects 0x00 with
     UNKNOWN, so the command space demonstrably differs across generations.

  2. UpdateEnvironment = 0 is the numeric encoding used in the 12.0
     binary's direct-update caller. FWU_ENV_IFU is documented as obsolete;
     FWU_ENV_MANUFACTURING is the only valid value on modern firmware.
"""
from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass

# Command codes, from the CSME 12.0 reference. See caveats above.
CMD_FWU_START = 0x02
CMD_FWU_DATA = 0x04
CMD_FWU_END = 0x06

# UpdateEnvironment values.
FWU_ENV_MANUFACTURING = 0x00

# Fixed structural sizes taken from the disassembly.
START_MSG_SIZE = 90
START_REPLY_SIZE = 24
DATA_HEADER_SIZE = 11
DATA_REPLY_SIZE = 8
END_MSG_SIZE = 4

# Intel's tool subtracts 12 (not 11) from max_msg. We mirror that to stay
# bit-identical with the reference.
DATA_CHUNK_OVERHEAD = 12

# START field offsets.
_START_CMD_OFFSET = 0
_START_LEN_OFFSET = 4
_START_ENV_OFFSET = 12
_START_FLAGS_OFFSET = 46
_START_OEM_OFFSET = 58
_START_OEM_LEN = 16

# Reply-code convention for the FWU client: response = command + 1.
# Confirmed live for commands 0x12, 0x18, 0x1A.
UNKNOWN_RESPONSE = 0xFF
STATUS_UNKNOWN = 0x8D
STATUS_SUCCESS = 0x00


@dataclass
class UpdatePlan:
    """A fully-computed update, packet-by-packet, with no I/O."""

    image: bytes
    image_length: int
    update_env: int
    oem_id: bytes
    chunk_size: int
    chunk_count: int
    tail_bytes: int
    max_msg: int

    def start_packet(self) -> bytes:
        return pack_start(self.image_length, self.update_env, self.oem_id)

    def iter_data_packets(self) -> Iterator[bytes]:
        for off in range(0, self.image_length, self.chunk_size):
            end = min(off + self.chunk_size, self.image_length)
            yield pack_data(self.image[off:end])

    @staticmethod
    def end_packet() -> bytes:
        return pack_end()


def pack_start(image_length: int, update_env: int = FWU_ENV_MANUFACTURING,
               oem_id: bytes | None = None) -> bytes:
    """Build a FWU_START packet."""
    if image_length <= 0:
        raise ValueError("image_length must be positive")
    if not 0 <= update_env <= 0xFF:
        raise ValueError("update_env must fit in one byte")
    if oem_id is None:
        oem_id = b"\x00" * _START_OEM_LEN
    if len(oem_id) != _START_OEM_LEN:
        raise ValueError(f"oem_id must be exactly {_START_OEM_LEN} bytes")

    buf = bytearray(START_MSG_SIZE)
    struct.pack_into("<I", buf, _START_CMD_OFFSET, CMD_FWU_START)
    struct.pack_into("<I", buf, _START_LEN_OFFSET, image_length)
    buf[_START_ENV_OFFSET] = update_env & 0xFF
    struct.pack_into("<I", buf, _START_FLAGS_OFFSET, 0)
    buf[_START_OEM_OFFSET:_START_OEM_OFFSET + _START_OEM_LEN] = oem_id
    return bytes(buf)


def pack_data(chunk: bytes) -> bytes:
    """Build one FWU_DATA packet carrying this chunk."""
    if not chunk:
        raise ValueError("chunk must not be empty")
    if len(chunk) > 0xFFFFFFFF:
        raise ValueError("chunk too large for u32 length field")

    buf = bytearray(DATA_HEADER_SIZE + len(chunk))
    struct.pack_into("<I", buf, 0, CMD_FWU_DATA)
    struct.pack_into("<I", buf, 4, len(chunk))
    # Bytes 8..10 remain zero (padding observed in the reference layout).
    buf[DATA_HEADER_SIZE:] = chunk
    return bytes(buf)


def pack_end() -> bytes:
    """Build a FWU_END packet (header-only)."""
    return struct.pack("<I", CMD_FWU_END)


def chunk_size_for(max_msg: int) -> int:
    """Maximum FWU_DATA payload for a channel with this max_msg limit."""
    usable = max_msg - DATA_CHUNK_OVERHEAD
    if usable <= 0:
        raise ValueError(f"max_msg {max_msg} too small for FWU_DATA overhead")
    return usable


def plan_update(image: bytes, max_msg: int,
                update_env: int = FWU_ENV_MANUFACTURING,
                oem_id: bytes | None = None) -> UpdatePlan:
    """Compute the full update plan without opening any device."""
    if not image:
        raise ValueError("image must not be empty")

    chunk = chunk_size_for(max_msg)
    total = len(image)
    full_chunks, tail = divmod(total, chunk)
    count = full_chunks + (1 if tail else 0)

    return UpdatePlan(
        image=image,
        image_length=total,
        update_env=update_env,
        oem_id=oem_id or (b"\x00" * _START_OEM_LEN),
        chunk_size=chunk,
        chunk_count=count,
        tail_bytes=tail if tail else chunk,
        max_msg=max_msg,
    )


def dry_run_summary(image: bytes, max_msg: int,
                    update_env: int = FWU_ENV_MANUFACTURING,
                    oem_id: bytes | None = None) -> dict:
    """Return per-packet analysis with no device access."""
    plan = plan_update(image, max_msg, update_env, oem_id)
    start = plan.start_packet()
    packets = list(plan.iter_data_packets())
    end = pack_end()

    return {
        "image_length": plan.image_length,
        "max_msg": plan.max_msg,
        "chunk_size": plan.chunk_size,
        "chunk_count": plan.chunk_count,
        "tail_bytes": plan.tail_bytes,
        "start_size": len(start),
        "start_hex": start.hex(),
        "first_data_size": len(packets[0]) if packets else 0,
        "first_data_header_hex": packets[0][:DATA_HEADER_SIZE].hex() if packets else "",
        "last_data_size": len(packets[-1]) if packets else 0,
        "last_data_header_hex": packets[-1][:DATA_HEADER_SIZE].hex() if packets else "",
        "end_size": len(end),
        "end_hex": end.hex(),
        "total_bytes_over_wire": len(start) + sum(len(p) for p in packets) + len(end),
    }
