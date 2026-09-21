"""A persistent FWU connection.

`fwu.transact()` opens and closes a channel per command. That is correct for
one-shot queries and wrong for an update: the ME tracks update state per
connection and enforces ordering between START, DATA and END, so the whole
sequence must travel on one open file descriptor.

Replies are returned, not raised on. A non-zero status is information the
caller needs, especially while identifying the command space.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from . import clients
from .mei import MeiChannel

UNKNOWN_RESPONSE = 0xFF
STATUS_UNKNOWN = 0x8D
STATUS_SUCCESS = 0x00

HEADER_LEN = 8

# Intel's own tool waits 30 s on the slow control commands.
DEFAULT_TIMEOUT = 30.0


@dataclass
class Reply:
    """One FWU reply: <u32 response_code> <u32 status> [data]."""

    command: int
    code: int
    status: int
    data: bytes
    raw: bytes

    @property
    def unknown(self) -> bool:
        """The ME did not recognise the command at all."""
        return self.code == UNKNOWN_RESPONSE and self.status == STATUS_UNKNOWN

    @property
    def echoed(self) -> bool:
        """The ME dispatched the command: response code is command + 1."""
        return self.code == self.command + 1

    @property
    def ok(self) -> bool:
        return self.echoed and self.status == STATUS_SUCCESS

    def describe(self) -> str:
        if self.unknown:
            return "UNKNOWN command (0xFF/0x8D)"
        if self.ok:
            return f"OK, {len(self.data)} B payload"
        if self.echoed:
            return f"RECOGNISED, status 0x{self.status:X}"
        return (f"unexpected reply code 0x{self.code:X} "
                f"status 0x{self.status:X}")


class FwuSession:
    """One MEI connection to the FWU client, held open across commands."""

    def __init__(self, device=None, timeout=DEFAULT_TIMEOUT):
        kwargs = {"device": device} if device else {}
        self.channel = MeiChannel(clients.FWU, **kwargs)
        self.timeout = timeout

    def open(self):
        self.channel.open()
        return self

    def close(self):
        self.channel.close()

    def __enter__(self):
        return self.open()

    def __exit__(self, *_):
        self.close()
        return False

    @property
    def max_msg(self) -> int:
        return self.channel.max_msg

    def command(self, command: int, payload: bytes = b"", timeout=None) -> Reply:
        """Send one FWU command on the open channel and read its reply."""
        request = struct.pack("<I", command) + bytes(payload)
        if len(request) > self.channel.max_msg:
            raise ValueError(
                f"request {len(request)} B exceeds channel max "
                f"{self.channel.max_msg} B")

        self.channel.send(request)
        raw = self.channel.recv(timeout if timeout is not None else self.timeout)

        if len(raw) < HEADER_LEN:
            raise ValueError(f"short reply, {len(raw)} B: {raw.hex()}")
        code, status = struct.unpack_from("<2I", raw, 0)
        return Reply(command=command, code=code, status=status,
                     data=raw[HEADER_LEN:], raw=raw)

    def send_raw(self, request: bytes, timeout=None) -> Reply:
        """Send a fully-formed packet whose first u32 is already the command."""
        command = struct.unpack_from("<I", request, 0)[0]
        if len(request) > self.channel.max_msg:
            raise ValueError(
                f"request {len(request)} B exceeds channel max "
                f"{self.channel.max_msg} B")
        self.channel.send(request)
        raw = self.channel.recv(timeout if timeout is not None else self.timeout)
        if len(raw) < HEADER_LEN:
            raise ValueError(f"short reply, {len(raw)} B: {raw.hex()}")
        code, status = struct.unpack_from("<2I", raw, 0)
        return Reply(command=command, code=code, status=status,
                     data=raw[HEADER_LEN:], raw=raw)


def one_shot(command: int, payload: bytes = b"", device=None,
             timeout=DEFAULT_TIMEOUT) -> Reply:
    """Send a single command on a connection of its own, then disconnect.

    Used for probing, so that nothing can chain between probed commands.
    """
    with FwuSession(device=device, timeout=timeout) as session:
        return session.command(command, payload)
