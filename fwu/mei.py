"""MEI/HECI transport over the mainline Linux mei driver.

One MEI file descriptor binds to exactly one client GUID, so a channel is
opened per client and closed when done.
"""
import fcntl
import os
import select
import struct

DEFAULT_DEVICE = "/dev/mei0"

# _IOWR('H', 0x01, struct mei_connect_client_data) -- uapi/linux/mei.h
IOCTL_MEI_CONNECT_CLIENT = 0xC0104801


class MeiError(RuntimeError):
    """A HECI transport failure."""


class MeiChannel:
    """A file descriptor bound to one MEI client.

    Used as a context manager:

        with MeiChannel(clients.MKHI) as channel:
            channel.send(payload)
            reply = channel.recv()
    """

    def __init__(self, guid, device=DEFAULT_DEVICE):
        self.guid = guid
        self.device = device
        self.fd = None
        self.max_msg = 0
        self.proto_ver = 0

    def open(self):
        """Bind the device to this client. Returns self."""
        try:
            self.fd = os.open(self.device, os.O_RDWR)
        except OSError as exc:
            raise MeiError(f"cannot open {self.device}: {exc}") from exc

        buf = bytearray(self.guid.bytes_le)
        try:
            fcntl.ioctl(self.fd, IOCTL_MEI_CONNECT_CLIENT, buf, True)
        except OSError as exc:
            os.close(self.fd)
            self.fd = None
            raise MeiError(f"cannot connect client {self.guid}: {exc}") from exc

        self.max_msg, self.proto_ver = struct.unpack("<IB", bytes(buf[:5]))
        return self

    def close(self):
        """Release the descriptor, disconnecting the client."""
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def send(self, payload):
        """Write one HECI message."""
        if self.fd is None:
            raise MeiError("channel is not open")
        if len(payload) > self.max_msg:
            raise MeiError(f"message {len(payload)} B exceeds max {self.max_msg} B")
        return os.write(self.fd, bytes(payload))

    def recv(self, timeout=5.0):
        """Read one HECI message, waiting at most timeout seconds.

        A silent ME would otherwise block the caller indefinitely.
        """
        if self.fd is None:
            raise MeiError("channel is not open")
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            raise MeiError(f"no reply from client {self.guid} within {timeout}s")
        return os.read(self.fd, self.max_msg)

    def __enter__(self):
        return self.open()

    def __exit__(self, *_):
        self.close()
        return False


def probe(guid, device=DEFAULT_DEVICE):
    """Connect then disconnect, reporting (max_msg, proto_ver)."""
    with MeiChannel(guid, device) as channel:
        return channel.max_msg, channel.proto_ver
