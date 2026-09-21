# fwu-client-linux

A Linux-native client for the Intel CSME firmware-update HECI endpoint — the
thing Intel only ships as `FWUpdLcl`, distributed through the OEM channel and
never published for Linux from an official source.

It talks to the ME over `/dev/mei0` using the mainline `mei` / `mei_me`
drivers. No Intel binaries, no kernel modules, no vendor tooling.

## Status

**Read path works. Write path is not implemented.** Nothing here can flash
firmware today.

| Capability | State |
|---|---|
| MEI transport (connect, send, recv) | working |
| MKHI `GET_FW_VERSION` | working, cross-checked against sysfs |
| FWU client reachability + negotiated limits | working |
| FWU `GET_VERSION` (command 0) | **rejected by CSME 15** — legacy path, see below |
| `FWU_START` / `FWU_DATA` / `FWU_END` | **not implemented** |

## Why this can exist

Intel's updater holds no secret, which is what makes a clean-room Linux client
possible at all. Checked against `FWUpdLcl64.exe` (CSME 15.0 build):

- **No cryptography.** Its entire import list is `KERNEL32`, `SETUPAPI`,
  `ADVAPI32`, `VERSION`, `POWRPROF` and two api-ms shims. No `bcrypt`,
  no `crypt32`, no crypto symbols, no embedded keys or certificates.
- **Trust lives in the image.** Firmware images carry Intel-signed `$MN2`
  manifests and the ME validates them itself. The host tool is a transport.
- **The kernel side is mainline.** `mei` and `mei_me` are in-tree and GPL.

So the remaining work is protocol recovery, not credential recovery.

## Requirements

- Linux with the `mei` and `mei_me` drivers loaded
- An Intel platform exposing `/dev/mei0`
- Python 3.9+
- root (`/dev/mei0` is mode 0600 root:root)

Confirmed on Ubuntu 24.04, kernel 7.0.0-31-generic, CSME 15.0.

## Building from source

The client itself has **no dependencies beyond the standard library**; the dev
extras are only pytest and ruff.

```bash
git clone git@github.com:grancier/fwu-client-linux.git
cd fwu-client-linux

make venv && . .venv/bin/activate
make install-dev      # editable install plus test and lint extras
make test             # unit tests, no hardware needed
make lint
```

To build distributables, or install without a venv:

```bash
make build            # wheel and sdist into dist/
make install          # pip install .
```

Either installs the `fwu-info` console script. You can also run straight from
a clone with no install at all:

```bash
sudo ./bin/fwu-info
```

Check the driver is present first:

```bash
lsmod | grep mei_me
ls -l /dev/mei0
cat /sys/class/mei/mei0/dev_state     # expect ENABLED
```

## Layout

```
fwu/            the client library
  mei.py        MEI/HECI transport over /dev/mei0
  clients.py    MEI client GUIDs
  mkhi.py       MKHI informational queries
  fwu.py        FWU client queries and header codec
  cli.py        fwu-info entry point
tests/          protocol unit tests, no hardware required
research/       analysis tooling that regenerates every protocol finding
  analyze_pe.py   sections, GUIDs, imports, strings, transact sites
  parse_fpt.py    CSME image partition table and IUP check
  fwu_raw.py      raw FWU reply dump from live hardware
  PROTOCOL.md     findings, confirmed vs inferred
  INPUTS.md       hashes of the analysed binaries
```

Intel's binaries are **not** redistributed here — their licence forbids it.
`research/INPUTS.md` records the exact artefacts and hashes the findings came
from, and the tooling regenerates them from your own copies.

## Usage

### `fwu-info`

Reports CSME state and MEI client reachability. Read-only: it opens the FWU
client to read its negotiated limits and closes it without sending anything.
The only message written to the ME is the MKHI version query.

```
$ sudo ./bin/fwu-info
sysfs
  dev_state : ENABLED
  fw_ver    : 0:15.0.42.2384 0:15.0.42.2384 0:15.0.20.1466
  hbm_ver   : 2.2

MEI clients
  fwu  : max_msg=4096 B  proto_ver=1
  mkhi : max_msg=2048 B  proto_ver=2

MKHI GET_FW_VERSION
  operational : 15.0.42.2384
  recovery    : 15.0.42.2384
  fitc        : 15.0.20.1466
```

`--device` selects a different MEI node.

### As a library

```python
from fwu import clients, mkhi
from fwu.mei import MeiChannel

print(mkhi.get_fw_version())

with MeiChannel(clients.FWU) as channel:
    print(channel.max_msg, channel.proto_ver)
```

## Protocol notes

Established so far:

| | |
|---|---|
| FWU client GUID | `309dcde8-ccb1-4062-8f78-600115a34327` |
| FWU limits | `max_msg` 4096 B, `proto_ver` 1 |
| MKHI limits | `max_msg` 2048 B, `proto_ver` 2 |
| MKHI header | 4 bytes: group, command (bit 7 set on reply), reserved, result |
| MKHI `GET_FW_VERSION` request | `0x000002FF` LE |
| MKHI version block | four LE u16: minor, major, build, hotfix |
| **FWU header** | LE u32 bitfield: group 0-7, command 8-14, is_response 15, result 24-31 |
| **FWU group** | `0x0A` on every command word observed |
| Command words seen | `0x040A`, `0x060A`, `0x080A`, `0x1B0A` |
| `UpdateEnvironment` | must be `FWU_ENV_MANUFACTURING`; `FWU_ENV_IFU` is obsolete |
| Update sequence | `FWU_START` (carries `UpdateEnvironment`) → `FWU_DATA` → `FWU_END` |
| Also present | `FWU_GET_RECOVERY_IMAGE_INFO` / `_DATA`, partial update by `PARTID` |

FWU shares MKHI's header *shape* but not its group. Legacy tooling's bare u32
`0` is group 0, command 0 — wrong group — which is why CSME 15 rejects it.

Full detail, with confirmed-versus-inferred marked per item, in
[research/PROTOCOL.md](research/PROTOCOL.md).

Ordering is enforced ME-side: `FWU_DATA` before `FWU_START`, `FWU_END` without
a preceding `FWU_DATA`, and oversized `FWU_DATA` are each rejected.

### FWU command 0 is legacy

Older tooling reads the firmware version from the FWU client with command 0,
expecting a 48, 52 or 56-byte record by ME generation. **CSME 15.0 rejects it**,
answering 8 bytes — two LE u32, `0x000000FF` then `0x0000008D`:

```
ff 00 00 00 8d 00 00 00
```

Version therefore comes from MKHI, which is the path this client uses. The
rejection is still informative: the FWU client answers unknown commands with a
clean error rather than misbehaving.

It also removes a safety gate. There is no harmless FWU round-trip on this
generation against which to validate message framing, so a write path cannot be
proven correct before `FWU_START` is sent in earnest. That raises the cost of
getting the struct wrong and is the main argument against the write path as
currently scoped.

### Why the version matters

Intel's CSME Version Detection Tool treats a 15.0 firmware as patched only at
hotfix 50 or above:

```python
if vers[0] == 15 and vers[1] == 0 and vers[2] >= 50:
    return glob.DISCOVERY_NOT_VULNERABLE_PATCHED
```

So 15.0.42 reports `DISCOVERY_VULNERABLE`, while 15.0.50, 15.0.55 and 15.0.56
all clear it. The margin above the threshold carries no further benefit.

Images for CSME 12+ must be stitched with the obligatory Independent Update
Partitions. A stitched CSME 15.0 image carries `PMCP`, `PPHY` and `PCHC`
alongside `FTPR` and `NFTP` in its `$FPT`; check before assuming an image is
usable.

## Safety

Firmware updates over this interface are not reversible from software. A
failed ME region write is recovered with an external SPI programmer, not a
reboot.

The write path is deliberately absent rather than half-finished. When it
lands, it gates behind a working read-path equivalent of `FWUpdLcl -FWVER`:
if a version query cannot round-trip through FWU's own framing, the layout is
wrong and nothing should be written.

The ME rejects images whose manifests do not validate, so a wrong or corrupt
payload fails closed. The hazard is a malformed *sequence*, not a bad image.

## Licence

Protocol details here are recovered by inspection of Intel's own distributed
binary for interoperability. No Intel code is included or redistributed.
