# fwu-client-linux

A Linux-native client for the Intel CSME firmware-update HECI endpoint, the
protocol Intel ships as `FWUpdLcl`. Intel does build that tool for Linux, as
`FWUpdate/LINUX64/FWUpdLcl` inside the CSME System Tools packages, but those
packages reach the public only through the OEM channel. This is an independent
implementation whose every wire constant is verified against it.

It talks to the ME over `/dev/mei0` using the mainline `mei` / `mei_me`
drivers. No Intel binaries, no kernel modules, no vendor tooling.

## Status

**Read and write paths both work.** The write path is implemented and its
encoding is verified against Intel's own native Linux CSME 15.0 build. A first
send reached `FWU_END` and was refused, because it transmitted the image file
rather than the assembled code partitions; that is fixed and documented below,
but a full send has not since been run to completion on hardware.

| Capability | State |
|---|---|
| MEI transport (connect, send, recv) | working |
| MKHI `GET_FW_VERSION` | working, cross-checked against sysfs |
| FWCAPS rule 7 (local update policy) | working |
| FWU client reachability + negotiated limits | working |
| FWU `0x12` status, `0x18` updatable size, `0x1A` IUP inventory | working |
| FWU `GET_VERSION` (command 0) | **rejected by CSME 15** — legacy path, see below |
| `FWU_START` / `FWU_DATA` / `FWU_END` | implemented, encoding verified against Intel |
| Update-stream assembly (code partitions) | working |
| FWU status decoding (295 codes) | working |
| Image parsing and pre-write gates | working |

Command codes 2 / 4 / 6 were confirmed implemented on a live CSME 15.0.42.2384
part, and every packet offset matches Intel's Linux `FWUpdLcl` 15.0.35.1951
instruction for instruction. See `research/PROTOCOL.md`.

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

### `fwu-probe` — identify the command space

Sends 4-byte header-only messages, each on its own connection, and classifies
each command as implemented or unknown. Two controls run first so the
classifier is proven before anything is concluded from it. A header-only
message cannot start an update: START needs a 90-byte struct, and DATA or END
out of order are refused by the ME.

```python
from fwu import probe
for f in probe.run():
    print(hex(f.command), f.outcome)
```

### `fwu-flash` — perform the update

Runs every gate, identifies the command space, pins down the
`UpdateEnvironment` byte, and prints the plan. **It writes nothing without
`--commit`.**

```
# sudo fwu-flash /path/to/image.bin
all preflight gates PASS
  START=0x02 DATA=0x04 END=0x06 confirmed implemented
  identified FWU_ENV_MANUFACTURING = 0
plan
  chunk size  : 4084 bytes
  chunks      : 802
DRY RUN. Nothing was sent to the update endpoint.
```

Gates that must all pass before a byte is sent: image structure and mandatory
partitions, the IUPs required since CSME 12, no overrun past end of image,
digest match, ME state `ENABLED`, local firmware update enabled, image newer
than running, same major version, and the image's code partitions totalling
exactly the size the ME reports through command `0x18`.

### What is actually transmitted

**Not the image file.** The ME receives the concatenated updatable code
partitions, with no header, and `FWU_START` declares that length. Intel's
own tool does the same: it sums the partition sizes, allocates a buffer of
exactly that total, and copies the partitions into it end to end.

For a 3,272,704-byte CSME 15.0 image the stream is 2,727,936 bytes, which is
byte-for-byte what the ME reports as updatable. Sending the file instead is
accepted chunk by chunk and then refused at `FWU_END` with status `0x2C9`,
Wrong structure of Update Image. Data partitions such as `MFS` are normal
in an update image; they are simply not sent.

### Status decoding

`fwu/status.py` carries 295 FWU status codes with Intel's own wording,
generated from the message table in their binary rather than transcribed.

```python
from fwu import status
status.describe(0x2C9)   # 'Wrong structure of Update Image.'
```

### As a library

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

The ME rejects images whose manifests do not validate, so a wrong or corrupt
payload fails closed. The hazard is a malformed *sequence*, not a bad image,
which is why the command space is probed rather than assumed and why the
whole sequence runs on one connection: the ME tracks update state per
connection and enforces ordering between START, DATA and END.

A wrong `UpdateEnvironment` byte also fails closed. The ME validates the field
and refuses the message, so a mis-identified constant stops the update rather
than corrupting it.

`--commit` is the only thing that sends a byte to the update endpoint. Run it
under `tmux`, because on a router or firewall the link carrying your session
is the machine being updated.

## Licence

Protocol details here are recovered by inspection of Intel's own distributed
binary for interoperability. No Intel code is included or redistributed.
