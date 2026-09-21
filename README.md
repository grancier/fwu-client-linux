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

## Installation

No dependencies beyond the standard library.

```bash
git clone <this repo>
cd fwu-client-linux
sudo ./bin/fwu-info
```

Check the driver is present first:

```bash
lsmod | grep mei_me
ls -l /dev/mei0
cat /sys/class/mei/mei0/dev_state     # expect ENABLED
```

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
| MKHI version block | four LE u16: minor, major, build, hotfix |
| Update sequence | `FWU_START` (carries `UpdateEnvironment`) → `FWU_DATA` → `FWU_END` |
| Also present | `FWU_GET_RECOVERY_IMAGE_INFO` / `_DATA`, partial update by `PARTID` |

Ordering is enforced ME-side: `FWU_DATA` before `FWU_START`, `FWU_END` without
a preceding `FWU_DATA`, and oversized `FWU_DATA` are each rejected.

**FWU does not share MKHI's framing** — `proto_ver` 1 against MKHI's 2 — so the
message layout cannot be extrapolated from the MKHI header above. Recovering it
is the open work.

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
