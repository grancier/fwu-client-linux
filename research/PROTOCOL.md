# FWU protocol notes

Recovered from a CSME 15.0 platform (ASUS PRIME H510M-A, i3-10100, running
15.0.42.2384) and by static analysis of `FWUpdLcl64.exe` from the
`ME_Intel_v15.0.56.2834` package.

Each item is marked **confirmed** (observed against live hardware or read
directly out of the binary) or **inferred** (deduced, not yet proven).

## Transport

| Fact | Confidence |
|---|---|
| FWU client GUID `309dcde8-ccb1-4062-8f78-600115a34327` | confirmed — connects |
| FWU `max_msg` 4096 B, `proto_ver` 1 | confirmed |
| MKHI `max_msg` 2048 B, `proto_ver` 2 | confirmed |
| `IOCTL_MEI_CONNECT_CLIENT` = `0xC0104801` | confirmed |
| Image is IUP-stitched: `PMCP`, `PPHY`, `PCHC` present in `$FPT` | confirmed |

A 3,272,704-byte image at a 4096-byte ceiling is 799 full chunks plus a
2,048-byte remainder.

## Command 0 is legacy

Older tooling reads the version from FWU with a bare `u32` 0, expecting a
48/52/56-byte record. CSME 15.0 answers 8 bytes instead:

```
ff 00 00 00 8d 00 00 00     -> u32 0x000000FF, u32 0x0000008D
```

**Confirmed** against live hardware. Version data comes from MKHI on this
generation. The rejection is clean, which says the client validates commands
rather than acting on unrecognised ones.

## Message header

`FWUpdLcl64.exe` stages a `DWORD` at the head of each request buffer. The
logging path immediately after decomposes it:

```asm
mov   eax, [rsp+0x194]        ; the command word
movzx r8d, al                 ; bits 0-7
shr   r9d, 0xf                ; bit 15
and   r9d, 1
shr   r8d, 0x8 ; and r8d, 0x7f ; bits 8-14
shr   r9d, 0x18               ; bits 24-31
```

**Inferred** layout, matching MKHI's shape:

| Bits | Field |
|---|---|
| 0-7 | group id |
| 8-14 | command |
| 15 | is_response |
| 16-23 | reserved |
| 24-31 | result |

**Confirmed**: every FWU command word observed carries group `0x0A`.

## Transact wrapper

`0x14001ff00` takes (request buffer, request size, response buffer, response
size, timeout ms). A representative call:

```asm
mov   DWORD PTR [rsp+0x40], 0x60a    ; command word
lea   rdx, [rsp+0x40]                ; request buffer
mov   r8d, 0x5                       ; request size
lea   r9,  [rsp+0x48]                ; response buffer
mov   QWORD PTR [rsp+0x28], 0x4      ; response size
mov   DWORD PTR [rsp+0x30], 0x7530   ; 30000 ms
call  0x14001ff00
```

It is a **general** HECI transact, not FWU-specific: only 7 of its 45 call
sites stage an immediate FWU command word, the rest load one from memory.

## Command words seen as immediates

| Word | Command | Sites | Note |
|---|---|---|---|
| `0x040A` | 4 | 1 | follows the `COMMIT_FILES_COMMAND_ID` log string — **inferred** COMMIT_FILES |
| `0x060A` | 6 | 1 | 5-byte request, 4-byte response |
| `0x080A` | 8 | 4 | most-used |
| `0x1B0A` | 27 | 1 | |

Which of these is `FWU_START`, `FWU_DATA` or `FWU_END` is **not yet
established**. The remaining 38 sites resolve their command at runtime.

## UpdateEnvironment

From the status table: *"FWU_START_MSG Heci message contains invalid value in
UpdateEnvironment. Value should be FWU_ENV_MANUFACTURING. (Other possible
value: FWU_ENV_IFU is obsolete)."*

So the field has effectively one valid value. Its **numeric** value is not yet
recovered.

## Status table

A fixed-stride table in `.data`: **1008 bytes per entry**, short text at +0 and
the long description at +501. Entries cover HECI transport failures, FW state
errors, OEM ID problems, and update-specific conditions such as:

- Full FW Update using same version is not allowed. Include `-allowsv`.
- Invalid Partition ID. Use a Partition ID which is possible to do Partial FW Update on.
- Firmware Update operation not initiated because a firmware update is already in progress.
- FW Update is disabled. MEBX has options to disable / enable FW Update.
- Unable to execute command in this Firmware State. Please reboot.

The table is not a single contiguous array — residues differ between regions —
so indexing a status code straight into it still needs the base worked out.

## Ordering rules

Enforced ME-side, per the status strings:

- `FWU_DATA` before any `FWU_START` is rejected.
- `FWU_END` with no preceding `FWU_DATA` is rejected.
- Oversized `FWU_DATA` is rejected.

## Open work

1. Identify which command number is `FWU_START`.
2. Recover the `FWU_START` payload struct and the `FWU_ENV_MANUFACTURING` value.
3. Establish the status-table base so result codes can be rendered.

There is no harmless FWU round-trip on CSME 15 to validate framing against, so
none of the above can be proven before `FWU_START` is sent for real. That is
the main risk in finishing this.
