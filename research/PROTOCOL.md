# FWU protocol notes

## The FWU client protocol — confirmed and working

**The FWU client takes no group/command header.** A request is a bare
little-endian u32 command, optionally followed by a payload:

```
request : <u32 command> [payload]
reply   : <u32 response_code> <u32 status> [data]
```

`response_code` is `command + 1` when recognised and `0xFF` when not. `status`
is `0` on success and `0x8D` for an unrecognised command — the binary's own
status table maps `0x8D` to **UNKNOWN**, which matches the live behaviour
exactly.

The client is reached through a **GUID table at `0x1401afb10`** indexed by the
tool's selector. `rcx` is that index, not a client id:

| Selector | Index | Client |
|---|---|---|
| `0x16`, `0x17` | 5 | MKHI |
| `0x18` | 10 | `082ee5a7-…` |
| `0x19` | 1 | **FWU** |
| `0x13` | 19 | `92136c79-…` (absent on this platform) |
| other | = selector, must be < 0x15 | table entry |

### Live results on CSME 15.0.42.2384

| Command | Response | Status | Data |
|---|---|---|---|
| `0x00` legacy version | `0xFF` | `0x8D` | not served on CSME 15 |
| `0x12` | `0x13` | `0x00` | 16 B, zeroes |
| `0x18` | `0x19` | `0x00` | 4 B — `0x0029A000` = 2,727,936 |
| `0x1A` | `0x1B` | `0x00` | 992 B |

These are the only three FWU commands `FWUpdLcl64.exe` issues. All three are
implemented in `fwu/fwu.py` and verified.

`0x18` returning 2,727,936 is the right order of magnitude for a firmware
region or maximum-image size and is worth identifying.

### Corrections this overturned

- The FWU client was **never** refusing everything. It refused the two invalid
  command codes tried earlier (`0x00` and `0x080A`). There is **no
  precondition** and no disabled-update policy.
- The FWU GUID has no direct code reference because it is reached through the
  runtime-indexed table above, not a direct load.


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

### Recovered signature

**Confirmed** by reading four call sites:

| Location | Meaning |
|---|---|
| `rcx` | `0x17` at every site — a client or handle selector, never varies |
| `rdx` | request buffer |
| `r8d` | request size in bytes |
| `r9` | response buffer |
| `[rsp+0x20]` | pointer to the response-size slot (in/out) |
| `[rsp+0x30]` | timeout, `0x7530` = 30000 ms |

Return value in `eax`, zero on success — every site follows with
`test eax,eax`.

### Per-command message shapes

**Confirmed** from the staging code at each site:

| Command | Request | Response |
|---|---|---|
| 4 (`0x040A`) | — | 4 B |
| 6 (`0x060A`) | 5 B: u32 header + one computed byte at +4 | 4 B |
| 8 (`0x080A`) | header, size held in a register | 8 B |
| 27 (`0x1B0A`) | 8 B: u32 header + `0xFF` at +4, then padding | 4 B |

None of these is large enough to be `FWU_START` carrying an image length, and
none sits in a chunking loop, so `FWU_START` and `FWU_DATA` are among the 38
sites that resolve their command at runtime.

### rcx selects the client

**Confirmed.** `rcx` is not a constant — it picks which HECI client the
transact targets:

- `0x17` on all six FWU sites
- `0` on a different flow that sends a `0x0101` header with a 10000 ms timeout

Filtering transact sites on `rcx == 0x17` isolates FWU cleanly: **6 of 45**.

### Command 8 is a status query

**Confirmed** from its response handling — 4-byte request (header only),
8-byte response, of which two bits are kept:

```asm
movzx ecx, BYTE PTR [rsp+0x4b]   ; result byte, response+3
mov   ebx, DWORD PTR [rsp+0x4c]  ; response+4
and   ebx, 0x3                   ; 2-bit state
mov   DWORD PTR [rdi], ebx
```

Four call sites, more than any other command. Being read-only, it looked like
the best candidate for a safe framing gate. **It was tried, and it failed.**

### The header layout is NOT validated

Sending `0x0000080A` (group `0x0A`, command 8) to the live FWU client returns
**byte-identical output to command 0**:

```
ff 00 00 00 8d 00 00 00
```

Two different command words producing the same reply means this is a generic
refusal envelope — `{u32 0x000000FF, u32 0x0000008D}` — emitted before command
dispatch, not a per-command response. Note also that bit 15 is clear, so the
reply is not itself in the header format.

So the bitfield layout above remains **inferred and unconfirmed**. The
disassembly evidence for it is solid as a description of how the *tool* builds
requests; what is not established is that a bare correctly-grouped command is
accepted at all.

The likeliest reading is that the FWU client refuses everything until some
precondition is met — a state the tool establishes before its first FWU
transact. Candidates worth tracing, in order:

1. Whatever the tool does *before* its first `rcx=0x17` transact.
2. The helpers `0x14001f130` (4 callers) and `0x14000ef40` (29 callers).
3. An MKHI-side enable or mode change.

Resolving this by sending further speculative command words is explicitly out
of scope: an accidental malformed `FWU_START` is the one failure this project
cannot walk back.

### The Windows transport is not the answer

**Confirmed** by walking the import call sites. The tool's HECI plumbing is:

| Site | API | Role |
|---|---|---|
| `0x14001fbeb` | `CreateFileW` | opens the device interface |
| `0x14001fa46` | `DeviceIoControl` | the only HECI ioctl site in the binary |
| `0x14001f264` | `WriteFile` | send |
| `0x14001f4c0` | `ReadFile` | receive |

`0x14001fa46` is a **generic wrapper** — request code, buffers and sizes all
arrive from the caller's stack, none are immediates — and it handles
`ERROR_IO_PENDING` (`0x3E5`) for overlapped I/O. It is ordinary Win32
plumbing with no ME semantics in it.

That makes this branch a dead end by construction: the Linux `mei` driver
already performs the equivalent connect successfully, returning `max_msg` 4096
and `proto_ver` 1. **The refusal is generated by the ME, not by transport**,
so no amount of Win32 detail explains it.

### Correction: 0x17 is not established as a client selector

`0x17` appears as the first argument at all six FWU transact sites, and as `0`
at a non-FWU site — which is what suggested a client selector. But it also
appears as a plain **error code** inside the `DeviceIoControl` wrapper
(`mov DWORD PTR [rsp+0x40],0x17` on failure paths). The selector reading is
therefore **inferred, not confirmed**. It still works as a filter for isolating
FWU call sites, which is all it is relied on for here.

### Better hypothesis: local FW update may be disabled

The status table carries these, which fit the observed behaviour far better
than a framing error:

- *FW Update is disabled. MEBX has options to disable / enable FW Update.*
- *Unable to execute command in this Firmware State. Please reboot.*

And the tool has a positive-confirmation string, `Local FWUpdate is Enabled`,
which it prints only after checking.

An earlier note here claimed local FW update was enabled because the FWU client
accepted a connection. **That inference was wrong**: accepting a HECI
connection is not the same as accepting commands. A firmware that has local FW
update disabled would connect and then refuse every command — exactly the
observed `0xFF / 0x8D` for both command 0 and command 8.

### How the tool determines it — MKHI FWCAPS rule 7

**Confirmed**, both from the binary and by implementing it against live
hardware. The check is not an FWU query at all:

```asm
lea   rcx, [rbp+0x214]        ; u16 out-param
call  0x140010e30             ; -> 0x1400205d0
movzx eax, WORD PTR [rbp+0x214]
cmp   r14w, ax                ; r14 = 1
jne   skip
mov   r8d, 0x1d4              ; message 468, "Local FWUpdate is Enabled"
```

`0x1400205d0` builds an 8-byte request with header `0x203` — group 3
(FWCAPS), command 2 (GET_RULE) — and the rule id in the second u32:

| Field | Value |
|---|---|
| Request | `{u32 0x00000203, u32 rule_id}`, 8 B |
| Rule id for local FW update | `7` |
| Reply | at least 13 B |
| Reply +0..3 | MKHI header, result byte at +3 |
| Reply +4..7 | rule id echo |
| Reply +8 | payload length, checked `== 4` |
| Reply +9..12 | payload; low u16 is the value |
| Meaning | `1` = local firmware update enabled |

Implemented in `fwu/fwcaps.py`.

### Result: the hypothesis is wrong

Against this platform the query returns **1 — local firmware update is
ENABLED** — and the FWU client still refuses both command 0 and command 8 with
the same `0xFF / 0x8D`.

So a disabled-update policy does not explain the refusal, and that line of
reasoning is closed.

What it does establish is the method: a request encoding read out of the
disassembly, implemented from scratch, returned a correct and corroborated
answer on the first attempt. The same approach should hold for FWU once the
right precondition is found.

## Group 0x0A rides on MKHI, not on the FWU client

**Confirmed against live hardware.** Sending the group-`0x0A` command 8 header
to the **MKHI** client returns a proper dispatched response:

```
request : 0a 08 00 00
reply   : 0a 88 00 89
```

The ME echoes group `0x0A`, echoes command 8, sets the response bit, and
reports a result — exactly the layout read out of the disassembly. That
**confirms the header bitfield**, which until now was inferred:

| Bits | Field |
|---|---|
| 0-7 | group id |
| 8-14 | command |
| 15 | is_response |
| 16-23 | reserved |
| 24-31 | result |

### Consequences

- The earlier `0x17 = FWU client` mapping was **wrong**. Commands 4, 6, 8 and
  27 are MKHI group-`0x0A` commands. `0x16` and `0x17` are indices into the
  tool's own client table, not ME client identities.
- Every probe aimed at the `309dcde8-…` FWU client was aimed at the wrong
  place. That client answers *everything* with the same 8-byte
  `ff 00 00 00 8d 00 00 00`, which is not MKHI framing at all — it is a
  separate, probably legacy, protocol.
- The "no harmless FWU round-trip exists" conclusion is therefore void: group
  `0x0A` over MKHI dispatches cleanly and is a usable channel.

## The full recovered command set

**Confirmed** by matching each transact site's request buffer slot to the
header immediate written into that exact slot — 24 of 45 sites resolve:

| Group | Commands | Request sizes |
|---|---|---|
| `0x00` | 1, 2, 16 | 1036, 1036, 4 |
| `0x05` | 7, 19 | 4, 4 |
| `0x0A` | 4, 6, 8, 27 | 4, 5, 4/reg, 8 |
| `0x12` / `0x18` / `0x1A` | 0 | 4, 4, 8 |
| `0xF0` | 18, 20, 28 | 4, 4, 8 |
| `0xFF` | 2, 29, 31 | 4, 4, 4 |

Group `0xFF` command 2 is `GET_FW_VERSION` and group `0x03` command 2 is
FWCAPS `GET_RULE`, both verified live, which validates the extraction.

The per-site "selector" (`rcx`) is **not** a client id. Group `0x0A` carries
selector `0x17` yet answers on MKHI, and `0x140020200` consumes the same value
to choose an error table. It is an error-table index.

### No image-sized request exists in this binary

The largest request any of the 45 transact sites builds is **1036 bytes** — a
4-byte header plus a 1032-byte body, at `0x140005d9b`:

```asm
mov BYTE PTR [rsp+0x50], 0x0     ; group 0x00
mov BYTE PTR [rsp+0x51], dil     ; command from the caller's first argument
mov r8d, 0x40c                   ; 1036 B request
```

and that 1032-byte body is `memset` to zero and never filled before the send.
It is a large fixed-size query struct, not payload.

For a tool that uploads a 3,272,704-byte image this is decisive: **the image
upload does not go through this transact function at all**, or it is among the
21 sites whose header is computed at runtime and has not been identified.
Either way, `FWU_START`, `FWU_DATA` and `FWU_END` remain unlocated.

### Open: result 0x89

Command 8 dispatches but returns result `0x89`. The tool maps result codes to
messages in `0x140020200`, a jump table keyed by client id (`0x16` → case 6,
`0x17` → case 7) selecting a `{count, table, default}` triple, where each
8-byte entry is `{u32 status, u32 message_index}` searched linearly.

Resolving those tables produced field labels — *Wireless MAC address*, *HDA
Subsystem Vendor ID* — not status text, and `0x89` is absent from them. So
either the case resolution or the table identification is wrong, and `0x89`
remains **undecoded**.

### One transact chokepoint, no bulk bypass

The low-level send `0x14001eed0` has only **5 callers, all inside the transact
layer itself** (`0x14001ff00`–`0x140020200`). There is no separate bulk path
for image data, so `FWU_DATA` goes through the same wrapper with a
runtime-resolved command word and a caller-supplied buffer.

`0x140020200`, called with `edx = 0x17` right after each transact returns, is
the status-to-message mapper.

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

## Decoded: commands 0x18 and 0x1A

**Confirmed live.**

### 0x18 - updatable firmware size

Returns a u32. On this platform `0x29A000` = 2,727,936, which is exactly the
sum of the image's updatable **code** partitions, data partitions excluded:

    IVBP 16384 + RBEP 98304 + FTPR 1200128 + NFTP 1228800
         + PMCP 155648 + PPHY 24576 + PCHC 4096 = 2727936

The command is a **stateful toggle**: a success is followed by status
`0x2BE` on the next call, then succeeds again. `get_updatable_size()`
retries once to absorb it.

### 0x1A - installed update partition inventory

Header `{8 zero bytes, u32 entry_size = 0x30, u32 count}` then fixed 48-byte
entries of `{char name[4], u32 reserved, u16 version[4], ...}`:

| Name | Version |
|---|---|
| PMCP | 150.2.10.1020 |
| PPHY | 12.14.215.2015 |
| SAMF | 1.17.0.0 |
| PCHC | 15.0.0.1021 |

PMCP and PPHY match the `$MN2` manifest versions read straight out of the
firmware image, which independently confirms the decode.

### 0x12 - status

16 bytes, all zero while idle. Given the tool's progress string
`Sending the update image to FW for verification: [ %u%% ]`, this is the
likely progress/status structure during an update.

## The updater programs SPI directly, not over HECI

**Confirmed.** Two independent FWUpdLcl builds (15.0.50 and 15.0.56) have an
*identical* HECI command set across the same eight groups, and in neither does
any transact site carry more than 1036 bytes. A 3.2 MB image cannot go that
way.

The binary instead carries a full SPI flash-programming path:

    Failed to initialize SPI interface.
    Could not verify the SPI access permissions, SPI programming is subject
      to region protection conditions.
    BIOS Region write access permissions do not match Intel recommended values.
    Flash descriptor is not valid.
    - Programming Flash [0x%07X] %5dKB of %5dKB - %3.0f percent complete.
    - Verifying Flash  [0x%07lX] %5dKB of %5dKB - %3.0f percent complete.

So the update flow is: HECI for control and inventory, **direct SPI writes for
the image**, gated by flash-descriptor region permissions.

`FWU_START` / `FWU_DATA` / `FWU_END` appear only in the ME status-code table
the tool uses to render errors. The ME implements that upload protocol; this
tool does not drive it. That resolves why no bulk HECI sender exists.

### Corroboration from coreboot

coreboot (GPL-2.0, `src/soc/intel/common/block/cse`) independently confirms
the group map recovered here:

| coreboot | Value | Recovered here |
|---|---|---|
| `MKHI_GROUP_ID_CBM` | `0x00` | cmds 1, 2, 16 |
| `MKHI_GROUP_ID_HMRFPO` | `0x05` | cmds 7, 19 |
| `MKHI_GROUP_ID_FWCAPS` | `0x03` | verified live |
| `MKHI_GROUP_ID_BUP_COMMON` | `0xf0` | cmds 18, 20, 28 |
| `MKHI_BUP_COMMON_GET_BOOT_PARTITION_INFO` | `0x1c` = 28 | exact match |
| `MKHI_GEN_GET_FW_VERSION` | `0x02` in `0xff` | verified live |
| `MKHI_CBM_GLOBAL_RESET_REQ` | `0x0b` in `0x00` | the reset step |

Group `0x05` being HMRFPO - Host ME Region Flash Protection Override - fits
the SPI architecture exactly: unlock the ME region, write it, re-lock.
