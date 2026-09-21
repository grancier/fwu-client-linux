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
