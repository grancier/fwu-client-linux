# Analysis inputs

Intel's binaries are **not** redistributed here — their licence forbids it.
This records exactly which artefacts the findings in `PROTOCOL.md` came from,
so anyone with their own copies can verify they are analysing the same bytes.

## Binaries

| Artefact | Size | SHA-256 |
|---|---|---|
| `ME_Intel_v15.0.56.2834.zip` | 2,308,791 | `4b83de65a0731d44c950f7982586c8c974886800e1c20187458d6cbe2ad98175` |
| `FWUpdLcl64.exe` | 2,280,344 | `7f98b7d64c2eee81fa9d7a68578fddf7bf87baf110766191cff3c5d9d4f90fa5` |
| `15.0.56.2834.bin` | 3,272,704 | `e59aa061f3769fe107dd326d637ad20b02d08dfa0ef6d69add9b933495ef4197` |

`FWUpdLcl64.exe` is PE32+ x86-64, image base `0x140000000`, built from
`...\System_Tools\FWUpdate\Windows64\FWUpdLcl64.pdb`.

## Platform the live results came from

| | |
|---|---|
| Board | ASUS PRIME H510M-A, BIOS 3002 |
| CPU | Intel Core i3-10100 (Comet Lake) |
| CSME | 15.0.42.2384 operational, 15.0.20.1466 recovery |
| OS | Ubuntu 24.04, kernel 7.0.0-31-generic |
| MEI | `mei`, `mei_me`; `/dev/mei0`; `hbm_ver` 2.2 |

## Toolchain

GNU objdump (GNU Binutils for Ubuntu) 2.46.

## Reproducing

```bash
objdump -d -M intel FWUpdLcl64.exe > fwupd.asm

./research/analyze_pe.py sections FWUpdLcl64.exe
./research/analyze_pe.py guids    FWUpdLcl64.exe
./research/analyze_pe.py imports  FWUpdLcl64.exe
./research/analyze_pe.py strings  FWUpdLcl64.exe
./research/analyze_pe.py transact FWUpdLcl64.exe --asm fwupd.asm
./research/parse_fpt.py 15.0.56.2834.bin
```

Live-hardware results come from `fwu-info` and `research/fwu_raw.py`.
