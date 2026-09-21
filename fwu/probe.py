"""Safe identification of the CSME 15 FWU command space.

The problem this solves: the update command codes are known for CSME 12
(START 2, DATA 4, END 6) from Intel's native Linux build, but the CSME 15
Windows build never issues them, so they are unverified on this generation.

The method: the ME answers an unrecognised command with a fixed refusal
envelope, `0xFF / 0x8D`, observed live for command 0. A command it *does*
implement is dispatched and answers with `response = command + 1` and a
command-specific status. Those two outcomes are distinguishable, so sending a
header-only message identifies whether a command exists without performing it.

Why a header-only message is safe for exactly these codes:

  * START carries a 90-byte struct. Four bytes cannot supply an image length,
    so the ME rejects it on length before any update begins.
  * DATA before any START is rejected by the ME's ordering rules.
  * END with no preceding DATA is rejected by the same rules.

Each probe additionally runs on a connection of its own, so no state can
carry between them, and no probe is ever sent after a START has succeeded.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import session as sess

# The CSME 12 update triple, the only codes with a documented meaning.
CSME12_START = 0x02
CSME12_DATA = 0x04
CSME12_END = 0x06

CANDIDATES = (
    (CSME12_START, "START (CSME 12 numbering)"),
    (CSME12_DATA, "DATA  (CSME 12 numbering)"),
    (CSME12_END, "END   (CSME 12 numbering)"),
)

# Commands already confirmed served on this platform, used as a control so a
# probe run proves the classifier works before anything is concluded from it.
CONTROL_SERVED = (0x18, "updatable size, known served")
CONTROL_UNKNOWN = (0x00, "legacy version, known unserved")


@dataclass
class Finding:
    command: int
    label: str
    outcome: str
    status: int
    code: int
    raw: str

    @property
    def implemented(self) -> bool:
        return self.outcome == "recognised"


def probe_command(command, label, device=None):
    """Send one header-only command on a fresh connection and classify it."""
    reply = sess.one_shot(command, device=device)
    if reply.unknown:
        outcome = "unknown"
    elif reply.echoed:
        outcome = "recognised"
    else:
        outcome = "unexpected"
    return Finding(command=command, label=label, outcome=outcome,
                   status=reply.status, code=reply.code,
                   raw=reply.raw.hex(" "))


def run(device=None, candidates=CANDIDATES):
    """Probe the controls, then the candidates. Returns a list of Findings."""
    findings = []
    for command, label in (CONTROL_UNKNOWN, CONTROL_SERVED):
        findings.append(probe_command(command, "control: " + label, device))
    for command, label in candidates:
        findings.append(probe_command(command, label, device))
    return findings


def controls_valid(findings) -> bool:
    """The classifier is trustworthy only if both controls land correctly."""
    by_cmd = {f.command: f for f in findings}
    lo = by_cmd.get(CONTROL_UNKNOWN[0])
    hi = by_cmd.get(CONTROL_SERVED[0])
    return (lo is not None and lo.outcome == "unknown"
            and hi is not None and hi.outcome == "recognised")
