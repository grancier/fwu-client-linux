"""MEI client GUIDs.

Read out of the .rdata client table in Intel's FWUpdLcl64.exe, where they sit
as adjacent 16-byte entries, and confirmed live against /dev/mei0.
"""
import uuid

# Firmware update endpoint. proto_ver 1, max_msg 4096 on CSME 15.0.
FWU = uuid.UUID("309dcde8-ccb1-4062-8f78-600115a34327")

# ME Kernel Host Interface. proto_ver 2, max_msg 2048. Informational queries.
MKHI = uuid.UUID("8e6a6715-9abc-4043-88ef-9e39c6f63e0f")

# AMT host interface. Present on the platform but unused here.
AMTHI = uuid.UUID("12f80028-b4b7-4b2d-aca8-46e0ff65814c")

BY_NAME = {"fwu": FWU, "mkhi": MKHI, "amthi": AMTHI}
