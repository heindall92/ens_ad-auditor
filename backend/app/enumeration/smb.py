"""
SMB enumeration (SMB signing).

SCAFFOLD: returns SAMPLE findings. A real implementation would check SMB
signing requirements per host (e.g. via impacket / crackmapexec-style probes).
"""
from __future__ import annotations

from typing import List

from app.models import Finding, FindingType

MODULE = "enumeration.smb"


def enumerate() -> List[Finding]:
    """Return SAMPLE SMB-related findings (demo data)."""
    return [
        Finding(
            finding_type=FindingType.SMB_SIGNING_DISABLED,
            title="[DEMO] SMB signing no requerido",
            target="10.10.10.25 (WS-FINANCE-07)",
            detail=(
                "El host no requiere firma SMB (signing:False). Es susceptible "
                "de NTLM relay y manipulación de tráfico en tránsito."
            ),
            evidence="[SAMPLE] SMB signing:False (demo).",
            source_module=MODULE,
            subtype="not_required",
            is_sample=True,
        ),
    ]
