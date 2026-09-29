"""
Kerberos enumeration (Kerberoasting, AS-REP roasting).

SCAFFOLD: returns SAMPLE findings. A real implementation would query LDAP for
servicePrincipalName / userAccountControl and request TGS/AS tickets via
impacket (GetUserSPNs, GetNPUsers).
"""
from __future__ import annotations

from typing import List

from app.models import Finding, FindingType

MODULE = "enumeration.kerberos"


def enumerate() -> List[Finding]:
    """Return SAMPLE Kerberos-related findings (demo data)."""
    return [
        Finding(
            finding_type=FindingType.KERBEROASTING,
            title="[DEMO] Cuenta de servicio kerberoasteable (RC4)",
            target="svc_sql@corp.example.local",
            detail=(
                "La cuenta de servicio 'svc_sql' tiene un SPN "
                "(MSSQLSvc/db01.corp.example.local:1433) y admite cifrado "
                "RC4-HMAC (etype 23), permitiendo Kerberoasting."
            ),
            evidence="[SAMPLE] GetUserSPNs.py -> etype 23, TGS extraído (demo).",
            source_module=MODULE,
            subtype="rc4",
            is_sample=True,
        ),
        Finding(
            finding_type=FindingType.ASREP_ROASTING,
            title="[DEMO] Cuenta sin pre-autenticación Kerberos",
            target="j.perez@corp.example.local",
            detail=(
                "La cuenta 'j.perez' tiene DONT_REQUIRE_PREAUTH activado "
                "(userAccountControl & 0x400000), permitiendo AS-REP Roasting."
            ),
            evidence="[SAMPLE] GetNPUsers.py -> AS-REP hash obtenido (demo).",
            source_module=MODULE,
            subtype="dont_require_preauth",
            is_sample=True,
        ),
    ]
