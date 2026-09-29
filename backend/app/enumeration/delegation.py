"""
Delegation enumeration (unconstrained, constrained, RBCD).

SCAFFOLD: returns SAMPLE findings. A real implementation would inspect
userAccountControl (TRUSTED_FOR_DELEGATION), msDS-AllowedToDelegateTo and
msDS-AllowedToActOnBehalfOfOtherIdentity via LDAP.
"""
from __future__ import annotations

from typing import List

from app.models import Finding, FindingType

MODULE = "enumeration.delegation"


def enumerate() -> List[Finding]:
    """Return SAMPLE delegation-related findings (demo data)."""
    return [
        Finding(
            finding_type=FindingType.UNCONSTRAINED_DELEGATION,
            title="[DEMO] Servidor con delegación no restringida",
            target="APP01$@corp.example.local",
            detail=(
                "El equipo 'APP01' tiene TRUSTED_FOR_DELEGATION habilitado. "
                "Puede almacenar TGT de cualquier usuario que se autentique, "
                "incluidos administradores de dominio."
            ),
            evidence="[SAMPLE] LDAP userAccountControl=0x80000 (demo).",
            source_module=MODULE,
            is_sample=True,
        ),
        Finding(
            finding_type=FindingType.CONSTRAINED_RBCD_DELEGATION,
            title="[DEMO] RBCD escribible por principal no privilegiado",
            target="FILE02$@corp.example.local",
            detail=(
                "El atributo msDS-AllowedToActOnBehalfOfOtherIdentity de "
                "'FILE02' es escribible por un usuario estándar, habilitando "
                "una ruta de escalada vía RBCD."
            ),
            evidence="[SAMPLE] ACL GenericWrite sobre FILE02$ (demo).",
            source_module=MODULE,
            subtype="rbcd_writable",
            is_sample=True,
        ),
        Finding(
            finding_type=FindingType.EXCESSIVE_PRIVILEGES,
            title="[DEMO] Usuarios innecesarios en Domain Admins",
            target="Group: Domain Admins",
            detail=(
                "Se detectan 12 miembros en 'Domain Admins', varios de ellos "
                "cuentas de usuario nominales y de servicio sin necesidad "
                "justificada (violación de mínimo privilegio)."
            ),
            evidence="[SAMPLE] net group 'Domain Admins' /domain (demo).",
            source_module=MODULE,
            is_sample=True,
        ),
    ]
