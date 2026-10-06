"""
Adapter from GRC alerts to ENS Compliance Studio technical-evidence JSON.

Studio imports hallazgos as JSON/CSV with categoria, cvss, activoId, titulo.
This module never fabricates alerts: an empty list yields an empty payload
with is_sample=False. Findings marked is_sample are skipped.
"""
from __future__ import annotations

from typing import List, Optional

from app.models import FindingType, GRCAlert, RiskLevel

# Studio's hallazgo_categorias (data/mapping.json). Keep keys in that catalogue.
CATEGORIA_POR_TIPO: dict[FindingType, str] = {
    FindingType.SMB_SIGNING_DISABLED: "TLS",
    FindingType.KERBEROASTING: "AUTH_MFA",
    FindingType.ASREP_ROASTING: "AUTH_MFA",
    FindingType.UNCONSTRAINED_DELEGATION: "IDOR",
    FindingType.CONSTRAINED_RBCD_DELEGATION: "IDOR",
    FindingType.EXCESSIVE_PRIVILEGES: "IDOR",
    FindingType.ADCS_ESC: "AUTH_MFA",
    FindingType.WEAK_PASSWORD_POLICY: "BRUTE",
    FindingType.WEAK_LOCKOUT_POLICY: "BRUTE",
    FindingType.KRBTGT_PASSWORD_AGE: "AUTH_MFA",
    FindingType.PROTECTED_USERS_GAP: "IDOR",
    FindingType.ADMIN_WITH_SPN: "AUTH_MFA",
    FindingType.STALE_PRIVILEGED_ACCOUNT: "IDOR",
    FindingType.LDAP_SIGNING_NOT_REQUIRED: "AUTH_MFA",
    FindingType.LDAP_CHANNEL_BINDING_WEAK: "AUTH_MFA",
    FindingType.TRUST_SID_FILTERING: "IDOR",
    FindingType.LAPS_NOT_DEPLOYED: "DEFCREDS",
    FindingType.MACHINE_ACCOUNT_QUOTA: "IDOR",
    FindingType.ACL_CONTROL_PATH: "IDOR",
    FindingType.CLEARTEXT_SECRET_ATTR: "INFOLEAK",
    FindingType.GPO_WEAK_SETTING: "TLS",
    FindingType.AUDIT_POLICY_GAP: "LOGGING",
}

CVSS_POR_RIESGO: dict[RiskLevel, float] = {
    RiskLevel.CRITICO: 9.0,
    RiskLevel.ALTO: 7.5,
    RiskLevel.MEDIO: 5.0,
    RiskLevel.BAJO: 2.5,
}

ACTIVO_ID = "AD"
FORMATO = "ens-studio-hallazgos"
NOTA = (
    "Importa este JSON en ENS Compliance Studio → Evidencia técnica. "
    "Crea antes un activo con id AD (Active Directory). "
    "Sin alertas el array va vacío: no se inventan hallazgos."
)


def _item_id(alert: GRCAlert, index: int) -> str:
    raw = f"{alert.rule_id}-{index}"
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in raw)
    return f"AD-{safe}"[:40]


def build_studio_evidencia(
    alerts: List[GRCAlert],
    domain: Optional[str] = None,
) -> dict:
    """Return a Studio-importable dict. Empty alerts → empty hallazgos."""
    hallazgos = []
    for i, alert in enumerate(alerts, start=1):
        if alert.finding.is_sample:
            continue
        categoria = CATEGORIA_POR_TIPO.get(alert.finding.finding_type)
        if not categoria:
            continue
        hallazgos.append(
            {
                "id": _item_id(alert, i),
                "titulo": alert.finding.title,
                "categoria": categoria,
                "cvss": CVSS_POR_RIESGO.get(alert.risk, 2.5),
                "activoId": ACTIVO_ID,
                "estado": "abierto",
                "fuente": "ENS AD Auditor",
                "ens": [c.id for c in alert.ens_controls],
                "objetivo": alert.finding.target,
            }
        )
    return {
        "formato": FORMATO,
        "is_sample": False,
        "origen": "ENS AD Auditor",
        "dominio": domain,
        "activo_sugerido": {
            "id": ACTIVO_ID,
            "nombre": domain or "Active Directory",
        },
        "nota": NOTA,
        "hallazgos": hallazgos,
    }
