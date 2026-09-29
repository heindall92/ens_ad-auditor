"""
Parse GptTmpl.inf text already read from SYSVOL.

No network access. Callers decide whether the file was actually retrieved.
"""
from __future__ import annotations

import re
from typing import List, Optional

from app.models import Finding, FindingType

MODULE = "enumeration.gpo"

_REG_VALUE = re.compile(
    r"(RequireSecuritySignature|LDAPServerIntegrity)\s*=\s*4\s*,\s*(\d+)",
    re.IGNORECASE,
)
_AUDIT = re.compile(r"^(Audit[A-Za-z0-9]+)\s*=\s*(\d+)\s*$", re.MULTILINE)

_AUDIT_KEYS = {
    "AuditAccountLogon",
    "AuditLogonEvents",
    "AuditDSAccess",
    "AuditAccountManage",
}


def _section(text: str, name: str) -> str:
    match = re.search(rf"\[{re.escape(name)}\](.*?)(?:\n\[|\Z)", text, re.IGNORECASE | re.DOTALL)
    return match.group(1) if match else ""


def parse_gpt(text: str, source: str = "GptTmpl.inf") -> List[Finding]:
    findings: List[Finding] = []
    registry = _section(text, "Registry Values")
    for match in _REG_VALUE.finditer(registry):
        key, raw = match.group(1), int(match.group(2))
        weak = raw == 0 or (key.lower() == "ldapserverintegrity" and raw < 2)
        if not weak:
            continue
        findings.append(
            Finding(
                finding_type=FindingType.GPO_WEAK_SETTING,
                title=f"GPO con {key} débil",
                target=source,
                detail=(
                    f"{key}={raw} en {source}. La política leída no exige la "
                    f"protección correspondiente."
                ),
                evidence=f"{key}={raw}",
                source_module=MODULE,
                subtype=key.lower(),
            )
        )

    audit = _section(text, "Event Audit")
    disabled = []
    for match in _AUDIT.finditer(audit):
        name, raw = match.group(1), int(match.group(2))
        if name in _AUDIT_KEYS and raw == 0:
            disabled.append(name)
    if disabled:
        findings.append(
            Finding(
                finding_type=FindingType.AUDIT_POLICY_GAP,
                title="Auditoría de directorio desactivada en la GPO leída",
                target=source,
                detail=(
                    "La sección [Event Audit] leída pone a 0: "
                    + ", ".join(disabled)
                    + ". Es la política vista, no un recuento de eventos."
                ),
                evidence=f"disabled={disabled}",
                source_module=MODULE,
                subtype="event_audit",
            )
        )
    return findings


def saw_event_audit(texts: List[str]) -> bool:
    return any(_section(text, "Event Audit").strip() for text in texts)


def parse_many(texts: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    for index, text in enumerate(texts, start=1):
        findings.extend(parse_gpt(text, source=f"GptTmpl.inf#{index}"))
    return findings
