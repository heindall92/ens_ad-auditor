"""
Read-only presence check for cleartext password attributes.

The attribute value is never requested and never copied into the finding.
"""
from __future__ import annotations

from typing import List

from app.enumeration.ldap_client import LdapSession, principal
from app.models import Finding, FindingType

MODULE = "enumeration.secrets"

_ATTRS = ("userPassword", "unixUserPassword")


def _sam(row: dict) -> str:
    return str(row.get("sAMAccountName") or row.get("dn") or "")


def enumerate(session: LdapSession) -> List[Finding]:
    findings: List[Finding] = []
    for attr in _ATTRS:
        rows = session.search(
            f"(&(objectClass=user)({attr}=*))",
            ["sAMAccountName", "distinguishedName"],
        )
        for row in rows:
            sam = _sam(row)
            if not sam or sam.endswith("$"):
                continue
            findings.append(
                Finding(
                    finding_type=FindingType.CLEARTEXT_SECRET_ATTR,
                    title=f"Atributo {attr} presente",
                    target=principal(sam, session.domain) if row.get("sAMAccountName") else sam,
                    detail=(
                        f"La cuenta tiene el atributo {attr}. El valor no se ha leído "
                        f"ni se incluye en el informe."
                    ),
                    evidence=f"attribute={attr} present=true",
                    source_module=MODULE,
                    subtype=attr,
                )
            )
    return findings
