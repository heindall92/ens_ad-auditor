"""
Enumeration modules.

Each module exposes an `enumerate(...)` function that returns Finding objects
observed against an authorised domain. `run_all` without a target returns an
empty list: this tool does not invent findings.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from app.enumeration import adcs, delegation, kerberos, policy, smb
from app.enumeration.ldap_client import LdapSession, bind
from app.enumeration.target import AuditConnectionError, AuditTarget
from app.models import Finding

__all__ = [
    "kerberos",
    "delegation",
    "adcs",
    "smb",
    "policy",
    "run_all",
    "AuditTarget",
    "AuditConnectionError",
]


def run_all(
    target: Optional[AuditTarget] = None,
) -> Tuple[List[Finding], List[str]]:
    """Run every enumeration module.

    Without a target the result is empty. Module failures are
    collected in the error list; successful modules still contribute findings.
    """
    if target is None:
        return [], []

    errors: List[str] = []
    findings: List[Finding] = []
    session: Optional[LdapSession] = None

    try:
        session = bind(target)
    except AuditConnectionError as exc:
        raise
    except Exception as exc:
        raise AuditConnectionError(str(exc)) from exc

    try:
        try:
            findings.extend(smb.enumerate(target, session))
        except Exception as exc:
            errors.append(f"smb: {exc}")

        try:
            findings.extend(kerberos.enumerate(session))
        except Exception as exc:
            errors.append(f"kerberos: {exc}")

        try:
            findings.extend(delegation.enumerate(session))
        except Exception as exc:
            errors.append(f"delegation: {exc}")

        try:
            findings.extend(policy.enumerate(session))
        except Exception as exc:
            errors.append(f"policy: {exc}")

        try:
            findings.extend(adcs.enumerate(target))
        except Exception as exc:
            errors.append(f"adcs: {exc}")
    finally:
        if session is not None:
            session.close()

    return findings, errors
