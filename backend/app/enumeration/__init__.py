"""
Enumeration modules.

Each module exposes an `enumerate(...)` function that returns Finding objects
observed against an authorised domain. `run_all` without a target returns an
empty list: this tool does not invent findings.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from app.enumeration import acl, adcs, delegation, gpo_text, kerberos, policy, secrets, smb, sysvol
from app.enumeration.coverage import UNAVAILABLE, empty_coverage, mark
from app.enumeration.ldap_client import LdapSession, bind
from app.enumeration.target import AuditConnectionError, AuditTarget
from app.models import CoverageCheck, Finding

__all__ = [
    "kerberos",
    "delegation",
    "adcs",
    "smb",
    "policy",
    "acl",
    "secrets",
    "run_all",
    "AuditTarget",
    "AuditConnectionError",
]


def _run_named(name: str, call, findings: List[Finding], errors: List[str], coverage: List[CoverageCheck]) -> bool:
    before = len(findings)
    try:
        findings.extend(call())
    except Exception as exc:
        errors.append(f"{name}: {exc}")
        mark(coverage, name, "no_comprobado", f"No comprobado. El módulo falló: {exc}")
        return False
    added = len(findings) - before
    if added:
        detail = f"Comprobado. El módulo ha devuelto {added} hallazgo(s). No se ha ejecutado ningún ataque."
    else:
        detail = "Comprobado contra el directorio autorizado. Sin hallazgo no se inventa uno."
    mark(coverage, name, "comprobado", detail)
    return True


def run_all(
    target: Optional[AuditTarget] = None,
) -> Tuple[List[Finding], List[str], List[CoverageCheck]]:
    """Run every enumeration module.

    Without a target the result is empty and every coverage row stays
    no_comprobado. Module failures are collected in the error list.
    """
    coverage = empty_coverage()
    if target is None:
        return [], [], coverage

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
        _run_named("smb", lambda: smb.enumerate(target, session), findings, errors, coverage)
        _run_named("kerberos", lambda: kerberos.enumerate(session), findings, errors, coverage)
        _run_named("delegacion", lambda: delegation.enumerate(session), findings, errors, coverage)
        if _run_named("politica", lambda: policy.enumerate(session), findings, errors, coverage):
            groups = {
                "krbtgt": {"krbtgt_password_age"},
                "privilegiadas": {
                    "protected_users_gap",
                    "admin_with_spn",
                    "stale_privileged_account",
                },
                "ldap": {"ldap_signing_not_required", "ldap_channel_binding_weak"},
                "confianza": {"trust_sid_filtering", "laps_not_deployed", "machine_account_quota"},
            }
            for check_id, types in groups.items():
                count = sum(1 for item in findings if item.finding_type.value in types)
                if count:
                    detail = f"Comprobado en la misma lectura de directorio. {count} hallazgo(s)."
                else:
                    detail = "Comprobado en la misma lectura de directorio. Sin hallazgo no se inventa uno."
                mark(coverage, check_id, "comprobado", detail)
        _run_named("acl", lambda: acl.enumerate(session), findings, errors, coverage)
        _run_named("secretos", lambda: secrets.enumerate(session), findings, errors, coverage)
        _run_named("adcs", lambda: adcs.enumerate(target), findings, errors, coverage)

        try:
            texts, gpo_error = sysvol.read_gpt_files(target)
        except Exception as exc:
            texts, gpo_error = [], str(exc)
        if gpo_error or not texts:
            detail = gpo_error or "SYSVOL sin GptTmpl.inf legible"
            mark(coverage, "gpo", "no_comprobado", f"No comprobado. {detail}")
            mark(
                coverage,
                "monitorizacion",
                "no_comprobado",
                "No comprobado. Sin GptTmpl.inf no hay sección [Event Audit] que leer.",
            )
        else:
            try:
                parsed = gpo_text.parse_many(texts)
            except Exception as exc:
                errors.append(f"gpo: {exc}")
                mark(coverage, "gpo", "no_comprobado", f"No comprobado. El módulo falló: {exc}")
                mark(
                    coverage,
                    "monitorizacion",
                    "no_comprobado",
                    "No comprobado. No se ha podido leer [Event Audit].",
                )
            else:
                findings.extend(parsed)
                mark(
                    coverage,
                    "gpo",
                    "comprobado",
                    "Comprobado sobre los GptTmpl.inf leídos. No se ha editado ninguna GPO.",
                )
                if gpo_text.saw_event_audit(texts):
                    mark(
                        coverage,
                        "monitorizacion",
                        "comprobado",
                        "Comprobado sobre [Event Audit] leída. No se estima un número de eventos.",
                    )
                else:
                    mark(
                        coverage,
                        "monitorizacion",
                        "no_comprobado",
                        "No comprobado. Los ficheros leídos no traen la sección [Event Audit].",
                    )
        for check_id, reason in UNAVAILABLE.items():
            mark(coverage, check_id, "no_comprobado", reason)
    finally:
        if session is not None:
            session.close()

    return findings, errors, coverage
