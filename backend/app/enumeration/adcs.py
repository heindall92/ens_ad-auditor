"""
AD CS enumeration (ESC1-ESC8) via certipy-ad, read-only.

Uses Certipy `find` (LDAP + optional HTTP check of Web Enrollment). Does not
request, forge or relay certificates.
"""
from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, List

from app.enumeration.target import AuditTarget
from app.models import Finding, FindingType

MODULE = "enumeration.adcs"

def _is_esc(name: str) -> bool:
    text = str(name).strip().upper()
    return text.startswith("ESC") and text[3:].isdigit()


def _certipy_target(target: AuditTarget):
    from certipy.lib.target import Target

    hashes = None
    password = target.password
    if target.nthash:
        hashes = f"{target.impacket_hashes[0]}:{target.nthash}"
        password = None
    return Target.create(
        domain=target.domain,
        username=target.sam,
        password=password or "",
        hashes=hashes,
        dc_ip=target.resolved_dc_ip(),
        remote_name=target.dc_host,
        target_ip=target.resolved_dc_ip(),
        no_pass=True,
        timeout=12,
        ns=target.resolved_dc_ip(),
        dns_tcp=True,
    )


def _iter_blocks(blob: Any) -> List[Dict[str, Any]]:
    if not blob or isinstance(blob, str):
        return []
    if isinstance(blob, dict):
        return [v for v in blob.values() if isinstance(v, dict)]
    if isinstance(blob, list):
        return [v for v in blob if isinstance(v, dict)]
    return []


def _findings_from_output(data: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []

    for ca in _iter_blocks(data.get("Certificate Authorities")):
        name = ca.get("CA Name") or ca.get("DNS Name") or "CA"
        dns = ca.get("DNS Name") or ""
        vulns = ca.get("[!] Vulnerabilities") or {}
        for esc, desc in vulns.items():
            if not _is_esc(str(esc)):
                continue
            target = f"CA: {name}" + (f" ({dns})" if dns else "")
            findings.append(
                Finding(
                    finding_type=FindingType.ADCS_ESC,
                    title=f"Configuración de CA vulnerable ({esc})",
                    target=target,
                    detail=str(desc),
                    evidence=f"certipy find -> {esc}: {desc}",
                    source_module=MODULE,
                    subtype=esc,
                    is_sample=False,
                )
            )

    for tpl in _iter_blocks(data.get("Certificate Templates")):
        name = tpl.get("Template Name") or tpl.get("Display Name") or "plantilla"
        cas = tpl.get("Certificate Authorities") or []
        if isinstance(cas, str):
            cas = [cas]
        ca_label = ", ".join(str(c) for c in cas) if cas else "CA desconocida"
        vulns = tpl.get("[!] Vulnerabilities") or {}
        for esc, desc in vulns.items():
            if not _is_esc(str(esc)):
                continue
            findings.append(
                Finding(
                    finding_type=FindingType.ADCS_ESC,
                    title=f"Plantilla de certificado vulnerable ({esc})",
                    target=f"Template: {name} @ {ca_label}",
                    detail=str(desc),
                    evidence=f"certipy find -> {esc}: {desc}",
                    source_module=MODULE,
                    subtype=esc,
                    is_sample=False,
                )
            )
    return findings


def enumerate(target: AuditTarget) -> List[Finding]:
    from certipy.commands.find import Find

    ctarget = _certipy_target(target)
    scheme = target.ldap_scheme if target.ldap_scheme in {"ldap", "ldaps"} else "ldap"

    with tempfile.TemporaryDirectory(prefix="ens-adcs-") as tmp:
        prefix = os.path.join(tmp, "out")
        finder = Find(
            target=ctarget,
            json=True,
            text=False,
            stdout=False,
            bloodhound=False,
            enabled=False,
            vulnerable=False,
            hide_admins=True,
            dc_only=False,
            scheme=scheme,
            output=prefix,
        )
        finder.find()
        path = f"{prefix}_Certipy.json"
        if not os.path.isfile(path):
            return []
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    if not isinstance(data, dict):
        return []
    return _findings_from_output(data)
