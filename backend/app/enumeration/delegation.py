"""
Delegation and privileged-group enumeration.

Read-only LDAP: unconstrained / constrained / RBCD and Domain Admins membership.
Does not modify msDS-AllowedToActOnBehalfOfOtherIdentity or any other attribute.
"""
from __future__ import annotations

from typing import List, Optional, Set

from app.enumeration.ldap_client import LdapSession, as_int, as_list, principal
from app.models import Finding, FindingType

MODULE = "enumeration.delegation"

UAC_ACCOUNTDISABLE = 0x0002
UAC_WORKSTATION_TRUST = 0x1000
UAC_SERVER_TRUST = 0x2000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000

# Property GUID of msDS-AllowedToActOnBehalfOfOtherIdentity.
RBCD_PROPERTY_GUID = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"

GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x40000000
WRITE_DACL = 0x00040000
WRITE_OWNER = 0x00080000
ADS_RIGHT_DS_WRITE_PROP = 0x00000020
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100

PRIVILEGED_GROUPS = (
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
)

# Principals treated as administrators when judging RBCD ACLs.
_ADMIN_RID = {"512", "516", "518", "519", "544", "526", "527"}
_ADMIN_SIDS = {
    "S-1-5-18",  # Local System
    "S-1-5-32-544",  # Administrators
    "S-1-5-32-548",  # Account Operators — still privileged; skip as "low priv"
    "S-1-5-32-549",
    "S-1-5-32-550",
    "S-1-5-32-551",
}


def _is_dc(uac: int) -> bool:
    return bool(uac & UAC_SERVER_TRUST)


def _sam(row: dict) -> str:
    return str(row.get("sAMAccountName") or "")


def _sid_is_admin(sid: str) -> bool:
    if sid in _ADMIN_SIDS:
        return True
    rid = sid.rsplit("-", 1)[-1]
    return rid in _ADMIN_RID


def _parse_rbcd_writers(sd_value, domain_sid: Optional[str]) -> List[str]:
    """Return low-privilege SIDs that can write RBCD on this object."""
    if not sd_value:
        return []
    try:
        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
    except Exception:
        return []

    raw = sd_value
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="ignore")
    try:
        sd = SR_SECURITY_DESCRIPTOR(data=bytes(raw))
    except Exception:
        return []

    writers: List[str] = []
    dacl = sd["Dacl"]
    if dacl is None:
        return []
    for ace in dacl["Data"]:
        try:
            mask = int(ace["Ace"]["Mask"]["Mask"])
            sid = ace["Ace"]["Sid"].formatCanonical()
        except Exception:
            continue
        if _sid_is_admin(sid):
            continue
        dangerous = bool(
            mask
            & (GENERIC_ALL | GENERIC_WRITE | WRITE_DACL | WRITE_OWNER | ADS_RIGHT_DS_WRITE_PROP)
        )
        if not dangerous:
            continue
        writers.append(sid)
    return writers


def _resolve_sid_names(session: LdapSession, sids: List[str]) -> List[str]:
    names: List[str] = []
    for sid in sids:
        rows = session.search(
            f"(objectSid={sid})",
            ["sAMAccountName", "name"],
        )
        if rows:
            names.append(str(rows[0].get("sAMAccountName") or rows[0].get("name") or sid))
        else:
            names.append(sid)
    return names


def _group_members(session: LdapSession, group_cn: str) -> List[dict]:
    groups = session.search(
        f"(&(objectClass=group)(sAMAccountName={group_cn}))",
        ["member", "sAMAccountName"],
    )
    if not groups:
        return []
    members = []
    for dn in as_list(groups[0].get("member")):
        row = session.get_by_dn(
            str(dn),
            ["sAMAccountName", "objectClass", "userAccountControl", "objectSid"],
        )
        if row:
            members.append(row)
    return members


def enumerate(session: LdapSession) -> List[Finding]:
    findings: List[Finding] = []
    domain = session.domain

    rows = session.search(
        "(|(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        "(msDS-AllowedToDelegateTo=*)"
        "(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
        [
            "sAMAccountName",
            "userAccountControl",
            "msDS-AllowedToDelegateTo",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
            "dNSHostName",
        ],
        with_sd=False,
    )

    seen_unconstrained: Set[str] = set()
    for row in rows:
        sam = _sam(row)
        if not sam:
            continue
        uac = as_int(row.get("userAccountControl"))
        target = principal(sam, domain)

        if (uac & UAC_TRUSTED_FOR_DELEGATION) and not _is_dc(uac):
            if sam not in seen_unconstrained:
                seen_unconstrained.add(sam)
                findings.append(
                    Finding(
                        finding_type=FindingType.UNCONSTRAINED_DELEGATION,
                        title="Cuenta o equipo con delegación no restringida",
                        target=target,
                        detail=(
                            f"'{sam}' tiene TRUSTED_FOR_DELEGATION. Puede almacenar el TGT "
                            f"de cualquier usuario que se autentique contra él, incluidos "
                            f"administradores de dominio. Los DC se omiten (es el comportamiento esperado)."
                        ),
                        evidence=f"sAMAccountName={sam} userAccountControl=0x{uac:x}",
                        source_module=MODULE,
                        is_sample=False,
                    )
                )

        spns = [str(s) for s in as_list(row.get("msDS-AllowedToDelegateTo"))]
        protocol_transition = bool(uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)
        if spns:
            findings.append(
                Finding(
                    finding_type=FindingType.CONSTRAINED_RBCD_DELEGATION,
                    title="Delegación restringida configurada",
                    target=target,
                    detail=(
                        f"'{sam}' tiene msDS-AllowedToDelegateTo = {', '.join(spns)}"
                        + (
                            " y TRUSTED_TO_AUTH_FOR_DELEGATION (transición de protocolo / S4U2Self)."
                            if protocol_transition
                            else "."
                        )
                    ),
                    evidence=(
                        f"sAMAccountName={sam} msDS-AllowedToDelegateTo={spns} "
                        f"userAccountControl=0x{uac:x}"
                    ),
                    source_module=MODULE,
                    subtype="constrained",
                    is_sample=False,
                )
            )

        if row.get("msDS-AllowedToActOnBehalfOfOtherIdentity"):
            findings.append(
                Finding(
                    finding_type=FindingType.CONSTRAINED_RBCD_DELEGATION,
                    title="RBCD configurado (msDS-AllowedToActOnBehalfOfOtherIdentity)",
                    target=target,
                    detail=(
                        f"'{sam}' tiene msDS-AllowedToActOnBehalfOfOtherIdentity. "
                        f"Otro principal puede obtener un ticket de servicio en nombre "
                        f"de cualquier usuario hacia este recurso."
                    ),
                    evidence=f"sAMAccountName={sam} msDS-AllowedToActOnBehalfOfOtherIdentity=present",
                    source_module=MODULE,
                    subtype="rbcd",
                    is_sample=False,
                )
            )

    # ACL check: computers writable by non-admin principals (RBCD path).
    computers = session.search(
        "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName", "nTSecurityDescriptor", "objectSid"],
        with_sd=True,
    )
    for row in computers:
        sam = _sam(row)
        writers = _parse_rbcd_writers(row.get("nTSecurityDescriptor"), None)
        if not writers:
            continue
        # Filter well-known self / creator-owner noise.
        interesting = [
            s
            for s in writers
            if s
            not in {
                "S-1-3-0",  # Creator Owner
                "S-1-5-10",  # Principal Self
            }
        ]
        if not interesting:
            continue
        names = _resolve_sid_names(session, interesting[:8])
        findings.append(
            Finding(
                finding_type=FindingType.CONSTRAINED_RBCD_DELEGATION,
                title="ACL que permite escribir RBCD",
                target=principal(sam, domain),
                detail=(
                    f"El objeto '{sam}' concede GenericAll, GenericWrite o WriteProperty "
                    f"a principales que no son administradores de dominio "
                    f"({', '.join(names)}). Eso habilita una ruta de escalada vía RBCD."
                ),
                evidence=f"sAMAccountName={sam} writers={names}",
                source_module=MODULE,
                subtype="rbcd_writable",
                is_sample=False,
            )
        )

    for group_name in PRIVILEGED_GROUPS:
        members = _group_members(session, group_name)
        extra = []
        for m in members:
            sam = _sam(m)
            if not sam:
                continue
            # Built-in Administrator (RID 500) is expected.
            sid = str(m.get("objectSid") or "")
            if sid.endswith("-500") or sam.lower() == "administrator":
                continue
            extra.append(sam)
        if extra:
            findings.append(
                Finding(
                    finding_type=FindingType.EXCESSIVE_PRIVILEGES,
                    title=f"Miembros adicionales en {group_name}",
                    target=f"Group: {group_name}",
                    detail=(
                        f"El grupo '{group_name}' incluye, además de la cuenta "
                        f"Administrador integrada, {len(extra)} principal(es): "
                        f"{', '.join(extra)}. Amplía la superficie de privilegio "
                        f"máximo del dominio."
                    ),
                    evidence=f"group={group_name} extra_members={extra}",
                    source_module=MODULE,
                    is_sample=False,
                )
            )

    return findings
