"""
Read-only ACL review on the domain object.

Looks for replication rights (DCSync) and GenericAll / WriteDacl granted to a
principal that is not a built-in administrator or domain controller identity.
Does not change the DACL.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from app.enumeration.ldap_client import LdapSession
from app.models import Finding, FindingType

MODULE = "enumeration.acl"

GENERIC_ALL = 0x10000000
WRITE_DACL = 0x00040000
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100

GUID_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

_ADMIN_RID = {"498", "500", "512", "516", "518", "519", "521", "544", "548", "549", "550", "551"}
_IGNORE_SID = {
    "S-1-5-9",
    "S-1-5-10",
    "S-1-5-11",
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-3-0",
}


def _ignored(sid: str) -> bool:
    if sid in _IGNORE_SID:
        return True
    rid = sid.rsplit("-", 1)[-1]
    return rid in _ADMIN_RID


def classify_ace(sid: str, mask: int, object_guid: Optional[str]) -> Optional[str]:
    """Return a path kind, or None when the ACE is not an audit finding."""
    if not sid or _ignored(sid):
        return None
    if mask & GENERIC_ALL:
        return "generic_all"
    if mask & WRITE_DACL:
        return "write_dacl"
    guid = (object_guid or "").strip("{}").lower()
    if mask & ADS_RIGHT_DS_CONTROL_ACCESS and guid == GUID_GET_CHANGES_ALL:
        return "get_changes_all"
    if mask & ADS_RIGHT_DS_CONTROL_ACCESS and guid == GUID_GET_CHANGES:
        return "get_changes"
    return None


def _iter_aces(sd_value) -> List[Tuple[str, int, Optional[str]]]:
    if not sd_value:
        return []
    try:
        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
    except Exception:
        return []
    raw = sd_value[0] if isinstance(sd_value, list) and sd_value else sd_value
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="ignore")
    try:
        sd = SR_SECURITY_DESCRIPTOR(data=bytes(raw))
    except Exception:
        return []
    dacl = sd["Dacl"]
    if dacl is None:
        return []
    out: List[Tuple[str, int, Optional[str]]] = []
    for ace in dacl["Data"]:
        try:
            mask = int(ace["Ace"]["Mask"]["Mask"])
            sid = ace["Ace"]["Sid"].formatCanonical()
        except Exception:
            continue
        guid = None
        try:
            object_type = ace["Ace"]["ObjectType"]
            if object_type:
                guid = str(object_type)
        except Exception:
            guid = None
        out.append((sid, mask, guid))
    return out


def enumerate(session: LdapSession) -> List[Finding]:
    rows = session.search(
        "(objectClass=domain)",
        ["nTSecurityDescriptor", "objectSid"],
        search_base=session.base_dn,
        with_sd=True,
    )
    if not rows:
        return []
    kinds: dict[str, set[str]] = {}
    for sid, mask, guid in _iter_aces(rows[0].get("nTSecurityDescriptor")):
        kind = classify_ace(sid, mask, guid)
        if kind:
            kinds.setdefault(sid, set()).add(kind)

    findings: List[Finding] = []
    for sid, flags in sorted(kinds.items()):
        dcsync = "get_changes" in flags and "get_changes_all" in flags
        broad = "generic_all" in flags or "write_dacl" in flags
        if not dcsync and not broad:
            continue
        label = "replicación de directorio" if dcsync else "control total del dominio"
        findings.append(
            Finding(
                finding_type=FindingType.ACL_CONTROL_PATH,
                title=f"ACL de dominio con {label}",
                target=session.domain,
                detail=(
                    f"El descriptor del dominio concede a {sid} "
                    f"{label} ({', '.join(sorted(flags))}). "
                    f"Es una ruta de control observada en la DACL, no un ataque ejecutado."
                ),
                evidence=f"sid={sid} flags={sorted(flags)}",
                source_module=MODULE,
                subtype="dcsync" if dcsync else "domain_control",
            )
        )
    return findings
