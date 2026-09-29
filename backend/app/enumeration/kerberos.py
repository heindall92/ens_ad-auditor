"""
Kerberos enumeration (Kerberoasting candidates, AS-REP roasting).

Read-only LDAP queries. Does not request TGS/AS tickets or extract hashes.
"""
from __future__ import annotations

from typing import List

from app.enumeration.ldap_client import LdapSession, as_int, as_list, principal
from app.models import Finding, FindingType

MODULE = "enumeration.kerberos"

UAC_ACCOUNTDISABLE = 0x0002
UAC_NORMAL_ACCOUNT = 0x0200
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_WORKSTATION_TRUST = 0x1000
UAC_SERVER_TRUST = 0x2000
UAC_DONT_REQUIRE_PREAUTH = 0x400000

# msDS-SupportedEncryptionTypes bits (MS-KILE).
ETYPE_DES_CRC = 0x01
ETYPE_DES_MD5 = 0x02
ETYPE_RC4 = 0x04
ETYPE_AES128 = 0x08
ETYPE_AES256 = 0x10


def _is_computer(uac: int, sam: str) -> bool:
    if uac & (UAC_WORKSTATION_TRUST | UAC_SERVER_TRUST):
        return True
    return sam.endswith("$")


def _rc4_allowed(enc_types: int) -> bool:
    # Missing / zero: domain default historically includes RC4.
    if enc_types == 0:
        return True
    return bool(enc_types & ETYPE_RC4)


def enumerate(session: LdapSession) -> List[Finding]:
    findings: List[Finding] = []
    domain = session.domain

    rows = session.search(
        "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        [
            "sAMAccountName",
            "userAccountControl",
            "servicePrincipalName",
            "msDS-SupportedEncryptionTypes",
            "adminCount",
        ],
    )

    for row in rows:
        sam = row.get("sAMAccountName") or ""
        if not sam:
            continue
        uac = as_int(row.get("userAccountControl"))
        if _is_computer(uac, sam):
            continue
        spns = [str(s) for s in as_list(row.get("servicePrincipalName"))]
        enc = as_int(row.get("msDS-SupportedEncryptionTypes"))
        target = principal(sam, domain)

        if spns:
            rc4 = _rc4_allowed(enc)
            enc_label = f"0x{enc:x}" if enc else "no definido (por defecto incluye RC4)"
            findings.append(
                Finding(
                    finding_type=FindingType.KERBEROASTING,
                    title="Cuenta de servicio kerberoasteable"
                    + (" (RC4)" if rc4 else ""),
                    target=target,
                    detail=(
                        f"La cuenta '{sam}' tiene SPN ({', '.join(spns)})"
                        + (
                            " y admite cifrado RC4-HMAC (etype 23), lo que facilita "
                            "Kerberoasting."
                            if rc4
                            else ". Tiene SPN: un ticket TGS es solicitables y la "
                            "contraseña se puede atacar fuera de línea."
                        )
                    ),
                    evidence=(
                        f"sAMAccountName={sam} servicePrincipalName={spns} "
                        f"msDS-SupportedEncryptionTypes={enc_label} "
                        f"userAccountControl=0x{uac:x}"
                    ),
                    source_module=MODULE,
                    subtype="rc4" if rc4 else "aes",
                    is_sample=False,
                )
            )

        if uac & UAC_DONT_REQUIRE_PREAUTH:
            findings.append(
                Finding(
                    finding_type=FindingType.ASREP_ROASTING,
                    title="Cuenta sin pre-autenticación Kerberos",
                    target=target,
                    detail=(
                        f"La cuenta '{sam}' tiene DONT_REQUIRE_PREAUTH "
                        f"(userAccountControl & 0x400000). Un principal no autenticado "
                        f"puede pedir un AS-REP cifrado con la clave del usuario."
                    ),
                    evidence=f"sAMAccountName={sam} userAccountControl=0x{uac:x}",
                    source_module=MODULE,
                    subtype="dont_require_preauth",
                    is_sample=False,
                )
            )

    return findings
