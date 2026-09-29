"""
Read-only domain policy and hygiene checks.

Password / lockout policy, krbtgt age, Protected Users, admin SPNs, stale
privileged accounts, LDAP signing / channel binding when the DC exposes them,
trusts, LAPS schema presence, machine account quota.

Does not read LAPS passwords, does not change objects, does not attack trusts.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

from app.enumeration.ldap_client import LdapSession, as_int, as_list, principal
from app.models import Finding, FindingType

MODULE = "enumeration.policy"

PRIVILEGED_GROUPS = ("Domain Admins", "Enterprise Admins", "Schema Admins")
KRBTGT_MAX_AGE_DAYS = 180
STALE_DAYS = 90
MIN_PWD_LENGTH = 12
MIN_PWD_HISTORY = 5
MAX_PWD_AGE_DAYS = 365
DOMAIN_PASSWORD_COMPLEX = 0x1

TRUST_ATTR_QUARANTINED = 0x4
TRUST_ATTR_FOREST_TRANSITIVE = 0x8
TRUST_ATTR_CROSS_ORG = 0x10
TRUST_DIRECTION_INBOUND = 1
TRUST_DIRECTION_OUTBOUND = 2
TRUST_DIRECTION_BIDI = 3
TRUST_TYPE_DOWNLEVEL = 1
TRUST_TYPE_UPLEVEL = 2
TRUST_TYPE_MIT = 3


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    return None


def _age_days(value: Any) -> Optional[float]:
    dt = _as_datetime(value)
    if dt is None:
        return None
    return (_now() - dt).total_seconds() / 86400.0


def _span_days(value: Any) -> Optional[float]:
    """Convert maxPwdAge / lockoutDuration (timedelta or FILETIME) to days."""
    if value is None:
        return None
    if isinstance(value, timedelta):
        return abs(value.total_seconds()) / 86400.0
    if isinstance(value, datetime):
        return None
    try:
        raw = int(value)
    except (TypeError, ValueError):
        return None
    if raw == 0:
        return 0.0
    # AD stores negative 100-ns intervals.
    return abs(raw) / 10_000_000.0 / 86400.0


def _sam(row: dict) -> str:
    return str(row.get("sAMAccountName") or "")


def _group_members(session: LdapSession, name: str) -> List[dict]:
    groups = session.search(
        f"(&(objectClass=group)(sAMAccountName={name}))",
        ["member", "sAMAccountName"],
    )
    if not groups:
        return []
    members: List[dict] = []
    for dn in as_list(groups[0].get("member")):
        row = session.get_by_dn(
            str(dn),
            [
                "sAMAccountName",
                "objectClass",
                "userAccountControl",
                "objectSid",
                "servicePrincipalName",
                "lastLogonTimestamp",
                "adminCount",
            ],
        )
        if row:
            members.append(row)
    return members


def _is_user_account(row: dict) -> bool:
    classes = {str(c).lower() for c in as_list(row.get("objectClass"))}
    sam = _sam(row)
    if sam.endswith("$"):
        return False
    return "user" in classes and "computer" not in classes


def enumerate(session: LdapSession) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(_password_and_lockout(session))
    findings.extend(_machine_quota(session))
    findings.extend(_krbtgt(session))
    findings.extend(_protected_users(session))
    findings.extend(_admin_spn(session))
    findings.extend(_stale_privileged(session))
    findings.extend(_ldap_channel(session))
    findings.extend(_trusts(session))
    findings.extend(_laps(session))
    return findings


def _password_and_lockout(session: LdapSession) -> List[Finding]:
    domain = session.get_by_dn(
        session.base_dn,
        [
            "minPwdLength",
            "maxPwdAge",
            "pwdHistoryLength",
            "pwdProperties",
            "lockoutThreshold",
            "lockoutDuration",
            "ms-DS-MachineAccountQuota",
        ],
    )
    if not domain:
        return []
    out: List[Finding] = []
    min_len = as_int(domain.get("minPwdLength"), default=-1)
    history = as_int(domain.get("pwdHistoryLength"), default=-1)
    max_age = _span_days(domain.get("maxPwdAge"))
    pwd_props = domain.get("pwdProperties")
    pwd_issues = []
    if min_len >= 0 and min_len < MIN_PWD_LENGTH:
        pwd_issues.append(f"minPwdLength={min_len} (< {MIN_PWD_LENGTH})")
    if history >= 0 and history < MIN_PWD_HISTORY:
        pwd_issues.append(f"pwdHistoryLength={history} (< {MIN_PWD_HISTORY})")
    if max_age is not None and (max_age == 0 or max_age > MAX_PWD_AGE_DAYS):
        label = "no caduca" if max_age == 0 else f"{max_age:.0f} días"
        pwd_issues.append(f"maxPwdAge={label}")
    if pwd_props is not None:
        flags = as_int(pwd_props)
        if flags & DOMAIN_PASSWORD_COMPLEX == 0:
            pwd_issues.append(f"pwdProperties={flags} (sin complejidad)")
    if pwd_issues:
        out.append(
            Finding(
                finding_type=FindingType.WEAK_PASSWORD_POLICY,
                title="Política de contraseñas del dominio débil",
                target=session.domain,
                detail=(
                    "La política de dominio no cumple un umbral mínimo de auditoría: "
                    + "; ".join(pwd_issues)
                    + "."
                ),
                evidence="; ".join(pwd_issues),
                source_module=MODULE,
                subtype="domain_policy",
            )
        )

    threshold = domain.get("lockoutThreshold")
    if threshold is not None and as_int(threshold) == 0:
        out.append(
            Finding(
                finding_type=FindingType.WEAK_LOCKOUT_POLICY,
                title="Bloqueo de cuenta deshabilitado",
                target=session.domain,
                detail=(
                    "lockoutThreshold=0: el dominio no bloquea cuentas tras fallos "
                    "de autenticación."
                ),
                evidence="lockoutThreshold=0",
                source_module=MODULE,
                subtype="no_lockout",
            )
        )
    return out


def _machine_quota(session: LdapSession) -> List[Finding]:
    domain = session.get_by_dn(session.base_dn, ["ms-DS-MachineAccountQuota"])
    if not domain or domain.get("ms-DS-MachineAccountQuota") is None:
        return []
    quota = as_int(domain.get("ms-DS-MachineAccountQuota"))
    if quota <= 0:
        return []
    return [
        Finding(
            finding_type=FindingType.MACHINE_ACCOUNT_QUOTA,
            title="Cuota de cuentas de equipo mayor que cero",
            target=session.domain,
            detail=(
                f"ms-DS-MachineAccountQuota={quota}. Un usuario autenticado puede "
                f"unir hasta {quota} equipo(s) al dominio sin delegación expresa."
            ),
            evidence=f"ms-DS-MachineAccountQuota={quota}",
            source_module=MODULE,
            subtype="quota",
        )
    ]


def _krbtgt(session: LdapSession) -> List[Finding]:
    rows = session.search(
        "(&(objectClass=user)(sAMAccountName=krbtgt))",
        ["sAMAccountName", "pwdLastSet"],
    )
    if not rows:
        return []
    age = _age_days(rows[0].get("pwdLastSet"))
    if age is None or age <= KRBTGT_MAX_AGE_DAYS:
        return []
    return [
        Finding(
            finding_type=FindingType.KRBTGT_PASSWORD_AGE,
            title="Contraseña de krbtgt sin rotar",
            target=principal("krbtgt", session.domain),
            detail=(
                f"pwdLastSet de krbtgt tiene {age:.0f} días "
                f"(umbral de auditoría {KRBTGT_MAX_AGE_DAYS} días)."
            ),
            evidence=f"pwdLastSet_age_days={age:.0f}",
            source_module=MODULE,
            subtype="age",
        )
    ]


def _protected_users(session: LdapSession) -> List[Finding]:
    pu = session.search(
        "(&(objectClass=group)(sAMAccountName=Protected Users))",
        ["member", "sAMAccountName"],
    )
    if not pu:
        return []
    pu_dns = {str(dn) for dn in as_list(pu[0].get("member"))}
    pu_sams = set()
    for dn in pu_dns:
        row = session.get_by_dn(dn, ["sAMAccountName"])
        if row and _sam(row):
            pu_sams.add(_sam(row).lower())

    missing: List[str] = []
    for group in PRIVILEGED_GROUPS:
        for member in _group_members(session, group):
            if not _is_user_account(member):
                continue
            sam = _sam(member)
            if sam.lower() in {"krbtgt", "administrator"}:
                continue
            if sam.lower() not in pu_sams:
                missing.append(f"{sam} ({group})")
    if not missing:
        return []
    return [
        Finding(
            finding_type=FindingType.PROTECTED_USERS_GAP,
            title="Cuentas privilegiadas fuera de Protected Users",
            target="Group: Protected Users",
            detail=(
                "Cuentas de usuario en grupos privilegiados que no están en "
                "Protected Users: " + ", ".join(missing) + "."
            ),
            evidence=f"missing={missing}",
            source_module=MODULE,
            subtype="gap",
        )
    ]


def _admin_spn(session: LdapSession) -> List[Finding]:
    rows = session.search(
        "(&(objectCategory=person)(objectClass=user)(adminCount=1)(servicePrincipalName=*)"
        "(!(sAMAccountName=krbtgt))"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName", "servicePrincipalName", "adminCount"],
    )
    findings: List[Finding] = []
    for row in rows:
        sam = _sam(row)
        if not sam or sam.endswith("$"):
            continue
        spns = [str(s) for s in as_list(row.get("servicePrincipalName"))]
        if not spns:
            continue
        findings.append(
            Finding(
                finding_type=FindingType.ADMIN_WITH_SPN,
                title="Cuenta privilegiada con SPN",
                target=principal(sam, session.domain),
                detail=(
                    f"'{sam}' tiene adminCount=1 y SPN ({', '.join(spns)}): "
                    f"es kerberoasteable con privilegio."
                ),
                evidence=f"sAMAccountName={sam} adminCount=1 servicePrincipalName={spns}",
                source_module=MODULE,
                subtype="admin_spn",
            )
        )
    return findings


def _stale_privileged(session: LdapSession) -> List[Finding]:
    stale: List[str] = []
    for group in PRIVILEGED_GROUPS:
        for member in _group_members(session, group):
            if not _is_user_account(member):
                continue
            sam = _sam(member)
            if sam.lower() == "krbtgt":
                continue
            age = _age_days(member.get("lastLogonTimestamp"))
            if age is None:
                stale.append(f"{sam} ({group}, sin lastLogonTimestamp)")
            elif age > STALE_DAYS:
                stale.append(f"{sam} ({group}, {age:.0f} días)")
    if not stale:
        return []
    return [
        Finding(
            finding_type=FindingType.STALE_PRIVILEGED_ACCOUNT,
            title="Cuentas privilegiadas inactivas",
            target="privileged groups",
            detail=(
                f"Cuentas privilegiadas sin inicio de sesión en {STALE_DAYS} días "
                f"o sin lastLogonTimestamp: " + ", ".join(stale) + "."
            ),
            evidence=f"stale={stale}",
            source_module=MODULE,
            subtype="stale",
        )
    ]


def _ldap_channel(session: LdapSession) -> List[Finding]:
    out: List[Finding] = []
    if not session.tls:
        out.append(
            Finding(
                finding_type=FindingType.LDAP_SIGNING_NOT_REQUIRED,
                title="LDAP sin firma ni TLS aceptado",
                target=session.target.dc_host,
                detail=(
                    f"El enlace a {session.target.dc_host} se completó por LDAP "
                    f"sin TLS (puerto {session.target.ldap_port}) y sin exigir firma. "
                    f"El DC no forzó un canal íntegro para esta sesión."
                ),
                evidence=f"scheme=ldap port={session.target.ldap_port} tls=false",
                source_module=MODULE,
                subtype="unsigned",
            )
        )
        out.append(
            Finding(
                finding_type=FindingType.LDAP_CHANNEL_BINDING_WEAK,
                title="Channel binding LDAP no aplicable (sin TLS)",
                target=session.target.dc_host,
                detail=(
                    "La sesión LDAP no usa TLS, así que channel binding no se "
                    "exigió. Un relay NTLM contra LDAP es viable si el DC acepta "
                    "este canal."
                ),
                evidence="tls=false ldapEnforceChannelBinding=not_enforced_on_session",
                source_module=MODULE,
                subtype="no_tls",
            )
        )
        return out

    dcs = session.search(
        "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        ["sAMAccountName", "dNSHostName", "msDS-LdapEnforceChannelBinding"],
    )
    for row in dcs:
        flag = row.get("msDS-LdapEnforceChannelBinding")
        if flag is None:
            continue
        value = as_int(flag, default=-1)
        if value >= 2:
            continue
        sam = _sam(row)
        out.append(
            Finding(
                finding_type=FindingType.LDAP_CHANNEL_BINDING_WEAK,
                title="Channel binding LDAP no está en Always",
                target=principal(sam, session.domain),
                detail=(
                    f"msDS-LdapEnforceChannelBinding={value} en '{sam}' "
                    f"(0=never, 1=when supported, 2=always)."
                ),
                evidence=f"sAMAccountName={sam} msDS-LdapEnforceChannelBinding={value}",
                source_module=MODULE,
                subtype="binding",
            )
        )
    return out


def _trusts(session: LdapSession) -> List[Finding]:
    rows = session.search(
        "(objectClass=trustedDomain)",
        ["name", "flatName", "trustDirection", "trustAttributes", "trustType"],
        search_base=f"CN=System,{session.base_dn}",
    )
    findings: List[Finding] = []
    for row in rows:
        name = str(row.get("name") or row.get("flatName") or "")
        if not name:
            continue
        attrs = as_int(row.get("trustAttributes"))
        direction = as_int(row.get("trustDirection"))
        ttype = as_int(row.get("trustType"))
        quarantined = bool(attrs & TRUST_ATTR_QUARANTINED)
        forest = bool(attrs & TRUST_ATTR_FOREST_TRANSITIVE)
        externalish = (not forest) and ttype in {TRUST_TYPE_UPLEVEL, TRUST_TYPE_DOWNLEVEL}
        if externalish and not quarantined and direction in {
            TRUST_DIRECTION_OUTBOUND,
            TRUST_DIRECTION_BIDI,
        }:
            findings.append(
                Finding(
                    finding_type=FindingType.TRUST_SID_FILTERING,
                    title="Trust sin SID filtering",
                    target=name,
                    detail=(
                        f"El trust '{name}' (dirección={direction}, "
                        f"trustAttributes=0x{attrs:x}) no tiene "
                        f"TRUST_ATTRIBUTE_QUARANTINED_DOMAIN. SID history desde "
                        f"el dominio de confianza no está filtrado."
                    ),
                    evidence=(
                        f"name={name} trustDirection={direction} "
                        f"trustAttributes=0x{attrs:x} trustType={ttype}"
                    ),
                    source_module=MODULE,
                    subtype="no_quarantine",
                )
            )
    return findings


def _laps(session: LdapSession) -> List[Finding]:
    if not session.schema_dn:
        return []
    schema_attrs = session.search(
        "(&(objectClass=attributeSchema)"
        "(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=msLAPS-Password)"
        "(lDAPDisplayName=msLAPS-PasswordExpirationTime)"
        "(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)))",
        ["lDAPDisplayName"],
        search_base=session.schema_dn,
    )
    names = {str(r.get("lDAPDisplayName") or "") for r in schema_attrs}
    if not names:
        return [
            Finding(
                finding_type=FindingType.LAPS_NOT_DEPLOYED,
                title="LAPS no está en el esquema",
                target=session.domain,
                detail=(
                    "No aparecen ms-Mcs-AdmPwd ni msLAPS-Password en el esquema. "
                    "Las contraseñas locales de administrador no se gestionan con LAPS."
                ),
                evidence="schema: no LAPS attributes",
                source_module=MODULE,
                subtype="no_schema",
            )
        ]

    exp_attr = None
    if "msLAPS-PasswordExpirationTime" in names:
        exp_attr = "msLAPS-PasswordExpirationTime"
    elif "ms-Mcs-AdmPwdExpirationTime" in names:
        exp_attr = "ms-Mcs-AdmPwdExpirationTime"
    if not exp_attr:
        return [
            Finding(
                finding_type=FindingType.LAPS_NOT_DEPLOYED,
                title="LAPS en esquema sin atributo de caducidad",
                target=session.domain,
                detail=f"Atributos LAPS vistos: {sorted(names)}. Falta el de caducidad.",
                evidence=f"schema={sorted(names)}",
                source_module=MODULE,
                subtype="no_expiry_attr",
            )
        ]

    computers = session.search(
        f"(&(objectClass=computer)({exp_attr}=*))",
        ["sAMAccountName", exp_attr],
    )
    if computers:
        return []
    return [
        Finding(
            finding_type=FindingType.LAPS_NOT_DEPLOYED,
            title="LAPS en esquema pero sin equipos con caducidad",
            target=session.domain,
            detail=(
                f"El esquema tiene {sorted(names)}, pero ningún equipo tiene "
                f"{exp_attr}. LAPS no está en uso observado."
            ),
            evidence=f"schema={sorted(names)} computers_with_{exp_attr}=0",
            source_module=MODULE,
            subtype="not_in_use",
        )
    ]
