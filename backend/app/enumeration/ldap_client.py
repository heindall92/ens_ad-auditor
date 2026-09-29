"""
LDAP session helper (ldap3, NTLM). Used by Kerberos and delegation modules.

Bind credentials stay on this object only for the request lifetime.
"""
from __future__ import annotations

from typing import Any, Iterable, List, Optional

from ldap3 import ALL, BASE, Connection, NTLM, SUBTREE, Server
from ldap3.core.exceptions import LDAPException
from ldap3.protocol.microsoft import security_descriptor_control

from app.enumeration.target import AuditConnectionError, AuditTarget

# Owner + Group + DACL. Needed to read nTSecurityDescriptor.
_SD_CONTROL = security_descriptor_control(sdflags=0x07)


class LdapSession:
    def __init__(
        self,
        target: AuditTarget,
        connection: Connection,
        base_dn: str,
        schema_dn: Optional[str] = None,
        config_dn: Optional[str] = None,
        tls: bool = False,
    ):
        self.target = target
        self.connection = connection
        self.base_dn = base_dn
        self.schema_dn = schema_dn
        self.config_dn = config_dn
        self.tls = tls

    @property
    def domain(self) -> str:
        return self.target.domain

    def search(
        self,
        ldap_filter: str,
        attributes: Iterable[str],
        search_base: Optional[str] = None,
        with_sd: bool = False,
    ) -> List[dict]:
        kwargs = {}
        if with_sd:
            kwargs["controls"] = _SD_CONTROL
        try:
            entries = self.connection.extend.standard.paged_search(
                search_base=search_base or self.base_dn,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=list(attributes),
                paged_size=400,
                generator=False,
                **kwargs,
            )
        except LDAPException as exc:
            raise AuditConnectionError(f"Búsqueda LDAP fallida: {exc}") from exc

        return _entries_to_dicts(entries)

    def get_by_dn(self, dn: str, attributes: Iterable[str]) -> Optional[dict]:
        try:
            ok = self.connection.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=list(attributes),
            )
        except LDAPException:
            return None
        if not ok or not self.connection.response:
            return None
        parsed = _entries_to_dicts(self.connection.response)
        return parsed[0] if parsed else None

    def close(self) -> None:
        try:
            if self.connection.bound:
                self.connection.unbind()
        except Exception:
            pass


def _try_bind(target: AuditTarget, use_ssl: bool, port: int) -> LdapSession:
    server = Server(
        target.dc_host,
        port=port,
        use_ssl=use_ssl,
        get_info=ALL,
        connect_timeout=8,
    )
    conn = Connection(
        server,
        user=target.ntlm_username,
        password=target.ldap_password,
        authentication=NTLM,
        auto_bind=True,
        raise_exceptions=True,
        receive_timeout=20,
    )
    base_dn = None
    schema_dn = None
    config_dn = None
    if server.info is not None:
        other = server.info.other or {}
        defaults = other.get("defaultNamingContext") or []
        if defaults:
            base_dn = defaults[0]
        schemas = other.get("schemaNamingContext") or []
        if schemas:
            schema_dn = schemas[0]
        configs = other.get("configurationNamingContext") or []
        if configs:
            config_dn = configs[0]
    if not base_dn:
        base_dn = ",".join(f"DC={p}" for p in target.domain.split("."))
    target.ldap_scheme = "ldaps" if use_ssl else "ldap"
    target.ldap_port = port
    return LdapSession(
        target,
        conn,
        base_dn,
        schema_dn=schema_dn,
        config_dn=config_dn,
        tls=use_ssl,
    )


def bind(target: AuditTarget) -> LdapSession:
    """Bind with NTLM. Try LDAP then LDAPS. Raises AuditConnectionError."""
    attempts = (
        (False, 389),
        (True, 636),
    )
    last_error: Optional[BaseException] = None
    for use_ssl, port in attempts:
        try:
            return _try_bind(target, use_ssl=use_ssl, port=port)
        except Exception as exc:
            last_error = exc
    raise AuditConnectionError(
        f"No se pudo enlazar con {target.dc_host} como {target.ntlm_username}: "
        f"{last_error}"
    )


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [v for v in value if v is not None]
    return [value]


def as_int(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def principal(sam: str, domain: str) -> str:
    return f"{sam}@{domain}"


def _entries_to_dicts(entries: Optional[Iterable[dict]]) -> List[dict]:
    out: List[dict] = []
    for raw in entries or []:
        if not isinstance(raw, dict):
            continue
        if raw.get("type") and raw.get("type") != "searchResEntry":
            continue
        attrs = dict(raw.get("attributes") or {})
        attrs["dn"] = raw.get("dn") or attrs.get("distinguishedName")
        out.append(attrs)
    return out
