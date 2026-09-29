"""
SMB signing enumeration via impacket.

Read-only negotiate/session setup. Does not relay or execute commands.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Set, Tuple

from app.enumeration.ldap_client import LdapSession, as_list
from app.enumeration.target import AuditTarget
from app.models import Finding, FindingType

MODULE = "enumeration.smb"

# Cap so a large domain does not block the API for tens of minutes.
MAX_EXTRA_HOSTS = 48
HOST_TIMEOUT = 4


def _login(conn, target: AuditTarget) -> None:
    lmhash, nthash = target.impacket_hashes
    domain = target.domain
    user = target.sam
    if nthash:
        conn.login(user, "", domain=domain, lmhash=lmhash, nthash=nthash)
    else:
        conn.login(user, target.password or "", domain=domain)


def _signing_required(host: str, target: AuditTarget) -> Optional[bool]:
    """Return True if SMB signing is required, False if not, None if unreachable."""
    try:
        from impacket.smbconnection import SMBConnection
    except Exception:
        return None

    conn = None
    try:
        conn = SMBConnection(host, host, sess_port=445, timeout=HOST_TIMEOUT)
        try:
            _login(conn, target)
        except Exception:
            # Negotiate may have completed even if auth failed.
            pass
        if hasattr(conn, "isSigningRequired"):
            return bool(conn.isSigningRequired())
        server = conn.getSMBServer()
        if hasattr(server, "_SignatureRequired"):
            return bool(server._SignatureRequired)
        connection = getattr(server, "_Connection", None)
        if isinstance(connection, dict) and "RequireSigning" in connection:
            return bool(connection["RequireSigning"])
    except Exception:
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
    return None


def _probe(host: str, target: AuditTarget) -> Optional[Tuple[str, bool]]:
    required = _signing_required(host, target)
    if required is None:
        return None
    return host, required


def _hosts_from_ldap(session: LdapSession, dc_host: str) -> List[str]:
    hosts: List[str] = []
    rows = session.search(
        "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["dNSHostName", "sAMAccountName"],
    )
    dc_l = dc_host.lower()
    for row in rows:
        dns = row.get("dNSHostName")
        if not dns:
            continue
        name = str(dns).rstrip(".")
        if name.lower() == dc_l:
            continue
        hosts.append(name)
        if len(hosts) >= MAX_EXTRA_HOSTS:
            break
    return hosts


def enumerate(target: AuditTarget, session: Optional[LdapSession] = None) -> List[Finding]:
    findings: List[Finding] = []
    seen: Set[str] = set()
    jobs: List[str] = []

    def add_host(host: str) -> None:
        key = host.strip().rstrip(".").lower()
        if key and key not in seen:
            seen.add(key)
            jobs.append(host.strip().rstrip("."))

    add_host(target.dc_host)
    if session is not None:
        for host in _hosts_from_ldap(session, target.dc_host):
            add_host(host)

    results: List[Tuple[str, bool]] = []
    workers = min(8, max(1, len(jobs)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_probe, host, target): host for host in jobs}
        for fut in as_completed(futs):
            item = fut.result()
            if item is not None:
                results.append(item)

    for host, required in results:
        if required:
            continue
        findings.append(
            Finding(
                finding_type=FindingType.SMB_SIGNING_DISABLED,
                title="SMB signing no requerido",
                target=host,
                detail=(
                    f"El host {host} no exige firma SMB. Es susceptible de NTLM relay "
                    f"y de manipulación de tráfico en tránsito."
                ),
                evidence="SMB RequireSigning=False",
                source_module=MODULE,
                subtype="not_required",
                is_sample=False,
            )
        )
    return findings
