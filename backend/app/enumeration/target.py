"""
Audit target: connection parameters for a live enumeration.

Holds domain, DC and credentials only in memory for the duration of the
request. Never serialised to disk.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Optional

from app.models import AuditRequest

EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"


class AuditConnectionError(Exception):
    """Raised when the domain controller cannot be reached or bind fails."""


@dataclass
class AuditTarget:
    domain: str
    dc_host: str
    username: str
    password: Optional[str]
    nthash: Optional[str]
    ldap_scheme: str = "ldap"
    ldap_port: int = 389

    @property
    def netbios(self) -> str:
        return self.domain.split(".")[0].upper()

    @property
    def ntlm_username(self) -> str:
        user = self.username
        if "\\" in user:
            return user
        if "@" in user:
            user = user.split("@", 1)[0]
        return f"{self.netbios}\\{user}"

    @property
    def sam(self) -> str:
        user = self.username
        if "\\" in user:
            return user.split("\\", 1)[1]
        if "@" in user:
            return user.split("@", 1)[0]
        return user

    @property
    def ldap_password(self) -> str:
        """Password string accepted by ldap3 NTLM (cleartext or LM:NT hash)."""
        if self.nthash:
            return f"{EMPTY_LM_HASH}:{self.nthash}"
        return self.password or ""

    @property
    def impacket_hashes(self) -> tuple[str, str]:
        if self.nthash:
            return EMPTY_LM_HASH, self.nthash
        return "", ""

    def resolved_dc_ip(self) -> str:
        try:
            return socket.gethostbyname(self.dc_host)
        except OSError:
            return self.dc_host

    def principal(self) -> str:
        return f"{self.sam}@{self.domain}"

    @classmethod
    def from_request(cls, req: AuditRequest) -> "AuditTarget":
        return cls(
            domain=req.domain.lower(),
            dc_host=req.dc_host,
            username=req.username,
            password=req.password,
            nthash=req.nthash,
        )
