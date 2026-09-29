"""
Core data models for ENS AD Auditor.

Finding      -> a raw technical finding produced by an enumeration module.
EnsControl   -> a reference to a specific ENS [op.acc] control.
GRCAlert     -> a technical Finding translated into an ENS GRC non-compliance.

All user-facing strings (descriptions, remediations, risk labels) are in
Spanish by design; code identifiers stay in English.

Credentials submitted at audit time live only in the request object; they are
never written to disk.
"""
from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class RiskLevel(str, Enum):
    """Risk rating using the Spanish labels expected by the ENS report."""

    CRITICO = "Critico"
    ALTO = "Alto"
    MEDIO = "Medio"
    BAJO = "Bajo"

    @property
    def order(self) -> int:
        """Numeric weight for sorting (higher = more severe)."""
        return {
            RiskLevel.CRITICO: 4,
            RiskLevel.ALTO: 3,
            RiskLevel.MEDIO: 2,
            RiskLevel.BAJO: 1,
        }[self]


class FindingType(str, Enum):
    """Canonical technical finding types recognised by the mapping engine."""

    SMB_SIGNING_DISABLED = "smb_signing_disabled"
    KERBEROASTING = "kerberoasting"
    ASREP_ROASTING = "asrep_roasting"
    UNCONSTRAINED_DELEGATION = "unconstrained_delegation"
    CONSTRAINED_RBCD_DELEGATION = "constrained_rbcd_delegation"
    EXCESSIVE_PRIVILEGES = "excessive_privileges"
    ADCS_ESC = "adcs_esc"
    WEAK_PASSWORD_POLICY = "weak_password_policy"
    WEAK_LOCKOUT_POLICY = "weak_lockout_policy"
    KRBTGT_PASSWORD_AGE = "krbtgt_password_age"
    PROTECTED_USERS_GAP = "protected_users_gap"
    ADMIN_WITH_SPN = "admin_with_spn"
    STALE_PRIVILEGED_ACCOUNT = "stale_privileged_account"
    LDAP_SIGNING_NOT_REQUIRED = "ldap_signing_not_required"
    LDAP_CHANNEL_BINDING_WEAK = "ldap_channel_binding_weak"
    TRUST_SID_FILTERING = "trust_sid_filtering"
    LAPS_NOT_DEPLOYED = "laps_not_deployed"
    MACHINE_ACCOUNT_QUOTA = "machine_account_quota"


class Finding(BaseModel):
    """A raw technical finding emitted by an enumeration module."""

    finding_type: FindingType
    title: str = Field(..., description="Short human-readable title (ES).")
    target: str = Field(..., description="Host, account, template or object affected.")
    detail: str = Field(..., description="Technical detail of what was observed (ES).")
    evidence: Optional[str] = Field(
        default=None, description="Optional raw evidence / tool output snippet."
    )
    source_module: str = Field(..., description="Enumeration module that produced it.")
    subtype: Optional[str] = Field(
        default=None,
        description="Optional variant key (e.g. 'ESC1', 'rc4', 'not_required') used by "
        "the mapping engine to select a more specific rule.",
    )
    is_sample: bool = Field(
        default=False,
        description=(
            "Always false on live findings. True is reserved for unit-test "
            "fixtures so the API can prove it never fabricates results."
        ),
    )


class EnsControl(BaseModel):
    """A reference to a specific ENS control (op.acc family)."""

    id: str = Field(..., description="ENS control id, e.g. 'op.acc.5'.")
    name: str = Field(..., description="Official-style control name (ES).")
    is_primary: bool = Field(
        default=True, description="Whether this is the primary mapped control."
    )


class GRCAlert(BaseModel):
    """A technical finding translated into an ENS GRC non-compliance alert."""

    rule_id: str = Field(..., description="Mapping rule applied, e.g. 'adcs_esc:ESC1'.")
    finding: Finding
    risk: RiskLevel
    ens_controls: List[EnsControl]
    non_compliance: str = Field(
        ..., description="Description of the ENS non-compliance (ES)."
    )
    remediation: str = Field(..., description="Concrete remediation guidance (ES).")
    references: List[str] = Field(
        default_factory=list, description="Extra references (other ENS dims, CIS, etc.)."
    )
    rationale: Optional[str] = Field(
        default=None, description="Why these ENS controls were chosen (ES, auditable)."
    )
    impact: int = Field(default=3, ge=1, le=5, description="MAGERIT impact 1-5.")
    likelihood: int = Field(
        default=3, ge=1, le=5, description="MAGERIT likelihood / frequency 1-5."
    )
    score: int = Field(default=9, description="impact × likelihood.")
    da_path: bool = Field(
        default=False,
        description="True when the observed weakness is a direct path to Domain Admin.",
    )

    @property
    def primary_control(self) -> Optional[EnsControl]:
        for c in self.ens_controls:
            if c.is_primary:
                return c
        return self.ens_controls[0] if self.ens_controls else None


class AuditRequest(BaseModel):
    """Credentials for a live, authorised audit. Not persisted."""

    domain: str = Field(..., min_length=1, description="AD DNS domain, e.g. contoso.local")
    dc_host: str = Field(..., min_length=1, description="Domain controller hostname or IP")
    username: str = Field(..., min_length=1, description="sAMAccountName or UPN")
    password: Optional[str] = Field(default=None, description="Cleartext password. Not stored.")
    nthash: Optional[str] = Field(
        default=None, description="NT hash (32 hex chars) or LM:NT. Not stored."
    )
    authorized: bool = Field(
        ...,
        description="Must be true: the caller affirms written authorisation exists.",
    )

    @field_validator("domain", "dc_host", "username")
    @classmethod
    def _strip_required(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Este campo no puede estar vacío")
        return stripped

    @field_validator("password")
    @classmethod
    def _strip_password(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None

    @field_validator("nthash")
    @classmethod
    def _normalise_nthash(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        raw = value.strip().replace(" ", "")
        if not raw:
            return None
        if ":" in raw:
            lm, _, nt = raw.partition(":")
            nt = nt.strip()
            lm = lm.strip()
            if len(nt) != 32 or (lm and len(lm) != 32):
                raise ValueError("El hash NT debe tener 32 caracteres hexadecimales")
            if any(c not in "0123456789abcdefABCDEF" for c in nt):
                raise ValueError("El hash NT debe ser hexadecimal")
            return nt.lower()
        if len(raw) != 32 or any(c not in "0123456789abcdefABCDEF" for c in raw):
            raise ValueError("El hash NT debe tener 32 caracteres hexadecimales")
        return raw.lower()

    @model_validator(mode="after")
    def _require_secret_and_authorisation(self) -> "AuditRequest":
        if not self.authorized:
            raise ValueError(
                "Se requiere autorización expresa por escrito antes de conectar"
            )
        if not self.password and not self.nthash:
            raise ValueError("Indica una contraseña o un hash NT")
        return self


class MatrixCell(BaseModel):
    impact: int
    likelihood: int
    count: int
    risk: RiskLevel


class RiskMatrix(BaseModel):
    """MAGERIT matrix built from returned alerts. Empty when there are none."""

    empty: bool = True
    cells: List[MatrixCell] = Field(default_factory=list)


class DomainSummary(BaseModel):
    """Domain-level criticidad. Zeros when there are no returned findings."""

    highest_risk: Optional[RiskLevel] = None
    controls_hit: int = 0
    da_path: bool = False
    da_path_count: int = 0
    total_alerts: int = 0


class ScanResponse(BaseModel):
    """Response for GET /api/scan and POST /api/audit."""

    generated_at: str
    is_sample: bool = Field(
        default=False,
        description="Always false. The API never returns fabricated findings.",
    )
    scanned: bool = False
    total_alerts: int
    counts_by_risk: dict
    alerts: List[GRCAlert]
    domain: Optional[str] = None
    dc_host: Optional[str] = None
    errors: List[str] = Field(default_factory=list)
    matrix: RiskMatrix = Field(default_factory=RiskMatrix)
    summary: DomainSummary = Field(default_factory=DomainSummary)
