"""
Core data models for ENS AD Auditor.

Finding      -> a raw technical finding produced by an enumeration module.
EnsControl   -> a reference to a specific ENS [op.acc] control.
GRCAlert     -> a technical Finding translated into an ENS GRC non-compliance.

All user-facing strings (descriptions, remediations, risk labels) are in
Spanish by design; code identifiers stay in English.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


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
        default=True,
        description="True when this is demo/sample data, not a real scan result.",
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

    @property
    def primary_control(self) -> Optional[EnsControl]:
        for c in self.ens_controls:
            if c.is_primary:
                return c
        return self.ens_controls[0] if self.ens_controls else None


class ScanResponse(BaseModel):
    """Top-level response for GET /api/scan."""

    generated_at: str
    is_sample: bool
    total_alerts: int
    counts_by_risk: dict
    alerts: List[GRCAlert]
