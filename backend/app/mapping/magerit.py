"""MAGERIT-style risk: impact × likelihood, mapped to ENS Crítico/Alto/Medio/Bajo.

The qualitative 5×5 follows the MAGERIT idea used in Spanish public-sector
risk analysis: value/impact of the asset times frequency/likelihood of the
scenario. The product is the score; bands map onto the ENS risk labels
already used by the mapping engine.

Only calculated from real alerts. No alerts → empty matrix.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from app.models import (
    DomainSummary,
    GRCAlert,
    MatrixCell,
    RiskLevel,
    RiskMatrix,
)

IMPACT_MIN = 1
IMPACT_MAX = 5


def score(impact: int, likelihood: int) -> int:
    if not (IMPACT_MIN <= impact <= IMPACT_MAX and IMPACT_MIN <= likelihood <= IMPACT_MAX):
        raise ValueError(f"Impacto y probabilidad deben estar entre {IMPACT_MIN} y {IMPACT_MAX}")
    return impact * likelihood


def level_from_factors(impact: int, likelihood: int) -> RiskLevel:
    """Map MAGERIT product to the ENS four-level scale."""
    product = score(impact, likelihood)
    if product >= 16:
        return RiskLevel.CRITICO
    if product >= 10:
        return RiskLevel.ALTO
    if product >= 5:
        return RiskLevel.MEDIO
    return RiskLevel.BAJO


def build_matrix(alerts: List[GRCAlert]) -> RiskMatrix:
    if not alerts:
        return RiskMatrix(empty=True, cells=[])
    counts: Dict[tuple[int, int], int] = {}
    for alert in alerts:
        key = (alert.impact, alert.likelihood)
        counts[key] = counts.get(key, 0) + 1
    cells = [
        MatrixCell(
            impact=imp,
            likelihood=like,
            count=n,
            risk=level_from_factors(imp, like),
        )
        for (imp, like), n in sorted(counts.items(), key=lambda kv: (-kv[0][0], -kv[0][1]))
    ]
    return RiskMatrix(empty=False, cells=cells)


def build_summary(alerts: List[GRCAlert]) -> DomainSummary:
    if not alerts:
        return DomainSummary()
    highest = max(alerts, key=lambda a: a.risk.order).risk
    controls = {c.id for a in alerts for c in a.ens_controls}
    da = [a for a in alerts if a.da_path]
    return DomainSummary(
        highest_risk=highest,
        controls_hit=len(controls),
        da_path=bool(da),
        da_path_count=len(da),
        total_alerts=len(alerts),
    )
