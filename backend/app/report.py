"""
Report generation: build JSON and Markdown reports from a list of GRCAlerts.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.enumeration.coverage import empty_coverage
from app.models import CoverageCheck, DomainSummary, GRCAlert, RiskLevel, RiskMatrix

RISK_ORDER = [RiskLevel.CRITICO, RiskLevel.ALTO, RiskLevel.MEDIO, RiskLevel.BAJO]


def counts_by_risk(alerts: List[GRCAlert]) -> Dict[str, int]:
    """Return a {risk_label: count} dict covering all risk levels."""
    counts = {r.value: 0 for r in RISK_ORDER}
    for a in alerts:
        counts[a.risk.value] += 1
    return counts


def _checks(coverage: Optional[List[CoverageCheck]]) -> List[CoverageCheck]:
    return list(coverage) if coverage is not None else empty_coverage()


def build_json_report(
    alerts: List[GRCAlert],
    is_sample: bool = False,  # kept in the payload as the "never fabricated" flag
    domain: Optional[str] = None,
    errors: Optional[List[str]] = None,
    matrix: Optional[RiskMatrix] = None,
    summary: Optional[DomainSummary] = None,
    coverage: Optional[List[CoverageCheck]] = None,
) -> dict:
    """Return a JSON-serialisable report dict."""
    matrix = matrix or RiskMatrix(empty=True, cells=[])
    summary = summary or DomainSummary()
    checks = _checks(coverage)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "is_sample": is_sample,
        "scanned": domain is not None,
        "domain": domain,
        "total_alerts": len(alerts),
        "counts_by_risk": counts_by_risk(alerts),
        "errors": list(errors or []),
        "matrix": matrix.model_dump(),
        "summary": summary.model_dump(),
        "coverage": [item.model_dump() for item in checks],
        "alerts": [a.model_dump() for a in alerts],
    }


def _coverage_section(checks: List[CoverageCheck]) -> List[str]:
    lines = ["## Cobertura", ""]
    lines.append("| Área | Estado | Detalle |")
    lines.append("|---|---|---|")
    for item in checks:
        detail = item.detail.replace("|", "/")
        lines.append(f"| {item.area} | {item.status} | {detail} |")
    lines.append("")
    return lines


def build_markdown_report(
    alerts: List[GRCAlert],
    is_sample: bool = False,  # unused: markdown never labels a result as sample
    domain: Optional[str] = None,
    errors: Optional[List[str]] = None,
    matrix: Optional[RiskMatrix] = None,
    summary: Optional[DomainSummary] = None,
    coverage: Optional[List[CoverageCheck]] = None,
) -> str:
    """Return a Markdown report (Spanish, user-facing)."""
    generated = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")
    counts = counts_by_risk(alerts)
    matrix = matrix or RiskMatrix(empty=True, cells=[])
    summary = summary or DomainSummary()

    checks = _checks(coverage)
    lines: List[str] = []
    lines.append("# Informe GRC — ENS AD Auditor")
    lines.append("")
    lines.append(
        "Auditoría de Active Directory mapeada al **ENS** (Esquema "
        "Nacional de Seguridad), familia de control de acceso **[op.acc]**."
    )
    lines.append("")
    lines.append(f"- **Fecha de generación:** {generated}")
    if domain:
        lines.append(f"- **Dominio:** `{domain}`")
    else:
        lines.append("- **Dominio:** no conectado")
    lines.append(f"- **Total de alertas:** {len(alerts)}")
    lines.append(
        "- **Distribución por riesgo:** "
        f"Crítico {counts['Critico']} · Alto {counts['Alto']} · "
        f"Medio {counts['Medio']} · Bajo {counts['Bajo']}"
    )
    lines.append("")

    if errors:
        lines.append("## Avisos de enumeración")
        lines.append("")
        for err in errors:
            lines.append(f"- {err}")
        lines.append("")

    lines.extend(_coverage_section(checks))

    lines.append("## Resumen de criticidad")
    lines.append("")
    if not alerts:
        lines.append("Sin hallazgos devueltos. La matriz MAGERIT está vacía.")
        lines.append("")
    else:
        highest = summary.highest_risk.value if summary.highest_risk else "n/d"
        lines.append(f"- **Riesgo más alto:** {highest}")
        lines.append(f"- **Controles [op.acc] afectados:** {summary.controls_hit}")
        lines.append(
            f"- **Camino directo a Domain Admin:** "
            f"{'sí' if summary.da_path else 'no'} ({summary.da_path_count} hallazgo(s))"
        )
        lines.append("")
        lines.append("## Matriz MAGERIT (impacto × probabilidad)")
        lines.append("")
        if matrix.empty:
            lines.append("Matriz vacía.")
        else:
            lines.append("| Impacto | Probabilidad | Score | Riesgo ENS | Hallazgos |")
            lines.append("|---|---|---|---|---|")
            for cell in matrix.cells:
                product = cell.impact * cell.likelihood
                lines.append(
                    f"| {cell.impact} | {cell.likelihood} | {product} | "
                    f"{cell.risk.value} | {cell.count} |"
                )
        lines.append("")

    if not alerts:
        ran = [item.area for item in checks if item.status == "comprobado"]
        pending = [item.area for item in checks if item.status != "comprobado"]
        if domain and ran:
            lines.append(
                "Comprobado y limpio en las filas con estado comprobado ("
                + ", ".join(ran)
                + "): la enumeración autorizada no ha devuelto debilidades en esas "
                "comprobaciones. No se han inventado hallazgos."
            )
            if pending:
                lines.append("")
                lines.append(
                    "No comprobado: "
                    + ", ".join(pending)
                    + ". Esas filas no se han ejecutado y no se consideran limpias."
                )
        else:
            lines.append(
                "No comprobado: no se ha enumerado ningún dominio, o ninguna fila "
                "de cobertura llegó a ejecutarse. Hace falta conectar con "
                "autorización expresa por escrito. La matriz está vacía."
            )
        lines.append("")
        lines.append("---")
        lines.append(
            "*Generado por ENS AD Auditor. Uso exclusivo para auditorías "
            "autorizadas.*"
        )
        return "\n".join(lines)

    for risk in RISK_ORDER:
        group = [a for a in alerts if a.risk == risk]
        if not group:
            continue
        lines.append(f"## Riesgo {risk.value} ({len(group)})")
        lines.append("")
        for a in group:
            controls = ", ".join(
                f"{c.id} {c.name}" + (" (primario)" if c.is_primary else "")
                for c in a.ens_controls
            )
            lines.append(f"### {a.finding.title}")
            lines.append("")
            lines.append(f"- **Objetivo:** {a.finding.target}")
            lines.append(f"- **Módulo:** `{a.finding.source_module}`")
            lines.append(
                f"- **Criticidad MAGERIT:** impacto {a.impact} × "
                f"probabilidad {a.likelihood} = {a.score} → {a.risk.value}"
            )
            if a.da_path:
                lines.append("- **Camino a Domain Admin:** sí")
            lines.append(f"- **Hallazgo técnico:** {a.finding.detail}")
            lines.append(f"- **Control(es) ENS [op.acc]:** {controls}")
            lines.append(f"- **Incumplimiento:** {a.non_compliance}")
            lines.append(f"- **Remediación:** {a.remediation}")
            if a.references:
                lines.append(f"- **Referencias adicionales:** {', '.join(a.references)}")
            if a.finding.evidence:
                lines.append(f"- **Evidencia:** `{a.finding.evidence}`")
            lines.append("")

    lines.append("---")
    lines.append(
        "*Generado por ENS AD Auditor. Uso exclusivo para auditorías "
        "autorizadas.*"
    )
    return "\n".join(lines)
