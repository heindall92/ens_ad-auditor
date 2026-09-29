"""
Report generation: build JSON and Markdown reports from a list of GRCAlerts.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.models import GRCAlert, RiskLevel

RISK_ORDER = [RiskLevel.CRITICO, RiskLevel.ALTO, RiskLevel.MEDIO, RiskLevel.BAJO]


def counts_by_risk(alerts: List[GRCAlert]) -> Dict[str, int]:
    """Return a {risk_label: count} dict covering all risk levels."""
    counts = {r.value: 0 for r in RISK_ORDER}
    for a in alerts:
        counts[a.risk.value] += 1
    return counts


def build_json_report(
    alerts: List[GRCAlert],
    is_sample: bool = False,
    domain: Optional[str] = None,
    errors: Optional[List[str]] = None,
) -> dict:
    """Return a JSON-serialisable report dict."""
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "is_sample": is_sample,
        "scanned": domain is not None,
        "domain": domain,
        "total_alerts": len(alerts),
        "counts_by_risk": counts_by_risk(alerts),
        "errors": list(errors or []),
        "alerts": [a.model_dump() for a in alerts],
    }


def build_markdown_report(
    alerts: List[GRCAlert],
    is_sample: bool = False,
    domain: Optional[str] = None,
    errors: Optional[List[str]] = None,
) -> str:
    """Return a Markdown report (Spanish, user-facing)."""
    generated = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")
    counts = counts_by_risk(alerts)

    lines: List[str] = []
    lines.append("# Informe GRC — ENS AD Auditor")
    lines.append("")
    lines.append(
        "Auditoría de Active Directory mapeada al **ENS** (Esquema "
        "Nacional de Seguridad), familia de control de acceso **[op.acc]**."
    )
    lines.append("")
    if is_sample:
        lines.append(
            "> **DATOS DE DEMOSTRACIÓN.** Este informe se ha generado "
            "con hallazgos de muestra, no con un escaneo real."
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

    if not alerts:
        if domain:
            lines.append(
                "La enumeración no ha devuelto debilidades de configuración "
                "en Kerberos, delegación, AD CS ni firma SMB."
            )
        else:
            lines.append(
                "Sin alertas. No se ha enumerado ningún dominio: hace falta "
                "conectar con autorización expresa por escrito."
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
