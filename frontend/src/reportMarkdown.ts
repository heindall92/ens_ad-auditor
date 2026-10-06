import { emptyCoverage } from "./emptyScan";
import { RISK_ORDER, type CoverageCheck, type GRCAlert, type ScanResponse } from "./types";

function coverageSection(checks: CoverageCheck[]): string[] {
  const lines = ["## Cobertura", "", "| Área | Estado | Detalle |", "|---|---|---|"];
  for (const item of checks) {
    lines.push(`| ${item.area} | ${item.status} | ${item.detail.replace(/\|/g, "/")} |`);
  }
  lines.push("");
  return lines;
}

/** Client-side Markdown report from an already loaded ScanResponse. No network. */
export function buildMarkdownReport(data: ScanResponse): string {
  const alerts = data.alerts;
  const counts = data.counts_by_risk;
  const checks = data.coverage?.length ? data.coverage : emptyCoverage();
  const generated = data.generated_at;
  const lines: string[] = [];
  lines.push("# Informe GRC — ENS AD Auditor", "");
  lines.push(
    "Auditoría de Active Directory mapeada al **ENS** (Esquema Nacional de Seguridad), familia de control de acceso **[op.acc]**.",
    "",
  );
  lines.push(`- **Fecha de generación:** ${generated}`);
  if (data.domain) lines.push(`- **Dominio:** \`${data.domain}\``);
  else lines.push("- **Dominio:** no conectado");
  lines.push(`- **Total de alertas:** ${alerts.length}`);
  lines.push(
    `- **Distribución por riesgo:** Crítico ${counts.Critico} · Alto ${counts.Alto} · Medio ${counts.Medio} · Bajo ${counts.Bajo}`,
    "",
  );

  if (data.errors.length) {
    lines.push("## Avisos de enumeración", "");
    for (const err of data.errors) lines.push(`- ${err}`);
    lines.push("");
  }

  lines.push(...coverageSection(checks));
  lines.push("## Resumen de criticidad", "");

  if (!alerts.length) {
    lines.push("Sin hallazgos devueltos. La matriz MAGERIT está vacía.", "");
    const ran = checks.filter((item) => item.status === "comprobado").map((item) => item.area);
    const pending = checks.filter((item) => item.status !== "comprobado").map((item) => item.area);
    if (data.scanned && data.domain && ran.length) {
      lines.push(
        "Comprobado y limpio en las filas con estado comprobado (" +
          ran.join(", ") +
          "): la enumeración autorizada no ha devuelto debilidades en esas comprobaciones. No se han inventado hallazgos.",
      );
      if (pending.length) {
        lines.push(
          "",
          "No comprobado: " +
            pending.join(", ") +
            ". Esas filas no se han ejecutado y no se consideran limpias.",
        );
      }
    } else {
      lines.push(
        "No comprobado: no se ha enumerado ningún dominio, o ninguna fila de cobertura llegó a ejecutarse. Hace falta conectar con autorización expresa por escrito. La matriz está vacía. «No comprobado» no significa que el dominio esté limpio.",
      );
    }
    lines.push("", "---", "*Generado por ENS AD Auditor. Uso exclusivo para auditorías autorizadas.*");
    return lines.join("\n");
  }

  const summary = data.summary;
  lines.push(`- **Riesgo más alto:** ${summary.highest_risk ?? "n/d"}`);
  lines.push(`- **Controles [op.acc] afectados:** ${summary.controls_hit}`);
  lines.push(
    `- **Camino directo a Domain Admin:** ${summary.da_path ? "sí" : "no"} (${summary.da_path_count} hallazgo(s))`,
    "",
  );
  lines.push("## Matriz MAGERIT (impacto × probabilidad)", "");
  if (data.matrix.empty) {
    lines.push("Matriz vacía.");
  } else {
    lines.push("| Impacto | Probabilidad | Score | Riesgo ENS | Hallazgos |", "|---|---|---|---|---|");
    for (const cell of data.matrix.cells) {
      lines.push(
        `| ${cell.impact} | ${cell.likelihood} | ${cell.impact * cell.likelihood} | ${cell.risk} | ${cell.count} |`,
      );
    }
  }
  lines.push("");

  for (const risk of RISK_ORDER) {
    const group = alerts.filter((a) => a.risk === risk);
    if (!group.length) continue;
    lines.push(`## Riesgo ${risk} (${group.length})`, "");
    for (const a of group) {
      writeAlert(lines, a);
    }
  }

  lines.push("---", "*Generado por ENS AD Auditor. Uso exclusivo para auditorías autorizadas.*");
  return lines.join("\n");
}

function writeAlert(lines: string[], a: GRCAlert): void {
  const controls = a.ens_controls
    .map((c) => `${c.id} ${c.name}` + (c.is_primary ? " (primario)" : ""))
    .join(", ");
  lines.push(`### ${a.finding.title}`, "");
  lines.push(`- **Objetivo:** ${a.finding.target}`);
  lines.push(`- **Módulo:** \`${a.finding.source_module}\``);
  lines.push(
    `- **Criticidad MAGERIT:** impacto ${a.impact} × probabilidad ${a.likelihood} = ${a.score} → ${a.risk}`,
  );
  if (a.da_path) lines.push("- **Camino a Domain Admin:** sí");
  lines.push(`- **Hallazgo técnico:** ${a.finding.detail}`);
  lines.push(`- **Control(es) ENS [op.acc]:** ${controls}`);
  lines.push(`- **Incumplimiento:** ${a.non_compliance}`);
  lines.push(`- **Remediación:** ${a.remediation}`);
  if (a.references.length) {
    lines.push(`- **Referencias adicionales:** ${a.references.join(", ")}`);
  }
  if (a.finding.evidence) {
    lines.push(`- **Evidencia:** \`${a.finding.evidence}\``);
  }
  lines.push("");
}
