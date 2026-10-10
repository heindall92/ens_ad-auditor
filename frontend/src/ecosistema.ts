import type { GRCAlert, RiskLevel } from "./types";

/** Sobre «yrd-ecosistema» v1, tipo «hallazgos». Keep in sync with backend/app/ecosistema.py */
export const ECO_FORMAT = "yrd-ecosistema";

export function buildEcosistema(alerts: GRCAlert[], domain: string | null, appVersion: string, now: Date = new Date()): object {
  const live = alerts.filter((a) => !a.finding.is_sample);
  const counts: Record<RiskLevel, number> = { Critico: 0, Alto: 0, Medio: 0, Bajo: 0 };
  for (const a of live) counts[a.risk] += 1;
  return {
    format: ECO_FORMAT,
    version: 1,
    origen: { herramienta: "ens-ad-auditor", version: appVersion, generado: now.toISOString().replace(/\.\d{3}Z$/, "Z") },
    tipo: "hallazgos",
    proyecto: domain || "Active Directory",
    datos: live,
    resumen: { domain, is_sample: false, total_alerts: live.length, counts_by_risk: counts, da_path: live.filter((a) => a.da_path).length },
  };
}
