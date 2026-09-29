// Mirrors backend/app/models.py (Pydantic). Keep in sync when models change.

export type RiskLevel = "Critico" | "Alto" | "Medio" | "Bajo";

export const RISK_ORDER: RiskLevel[] = ["Critico", "Alto", "Medio", "Bajo"];

export const RISK_LABEL: Record<RiskLevel, string> = {
  Critico: "Crítico",
  Alto: "Alto",
  Medio: "Medio",
  Bajo: "Bajo",
};

export interface Finding {
  finding_type: string;
  title: string;
  target: string;
  detail: string;
  evidence: string | null;
  source_module: string;
  subtype: string | null;
  is_sample: boolean;
}

export interface EnsControl {
  id: string;
  name: string;
  is_primary: boolean;
}

export interface GRCAlert {
  rule_id: string;
  finding: Finding;
  risk: RiskLevel;
  ens_controls: EnsControl[];
  non_compliance: string;
  remediation: string;
  references: string[];
  rationale: string | null;
}

export interface ScanResponse {
  generated_at: string;
  is_sample: boolean;
  total_alerts: number;
  counts_by_risk: Record<RiskLevel, number>;
  alerts: GRCAlert[];
}

// GET /api/controls: catálogo de controles ENS de la familia [op.acc].
export interface ControlsCatalog {
  family: string;
  controls: Record<string, string>;
}
