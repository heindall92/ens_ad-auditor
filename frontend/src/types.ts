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
  impact: number;
  likelihood: number;
  score: number;
  da_path: boolean;
}

export interface MatrixCell {
  impact: number;
  likelihood: number;
  count: number;
  risk: RiskLevel;
}

export interface RiskMatrix {
  empty: boolean;
  cells: MatrixCell[];
}

export interface DomainSummary {
  highest_risk: RiskLevel | null;
  controls_hit: number;
  da_path: boolean;
  da_path_count: number;
  total_alerts: number;
}

export interface CoverageCheck {
  id: string;
  area: string;
  status: string;
  detail: string;
}

export interface ScanResponse {
  generated_at: string;
  is_sample: boolean;
  scanned: boolean;
  total_alerts: number;
  counts_by_risk: Record<RiskLevel, number>;
  alerts: GRCAlert[];
  domain: string | null;
  dc_host: string | null;
  errors: string[];
  matrix: RiskMatrix;
  summary: DomainSummary;
  coverage?: CoverageCheck[];
}

export interface AuditRequest {
  domain: string;
  dc_host: string;
  username: string;
  password?: string;
  nthash?: string;
  authorized: boolean;
}

export interface ControlsCatalog {
  family: string;
  controls: Record<string, string>;
}
