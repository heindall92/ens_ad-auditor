import { emptyCoverage } from "./emptyScan";
import { RISK_ORDER, type CoverageCheck, type GRCAlert, type RiskLevel, type ScanResponse } from "./types";

const RISKS = new Set<string>(RISK_ORDER);
const SECRET_KEYS = new Set(["password", "nthash", "secret", "lmhash"]);

export const JSON_FILE_MAX_BYTES = 8 * 1024 * 1024;

export type ScanParseError =
  | "invalid_json"
  | "not_object"
  | "sample"
  | "credentials"
  | "schema"
  | "too_large";

export type ScanParseResult =
  | { ok: true; data: ScanResponse }
  | { ok: false; error: ScanParseError; detail?: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasSecretKey(value: unknown, depth = 0): boolean {
  if (depth > 8 || value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some((item) => hasSecretKey(item, depth + 1));
  for (const key of Object.keys(value as Record<string, unknown>)) {
    if (SECRET_KEYS.has(key.toLowerCase())) return true;
    if (hasSecretKey((value as Record<string, unknown>)[key], depth + 1)) return true;
  }
  return false;
}

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function asBool(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function asInt(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) ? value : null;
}

function asRisk(value: unknown): RiskLevel | null {
  return typeof value === "string" && RISKS.has(value) ? (value as RiskLevel) : null;
}

function parseFinding(raw: unknown): GRCAlert["finding"] | null {
  if (!isRecord(raw)) return null;
  const finding_type = asString(raw.finding_type);
  const title = asString(raw.title);
  const target = asString(raw.target);
  const detail = asString(raw.detail);
  const source_module = asString(raw.source_module);
  if (!finding_type || !title || !target || !detail || !source_module) return null;
  if (raw.is_sample === true) return null;
  const evidence = raw.evidence === null || raw.evidence === undefined ? null : asString(raw.evidence);
  if (raw.evidence !== undefined && raw.evidence !== null && evidence === null) return null;
  const subtype = raw.subtype === null || raw.subtype === undefined ? null : asString(raw.subtype);
  if (raw.subtype !== undefined && raw.subtype !== null && subtype === null) return null;
  return {
    finding_type,
    title,
    target,
    detail,
    evidence,
    source_module,
    subtype,
    is_sample: false,
  };
}

function parseControl(raw: unknown): GRCAlert["ens_controls"][number] | null {
  if (!isRecord(raw)) return null;
  const id = asString(raw.id);
  const name = asString(raw.name);
  const is_primary = asBool(raw.is_primary);
  if (!id || !name || is_primary === null) return null;
  return { id, name, is_primary };
}

function parseAlert(raw: unknown): GRCAlert | null {
  if (!isRecord(raw)) return null;
  const rule_id = asString(raw.rule_id);
  const finding = parseFinding(raw.finding);
  const risk = asRisk(raw.risk);
  const non_compliance = asString(raw.non_compliance);
  const remediation = asString(raw.remediation);
  const impact = asInt(raw.impact);
  const likelihood = asInt(raw.likelihood);
  const score = asInt(raw.score);
  if (!rule_id || !finding || !risk || !non_compliance || !remediation) return null;
  if (impact === null || impact < 1 || impact > 5) return null;
  if (likelihood === null || likelihood < 1 || likelihood > 5) return null;
  if (score === null) return null;
  if (!Array.isArray(raw.ens_controls) || raw.ens_controls.length === 0) return null;
  const ens_controls = raw.ens_controls.map(parseControl);
  if (ens_controls.some((c) => c === null)) return null;
  const references = Array.isArray(raw.references)
    ? raw.references.map(asString)
    : [];
  if (references.some((r) => r === null)) return null;
  const rationale =
    raw.rationale === null || raw.rationale === undefined ? null : asString(raw.rationale);
  if (raw.rationale !== undefined && raw.rationale !== null && rationale === null) return null;
  const da_path = raw.da_path === undefined ? false : asBool(raw.da_path);
  if (da_path === null) return null;
  return {
    rule_id,
    finding,
    risk,
    ens_controls: ens_controls as GRCAlert["ens_controls"],
    non_compliance,
    remediation,
    references: references as string[],
    rationale,
    impact,
    likelihood,
    score,
    da_path,
  };
}

function parseCoverage(raw: unknown): CoverageCheck | null {
  if (!isRecord(raw)) return null;
  const id = asString(raw.id);
  const area = asString(raw.area);
  const status = asString(raw.status);
  const detail = asString(raw.detail);
  if (!id || !area || !status || !detail) return null;
  return { id, area, status, detail };
}

function countsFrom(alerts: GRCAlert[]): ScanResponse["counts_by_risk"] {
  const counts = { Critico: 0, Alto: 0, Medio: 0, Bajo: 0 };
  for (const a of alerts) counts[a.risk] += 1;
  return counts;
}

function riskBand(impact: number, likelihood: number): RiskLevel {
  const product = impact * likelihood;
  if (product >= 16) return "Critico";
  if (product >= 10) return "Alto";
  if (product >= 5) return "Medio";
  return "Bajo";
}

function matrixFrom(alerts: GRCAlert[]): ScanResponse["matrix"] {
  if (alerts.length === 0) return { empty: true, cells: [] };
  const map = new Map<string, { impact: number; likelihood: number; count: number; risk: RiskLevel }>();
  for (const a of alerts) {
    const key = `${a.impact}:${a.likelihood}`;
    const cur = map.get(key);
    if (cur) cur.count += 1;
    else {
      map.set(key, {
        impact: a.impact,
        likelihood: a.likelihood,
        count: 1,
        risk: riskBand(a.impact, a.likelihood),
      });
    }
  }
  return { empty: false, cells: [...map.values()] };
}

function summaryFrom(alerts: GRCAlert[]): ScanResponse["summary"] {
  const controls = new Set<string>();
  let da = 0;
  let highest: RiskLevel | null = null;
  const rank = (r: RiskLevel) => RISK_ORDER.indexOf(r);
  for (const a of alerts) {
    for (const c of a.ens_controls) controls.add(c.id);
    if (a.da_path) da += 1;
    if (!highest || rank(a.risk) < rank(highest)) highest = a.risk;
  }
  return {
    highest_risk: highest,
    controls_hit: controls.size,
    da_path: da > 0,
    da_path_count: da,
    total_alerts: alerts.length,
  };
}

function parseMatrix(raw: unknown, alerts: GRCAlert[]): ScanResponse["matrix"] {
  if (!isRecord(raw)) return matrixFrom(alerts);
  const empty = asBool(raw.empty);
  if (empty === null || !Array.isArray(raw.cells)) return matrixFrom(alerts);
  const cells = [];
  for (const item of raw.cells) {
    if (!isRecord(item)) return matrixFrom(alerts);
    const impact = asInt(item.impact);
    const likelihood = asInt(item.likelihood);
    const count = asInt(item.count);
    const risk = asRisk(item.risk);
    if (impact === null || likelihood === null || count === null || !risk) return matrixFrom(alerts);
    cells.push({ impact, likelihood, count, risk });
  }
  return { empty, cells };
}

function parseSummary(raw: unknown, alerts: GRCAlert[]): ScanResponse["summary"] {
  if (!isRecord(raw)) return summaryFrom(alerts);
  const highest_risk = raw.highest_risk === null || raw.highest_risk === undefined ? null : asRisk(raw.highest_risk);
  if (raw.highest_risk !== undefined && raw.highest_risk !== null && highest_risk === null) {
    return summaryFrom(alerts);
  }
  const controls_hit = asInt(raw.controls_hit);
  const da_path = asBool(raw.da_path);
  const da_path_count = asInt(raw.da_path_count);
  const total_alerts = asInt(raw.total_alerts);
  if (controls_hit === null || da_path === null || da_path_count === null || total_alerts === null) {
    return summaryFrom(alerts);
  }
  return { highest_risk, controls_hit, da_path, da_path_count, total_alerts };
}

export function parseScanJson(text: string): ScanParseResult {
  let raw: unknown;
  try {
    raw = JSON.parse(text) as unknown;
  } catch {
    return { ok: false, error: "invalid_json" };
  }
  if (!isRecord(raw)) return { ok: false, error: "not_object" };
  if (hasSecretKey(raw)) return { ok: false, error: "credentials" };
  if (raw.is_sample === true) return { ok: false, error: "sample" };
  if (!Array.isArray(raw.alerts)) return { ok: false, error: "schema", detail: "alerts" };

  const alerts: GRCAlert[] = [];
  for (let i = 0; i < raw.alerts.length; i += 1) {
    const alert = parseAlert(raw.alerts[i]);
    if (!alert) return { ok: false, error: "schema", detail: `alerts[${i}]` };
    alerts.push(alert);
  }

  if (raw.total_alerts !== undefined) {
    const n = asInt(raw.total_alerts);
    if (n === null || n !== alerts.length) {
      return { ok: false, error: "schema", detail: "total_alerts" };
    }
  }

  let coverage: CoverageCheck[];
  if (raw.coverage === undefined) {
    coverage = emptyCoverage();
  } else if (!Array.isArray(raw.coverage)) {
    return { ok: false, error: "schema", detail: "coverage" };
  } else {
    coverage = [];
    for (let i = 0; i < raw.coverage.length; i += 1) {
      const row = parseCoverage(raw.coverage[i]);
      if (!row) return { ok: false, error: "schema", detail: `coverage[${i}]` };
      coverage.push(row);
    }
  }

  const generated_at = asString(raw.generated_at) ?? new Date().toISOString();
  const scanned = asBool(raw.scanned) ?? Boolean(asString(raw.domain));
  const domain = raw.domain === undefined || raw.domain === null ? null : asString(raw.domain);
  if (raw.domain !== undefined && raw.domain !== null && domain === null) {
    return { ok: false, error: "schema", detail: "domain" };
  }
  const dc_host = raw.dc_host === undefined || raw.dc_host === null ? null : asString(raw.dc_host);
  if (raw.dc_host !== undefined && raw.dc_host !== null && dc_host === null) {
    return { ok: false, error: "schema", detail: "dc_host" };
  }
  let errors: string[] = [];
  if (raw.errors !== undefined) {
    if (!Array.isArray(raw.errors)) return { ok: false, error: "schema", detail: "errors" };
    const parsed = raw.errors.map(asString);
    if (parsed.some((e) => e === null)) return { ok: false, error: "schema", detail: "errors" };
    errors = parsed as string[];
  }

  const counts = countsFrom(alerts);
  if (isRecord(raw.counts_by_risk)) {
    for (const level of RISK_ORDER) {
      const n = asInt(raw.counts_by_risk[level]);
      if (n !== null && n !== counts[level]) {
        return { ok: false, error: "schema", detail: "counts_by_risk" };
      }
    }
  }

  return {
    ok: true,
    data: {
      generated_at,
      is_sample: false,
      scanned,
      total_alerts: alerts.length,
      counts_by_risk: counts,
      alerts,
      domain,
      dc_host,
      errors,
      matrix: parseMatrix(raw.matrix, alerts),
      summary: parseSummary(raw.summary, alerts),
      coverage,
    },
  };
}
