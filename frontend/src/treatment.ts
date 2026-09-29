import type { GRCAlert } from "./types";

export type TreatStatus = "abierto" | "en_curso" | "aceptado" | "corregido";

export interface Treatment {
  owner: string;
  status: TreatStatus;
  due: string;
}

const KEY = "ens-ad-auditor.treatment";

export function treatmentKey(ruleId: string, target: string): string {
  return `${ruleId}::${target}`;
}

export function emptyTreatment(): Treatment {
  return { owner: "", status: "abierto", due: "" };
}

export function loadTreatments(): Record<string, Treatment> {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Record<string, Treatment>;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

export function saveTreatment(key: string, value: Treatment): void {
  const all = loadTreatments();
  const owner = value.owner.trim();
  if (!owner && !value.due && value.status === "abierto") delete all[key];
  else all[key] = { owner, status: value.status, due: value.due };
  localStorage.setItem(KEY, JSON.stringify(all));
}

export function appendixMarkdown(
  alerts: GRCAlert[],
  labels: Record<TreatStatus, string>,
  headings: { title: string; owner: string; status: string; due: string; empty: string; note: string },
): string {
  const stored = loadTreatments();
  const byKey = new Map(alerts.map((a) => [treatmentKey(a.rule_id, a.finding.target), a]));
  const keys = Object.keys(stored);
  const lines = [`# ${headings.title}`, "", headings.note, ""];
  if (!keys.length) {
    lines.push(headings.empty, "");
    return lines.join("\n");
  }
  lines.push(`| ${headings.owner} | ${headings.status} | ${headings.due} | Hallazgo | Objetivo |`);
  lines.push("|---|---|---|---|---|");
  for (const key of keys) {
    const row = stored[key];
    const alert = byKey.get(key);
    const sep = key.indexOf("::");
    const ruleId = sep >= 0 ? key.slice(0, sep) : key;
    const target = sep >= 0 ? key.slice(sep + 2) : "";
    const title = alert?.finding.title ?? ruleId;
    const goal = alert?.finding.target ?? target ?? "";
    lines.push(
      `| ${row.owner || "—"} | ${labels[row.status] ?? row.status} | ${row.due || "—"} | ${title} | ${goal} |`,
    );
  }
  lines.push("");
  return lines.join("\n");
}
