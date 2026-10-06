import { PAGES_BUILD } from "../browserMode";
import type { AuditRequest, ControlsCatalog, ScanResponse } from "../types";

const API_BASE: string = import.meta.env.VITE_API_BASE ?? "";

async function readError(res: Response, path: string): Promise<string> {
  try {
    const body = (await res.json()) as { detail?: unknown };
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail)) {
      return body.detail
        .map((item) => (typeof item === "object" && item && "msg" in item ? String(item.msg) : String(item)))
        .join(" · ");
    }
  } catch {
    /* ignore non-JSON */
  }
  return `Error ${res.status} al consultar ${path}`;
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) {
    throw new Error(await readError(res, path));
  }
  return (await res.json()) as T;
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(await readError(res, path));
  }
  return (await res.json()) as T;
}

export function fetchScan(): Promise<ScanResponse> {
  return getJson<ScanResponse>("/api/scan");
}

export function runAudit(req: AuditRequest): Promise<ScanResponse> {
  return postJson<ScanResponse>("/api/audit", req);
}

export async function fetchMarkdownReport(req?: AuditRequest): Promise<string> {
  const res = await fetch(`${API_BASE}/api/report`, {
    method: req ? "POST" : "GET",
    headers: req ? { "Content-Type": "application/json" } : undefined,
    body: req ? JSON.stringify(req) : undefined,
  });
  if (!res.ok) {
    throw new Error(await readError(res, "/api/report"));
  }
  return res.text();
}

export function fetchControls(): Promise<ControlsCatalog> {
  return getJson<ControlsCatalog>("/api/controls");
}

export async function fetchHealth(): Promise<boolean> {
  if (PAGES_BUILD) return false;
  try {
    const res = await fetch(`${API_BASE}/api/health`);
    return res.ok;
  } catch {
    return false;
  }
}
