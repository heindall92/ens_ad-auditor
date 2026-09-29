import type { ControlsCatalog, ScanResponse } from "../types";

// Relative by default (Vite dev proxy -> FastAPI). Override with VITE_API_BASE
// (e.g. "http://127.0.0.1:8000") when serving the built bundle elsewhere.
const API_BASE: string = import.meta.env.VITE_API_BASE ?? "";

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) {
    throw new Error(`Error ${res.status} al consultar ${path}`);
  }
  return (await res.json()) as T;
}

export function fetchScan(): Promise<ScanResponse> {
  return getJson<ScanResponse>("/api/scan");
}

export async function fetchMarkdownReport(): Promise<string> {
  const res = await fetch(`${API_BASE}/api/report`);
  if (!res.ok) {
    throw new Error(`Error ${res.status} al generar el informe`);
  }
  return res.text();
}

export function fetchControls(): Promise<ControlsCatalog> {
  return getJson<ControlsCatalog>("/api/controls");
}

// GET /api/health: liveness probe used by the Support page.
export async function fetchHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/api/health`);
    return res.ok;
  } catch {
    return false;
  }
}
