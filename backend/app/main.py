"""
ENS AD Auditor — FastAPI application.

Pipeline: enumeration stubs -> ENS mapping engine -> GRC alerts / report.

Endpoints
---------
GET /                 -> service metadata.
GET /api/health       -> health check.
GET /api/controls     -> ENS [op.acc] control catalogue used by the engine.
GET /api/mapping      -> full data-driven mapping knowledge base (rules).
GET /api/scan         -> run stub enumerators, map to ENS, return GRCAlerts.
GET /api/report       -> Markdown GRC report (Content-Type text/markdown).
GET /api/report.json  -> full JSON report.

NOTE: enumeration modules currently return SAMPLE data; no network scanning
is performed. Real scans require explicit written authorization.
"""
from __future__ import annotations

from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware

from app.enumeration import run_all
from app.mapping import ENS_CONTROLS, export_rules, map_findings
from app.models import ScanResponse
from app.report import build_json_report, build_markdown_report, counts_by_risk

app = FastAPI(
    title="ENS AD Auditor",
    description=(
        "Auditor de Active Directory mapeado al ENS (Esquema Nacional de "
        "Seguridad). Traduce hallazgos técnicos a incumplimientos [op.acc]."
    ),
    version="0.1.0",
)

# CORS: allow the Vite dev server (localhost:5173) during development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # scaffold: relax for local dev; tighten in prod.
    allow_methods=["*"],
    allow_headers=["*"],
)


def _run_pipeline():
    """Run enumeration stubs and map findings to ENS GRC alerts."""
    findings = run_all()
    alerts = map_findings(findings)
    return findings, alerts


@app.get("/")
def root():
    return {
        "name": "ENS AD Auditor",
        "version": app.version,
        "description": app.description,
        "endpoints": [
            "/api/health",
            "/api/controls",
            "/api/mapping",
            "/api/scan",
            "/api/report",
            "/api/report.json",
        ],
        "warning": (
            "Datos de demostración. Ejecutar escaneos reales solo con "
            "autorización expresa por escrito."
        ),
    }


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/controls")
def controls():
    """Return the ENS [op.acc] control catalogue used by the mapping engine."""
    return {"family": "op.acc", "controls": ENS_CONTROLS}


@app.get("/api/mapping")
def mapping():
    """Return the ENS mapping rules (finding type -> controls, risk, text)."""
    return {"family": "op.acc", "rules": export_rules()}


@app.get("/api/scan", response_model=ScanResponse)
def scan():
    """Run the stub enumerators and return ENS GRC alerts (sample data)."""
    findings, alerts = _run_pipeline()
    is_sample = any(f.is_sample for f in findings) if findings else True
    return ScanResponse(
        generated_at=build_json_report(alerts, is_sample)["generated_at"],
        is_sample=is_sample,
        total_alerts=len(alerts),
        counts_by_risk=counts_by_risk(alerts),
        alerts=alerts,
    )


@app.get("/api/report", response_class=Response)
def report_markdown():
    """Return a Markdown GRC report."""
    findings, alerts = _run_pipeline()
    is_sample = any(f.is_sample for f in findings) if findings else True
    md = build_markdown_report(alerts, is_sample)
    return Response(content=md, media_type="text/markdown; charset=utf-8")


@app.get("/api/report.json")
def report_json():
    """Return the full JSON report."""
    findings, alerts = _run_pipeline()
    is_sample = any(f.is_sample for f in findings) if findings else True
    return build_json_report(alerts, is_sample)
