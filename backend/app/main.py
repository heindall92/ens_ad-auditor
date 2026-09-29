"""
ENS AD Auditor — FastAPI application.

Pipeline: live enumeration (when credentials are posted) -> ENS mapping -> GRC alerts.

Endpoints
---------
GET  /                 -> service metadata.
GET  /api/health       -> health check.
GET  /api/controls     -> ENS [op.acc] control catalogue used by the engine.
GET  /api/mapping      -> full data-driven mapping knowledge base (rules).
GET  /api/scan         -> empty result (no credentials: no findings).
POST /api/audit        -> live enumeration with credentials supplied in the body.
GET  /api/report       -> Markdown report of the empty scan.
POST /api/report       -> Markdown report of a live audit.
GET  /api/report.json  -> JSON report of the empty scan.
POST /api/report.json  -> JSON report of a live audit.

Credentials are used only for the request and are never written to disk.
Live enumeration is read-only (Kerberos/delegation/AD CS/SMB configuration).
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware

from app.enumeration import AuditConnectionError, run_all
from app.enumeration.coverage import empty_coverage
from app.enumeration.target import AuditTarget
from app.mapping import (
    ENS_CONTROLS,
    build_matrix,
    build_summary,
    export_rules,
    map_findings,
)
from app.models import AuditRequest, DomainSummary, RiskMatrix, ScanResponse
from app.report import build_json_report, build_markdown_report, counts_by_risk

app = FastAPI(
    title="ENS AD Auditor",
    description=(
        "Auditor de Active Directory mapeado al ENS (Esquema Nacional de "
        "Seguridad). Traduce hallazgos técnicos a incumplimientos [op.acc]. "
        "Solo para auditorías con autorización expresa por escrito."
    ),
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _empty_scan() -> ScanResponse:
    coverage = empty_coverage()
    return ScanResponse(
        generated_at=build_json_report([], is_sample=False, coverage=coverage)["generated_at"],
        is_sample=False,
        scanned=False,
        total_alerts=0,
        counts_by_risk=counts_by_risk([]),
        alerts=[],
        domain=None,
        dc_host=None,
        errors=[],
        matrix=RiskMatrix(empty=True, cells=[]),
        summary=DomainSummary(),
        coverage=coverage,
    )


def _run_live(req: AuditRequest) -> ScanResponse:
    target = AuditTarget.from_request(req)
    try:
        findings, errors, coverage = run_all(target)
    except AuditConnectionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    alerts = map_findings(findings)
    matrix = build_matrix(alerts)
    summary = build_summary(alerts)
    payload = build_json_report(
        alerts,
        is_sample=False,
        domain=target.domain,
        errors=errors,
        matrix=matrix,
        summary=summary,
        coverage=coverage,
    )
    return ScanResponse(
        generated_at=payload["generated_at"],
        is_sample=False,
        scanned=True,
        total_alerts=len(alerts),
        counts_by_risk=counts_by_risk(alerts),
        alerts=alerts,
        domain=target.domain,
        dc_host=target.dc_host,
        errors=errors,
        matrix=matrix,
        summary=summary,
        coverage=coverage,
    )


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
            "/api/audit",
            "/api/report",
            "/api/report.json",
        ],
        "warning": (
            "Solo auditorías autorizadas por escrito. Sin credenciales la API "
            "no inventa hallazgos."
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
    """No credentials: empty alert list. Never fabricates findings."""
    return _empty_scan()


@app.post("/api/audit", response_model=ScanResponse)
def audit(req: AuditRequest):
    """Run live enumeration against the supplied domain controller."""
    return _run_live(req)


@app.get("/api/report", response_class=Response)
def report_markdown_empty():
    md = build_markdown_report([], is_sample=False, coverage=empty_coverage())
    return Response(content=md, media_type="text/markdown; charset=utf-8")


@app.post("/api/report", response_class=Response)
def report_markdown_live(req: AuditRequest):
    result = _run_live(req)
    md = build_markdown_report(
        result.alerts,
        is_sample=False,
        domain=result.domain,
        errors=result.errors,
        matrix=result.matrix,
        summary=result.summary,
        coverage=result.coverage,
    )
    return Response(content=md, media_type="text/markdown; charset=utf-8")


@app.get("/api/report.json")
def report_json_empty():
    return build_json_report([], is_sample=False, coverage=empty_coverage())


@app.post("/api/report.json")
def report_json_live(req: AuditRequest):
    result = _run_live(req)
    return build_json_report(
        result.alerts,
        is_sample=False,
        domain=result.domain,
        errors=result.errors,
        matrix=result.matrix,
        summary=result.summary,
        coverage=result.coverage,
    )
