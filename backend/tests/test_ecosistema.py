"""yrd-ecosistema envelope: empty is honest, sample findings never leak, alerts travel intact."""
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.ecosistema import FORMATO, HERRAMIENTA, build_ecosistema
from app.main import app
from app.mapping import map_findings
from app.models import Finding, FindingType
from tests.sample_findings import mapping_fixtures

client = TestClient(app)

NOW = datetime(2026, 10, 10, 9, 0, 0, 123456, tzinfo=timezone.utc)


def _live(ftype=FindingType.KERBEROASTING, subtype="rc4"):
    return Finding(
        finding_type=ftype,
        title="SPN con RC4",
        target="svc@lab.test",
        detail="etype 23",
        source_module="enumeration.kerberos",
        subtype=subtype,
        is_sample=False,
    )


def test_empty_envelope_has_valid_header_and_no_data():
    env = build_ecosistema([], domain=None, app_version="0.4.0", now=NOW)
    assert env["format"] == FORMATO == "yrd-ecosistema"
    assert env["version"] == 1
    assert env["tipo"] == "hallazgos"
    assert env["origen"] == {"herramienta": HERRAMIENTA, "version": "0.4.0", "generado": "2026-10-10T09:00:00Z"}
    assert env["datos"] == []
    assert env["resumen"]["is_sample"] is False
    assert env["resumen"]["total_alerts"] == 0


def test_sample_findings_are_skipped():
    alerts = map_findings(mapping_fixtures())
    assert alerts
    env = build_ecosistema(alerts, domain="lab.test")
    assert env["datos"] == []
    assert env["proyecto"] == "lab.test"


def test_live_alert_travels_as_the_json_report_emits_it():
    alerts = map_findings([_live()])
    env = build_ecosistema(alerts, domain="lab.test", app_version="0.4.0", now=NOW)
    assert len(env["datos"]) == 1
    item = env["datos"][0]
    # The fields CTEM-Nexus reads: finding.finding_type/title/target, risk, ens_controls[].id, da_path
    assert item["finding"]["finding_type"] == "kerberoasting"
    assert item["finding"]["target"] == "svc@lab.test"
    assert item["risk"] in {"Critico", "Alto", "Medio", "Bajo"}
    assert any(c["id"].startswith("op.acc.") for c in item["ens_controls"])
    assert isinstance(item["da_path"], bool)
    assert env["resumen"]["domain"] == "lab.test"
    assert sum(env["resumen"]["counts_by_risk"].values()) == 1


def test_http_export_without_credentials_is_empty_envelope():
    res = client.get("/api/export/ecosistema")
    assert res.status_code == 200
    env = res.json()
    assert env["format"] == "yrd-ecosistema" and env["tipo"] == "hallazgos" and env["datos"] == []
    assert env["origen"]["version"] == app.version
    assert "/api/export/ecosistema" in client.get("/").json()["endpoints"]
