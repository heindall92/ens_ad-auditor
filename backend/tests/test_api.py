"""API contract: no credentials => no findings. Never fabricates data."""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_scan_without_credentials_is_empty_and_not_sample():
    res = client.get("/api/scan")
    assert res.status_code == 200
    body = res.json()
    assert body["is_sample"] is False
    assert body["scanned"] is False
    assert body["alerts"] == []
    assert body["total_alerts"] == 0
    assert body["domain"] is None
    assert body["matrix"]["empty"] is True
    assert body["matrix"]["cells"] == []
    assert body["summary"]["total_alerts"] == 0
    assert body["summary"]["da_path"] is False
    assert body["coverage"]
    assert {row["status"] for row in body["coverage"]} == {"no_comprobado"}
    assert {row["id"] for row in body["coverage"]} >= {"tiering", "entra", "acl", "gpo", "secretos"}
    dumped = res.text.lower()
    assert "corp.example.local" not in dumped
    assert "[demo]" not in dumped
    assert "demostración" not in dumped
    assert "demo data" not in dumped


def test_report_without_credentials_is_empty_and_not_sample():
    res = client.get("/api/report.json")
    assert res.status_code == 200
    body = res.json()
    assert body["is_sample"] is False
    assert body["alerts"] == []
    assert body["coverage"]
    assert all(row["status"] == "no_comprobado" for row in body["coverage"])
    assert "corp.example.local" not in res.text.lower()
    md = client.get("/api/report")
    assert md.status_code == 200
    text = md.text.lower()
    assert "[demo]" not in text
    assert "demostración" not in text
    assert "datos de muestra" not in text
    assert "no comprobado" in text
    assert "comprobado y limpio" not in text
    assert "matriz está vacía" in text


def test_audit_requires_authorisation():
    res = client.post(
        "/api/audit",
        json={
            "domain": "example.test",
            "dc_host": "dc.example.test",
            "username": "auditor",
            "password": "x",
            "authorized": False,
        },
    )
    assert res.status_code == 422


def test_audit_requires_secret():
    res = client.post(
        "/api/audit",
        json={
            "domain": "example.test",
            "dc_host": "dc.example.test",
            "username": "auditor",
            "authorized": True,
        },
    )
    assert res.status_code == 422


def test_root_has_no_demo_wording():
    res = client.get("/")
    assert res.status_code == 200
    text = res.text.lower()
    assert "demostración" not in text
    assert "[demo]" not in text
    assert "autorizadas por escrito" in text


def test_mapping_exposes_magerit_factors():
    res = client.get("/api/mapping")
    assert res.status_code == 200
    rules = res.json()["rules"]
    assert rules
    for rule in rules:
        assert 1 <= rule["impact"] <= 5
        assert 1 <= rule["likelihood"] <= 5
        assert "da_path" in rule
        assert "magerit_risk" in rule


def test_markdown_with_domain_and_no_alerts_is_checked_clean():
    from app.models import CoverageCheck
    from app.report import build_markdown_report

    coverage = [
        CoverageCheck(id="kerberos", area="Kerberos", status="comprobado", detail="leído"),
        CoverageCheck(
            id="tiering",
            area="Tiering",
            status="no_comprobado",
            detail="sin equipo de inicio de sesión",
        ),
    ]
    md = build_markdown_report([], domain="lab.test", coverage=coverage).lower()
    assert "comprobado y limpio" in md
    assert "no se han inventado" in md
    assert "no comprobado" in md
    assert "tiering" in md
