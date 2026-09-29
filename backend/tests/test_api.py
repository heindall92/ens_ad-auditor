"""API contract: no credentials => no findings, is_sample false."""
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
    dumped = res.text.lower()
    assert "corp.example.local" not in dumped
    assert "[demo]" not in dumped


def test_report_without_credentials_is_empty_and_not_sample():
    res = client.get("/api/report.json")
    assert res.status_code == 200
    body = res.json()
    assert body["is_sample"] is False
    assert body["alerts"] == []
    assert "corp.example.local" not in res.text.lower()


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
