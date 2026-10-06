"""Studio evidencia adapter: empty is honest; no sample findings leak."""
from fastapi.testclient import TestClient

from app.main import app
from app.mapping import map_findings
from app.models import Finding, FindingType, RiskLevel
from app.studio_evidencia import ACTIVO_ID, CATEGORIA_POR_TIPO, build_studio_evidencia
from tests.sample_findings import mapping_fixtures

client = TestClient(app)


def test_empty_payload_is_not_sample_and_has_no_alerts():
    payload = build_studio_evidencia([], domain=None)
    assert payload["is_sample"] is False
    assert payload["hallazgos"] == []
    assert payload["dominio"] is None
    assert payload["activo_sugerido"]["id"] == ACTIVO_ID
    blob = str(payload).lower()
    assert "corp.example.local" not in blob
    assert "[demo]" not in blob
    assert "demostración" not in blob


def test_sample_findings_are_skipped():
    alerts = map_findings(mapping_fixtures())
    assert alerts
    payload = build_studio_evidencia(alerts, domain="lab.test")
    assert payload["is_sample"] is False
    assert payload["hallazgos"] == []
    assert payload["dominio"] == "lab.test"


def test_live_alert_maps_to_known_studio_category():
    finding = Finding(
        finding_type=FindingType.KERBEROASTING,
        title="SPN con RC4",
        target="svc@lab.test",
        detail="etype 23",
        source_module="enumeration.kerberos",
        subtype="rc4",
        is_sample=False,
    )
    alerts = map_findings([finding])
    payload = build_studio_evidencia(alerts, domain="lab.test")
    assert payload["is_sample"] is False
    assert len(payload["hallazgos"]) == 1
    item = payload["hallazgos"][0]
    assert item["categoria"] == CATEGORIA_POR_TIPO[FindingType.KERBEROASTING]
    assert item["activoId"] == ACTIVO_ID
    assert item["cvss"] == 7.5
    assert item["estado"] == "abierto"
    assert "op.acc." in ",".join(item["ens"])
    assert item["objetivo"] == "svc@lab.test"


def test_every_finding_type_has_a_studio_category():
    for ftype in FindingType:
        assert ftype in CATEGORIA_POR_TIPO


def test_cvss_follows_ens_risk_band():
    finding = Finding(
        finding_type=FindingType.UNCONSTRAINED_DELEGATION,
        title="Delegación no restringida",
        target="APP$@lab.test",
        detail="TRUSTED_FOR_DELEGATION",
        source_module="enumeration.delegation",
        is_sample=False,
    )
    alerts = map_findings([finding])
    payload = build_studio_evidencia(alerts, domain="lab.test")
    item = payload["hallazgos"][0]
    if alerts[0].risk is RiskLevel.CRITICO:
        assert item["cvss"] == 9.0
    elif alerts[0].risk is RiskLevel.ALTO:
        assert item["cvss"] == 7.5


def test_http_export_without_credentials_is_empty():
    res = client.get("/api/export/studio")
    assert res.status_code == 200
    body = res.json()
    assert body["is_sample"] is False
    assert body["hallazgos"] == []
    assert body["dominio"] is None
    text = res.text.lower()
    assert "corp.example.local" not in text
    assert "[demo]" not in text
    assert "demostración" not in text
