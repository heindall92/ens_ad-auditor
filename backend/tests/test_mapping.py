"""Sanity tests for the ENS mapping engine (run: python -m pytest -q)."""
from app.enumeration import run_all
from app.mapping import ENS_CONTROLS, ENS_MAPPING, SUBTYPE_OVERRIDES, map_findings
from app.models import FindingType
from tests.sample_findings import mapping_fixtures


def test_every_finding_type_has_a_rule():
    for ftype in FindingType:
        assert ftype in ENS_MAPPING, f"Missing ENS rule for {ftype}"


def test_rules_only_reference_known_op_acc_controls():
    rules = list(ENS_MAPPING.values()) + [
        o for subs in SUBTYPE_OVERRIDES.values() for o in subs.values()
    ]
    for rule in rules:
        for cid, _ in rule.get("controls", []):
            assert cid in ENS_CONTROLS


def test_each_rule_has_exactly_one_primary_control():
    for ftype, rule in ENS_MAPPING.items():
        assert sum(1 for _, p in rule["controls"] if p) == 1, ftype


def test_pipeline_sorts_fixture_alerts_by_risk():
    alerts = map_findings(mapping_fixtures())
    assert alerts, "mapping fixtures should yield alerts"
    orders = [a.risk.order for a in alerts]
    assert orders == sorted(orders, reverse=True)


def test_adcs_subtype_override_applied():
    alerts = {a.rule_id: a for a in map_findings(mapping_fixtures())}
    assert "adcs_esc:ESC8" in alerts
    assert "ESC8" in alerts["adcs_esc:ESC8"].non_compliance
    assert any(c.id == "op.acc.7" for c in alerts["adcs_esc:ESC8"].ens_controls)


def test_magerit_factors_present_on_every_rule():
    for ftype, rule in ENS_MAPPING.items():
        assert 1 <= rule["impact"] <= 5, ftype
        assert 1 <= rule["likelihood"] <= 5, ftype
        assert "da_path" in rule


def test_run_all_without_target_is_empty():
    findings, errors, coverage = run_all()
    assert findings == []
    assert errors == []
    assert coverage
    assert all(item.status == "no_comprobado" for item in coverage)
