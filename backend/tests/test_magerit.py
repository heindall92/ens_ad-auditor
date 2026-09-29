"""MAGERIT matrix math and empty-audit contract."""
from app.mapping import build_matrix, build_summary, level_from_factors, map_findings, score
from app.mapping.ens_mapping import ENS_MAPPING
from app.models import Finding, FindingType, RiskLevel
from tests.sample_findings import mapping_fixtures


def test_score_is_product():
    assert score(5, 4) == 20
    assert score(1, 1) == 1


def test_bands():
    assert level_from_factors(5, 4) is RiskLevel.CRITICO  # 20
    assert level_from_factors(4, 4) is RiskLevel.CRITICO  # 16
    assert level_from_factors(5, 3) is RiskLevel.ALTO  # 15
    assert level_from_factors(4, 3) is RiskLevel.ALTO  # 12
    assert level_from_factors(3, 3) is RiskLevel.MEDIO  # 9
    assert level_from_factors(2, 3) is RiskLevel.MEDIO  # 6
    assert level_from_factors(1, 4) is RiskLevel.BAJO  # 4
    assert level_from_factors(2, 2) is RiskLevel.BAJO  # 4


def test_every_rule_magerit_matches_declared_ens_risk():
    for ftype, rule in ENS_MAPPING.items():
        derived = level_from_factors(int(rule["impact"]), int(rule["likelihood"]))
        assert derived is rule["risk"], f"{ftype}: {derived} != {rule['risk']}"


def test_matrix_empty_without_alerts():
    matrix = build_matrix([])
    assert matrix.empty is True
    assert matrix.cells == []
    summary = build_summary([])
    assert summary.total_alerts == 0
    assert summary.da_path is False
    assert summary.controls_hit == 0
    assert summary.highest_risk is None


def test_matrix_counts_only_returned_findings():
    alerts = map_findings(mapping_fixtures())
    matrix = build_matrix(alerts)
    assert matrix.empty is False
    assert sum(c.count for c in matrix.cells) == len(alerts)
    summary = build_summary(alerts)
    assert summary.total_alerts == len(alerts)
    assert summary.controls_hit > 0
    assert summary.highest_risk is RiskLevel.CRITICO
    assert summary.da_path is True


def test_mapped_alert_risk_follows_magerit_product():
    alerts = map_findings(mapping_fixtures())
    assert alerts
    for alert in alerts:
        assert alert.risk is level_from_factors(alert.impact, alert.likelihood)
        assert alert.score == score(alert.impact, alert.likelihood)


def test_da_path_on_admin_spn():
    alerts = map_findings(
        [
            Finding(
                finding_type=FindingType.ADMIN_WITH_SPN,
                title="admin SPN",
                target="da@lab.test",
                detail="adminCount=1 SPN",
                source_module="enumeration.policy",
            )
        ]
    )
    assert alerts[0].da_path is True
    assert alerts[0].risk is RiskLevel.CRITICO
    assert build_summary(alerts).da_path is True
