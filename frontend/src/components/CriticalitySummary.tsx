import Icon from "./Icon";
import { RISK_TONE } from "../risk";
import { useSettings } from "../settings/SettingsContext";
import type { DomainSummary } from "../types";

interface Props {
  summary: DomainSummary;
  scanned: boolean;
}

export default function CriticalitySummary({ summary, scanned }: Props) {
  const { t } = useSettings();
  if (!scanned) return null;

  return (
    <div className="kpi-grid crit-summary">
      <div className="kpi">
        <span className="kpi-l">
          <Icon name="alert" size={16} />
          {t("sum.highest")}
        </span>
        <span className="kpi-v">
          {summary.highest_risk ? (
            <span className={`badge ${RISK_TONE[summary.highest_risk]}`}>
              <span className="dot" />
              {t(`risk.${summary.highest_risk}`)}
            </span>
          ) : (
            t("pf.none")
          )}
        </span>
        <span className="kpi-s">{t("sum.highestSub")}</span>
      </div>
      <div className="kpi">
        <span className="kpi-l">
          <Icon name="shieldCheck" size={16} />
          {t("sum.controls")}
        </span>
        <span className="kpi-v num">{summary.controls_hit}</span>
        <span className="kpi-s">{t("sum.controlsSub")}</span>
      </div>
      <div className={`kpi${summary.da_path ? " alert" : ""}`}>
        <span className="kpi-l">
          <Icon name="flag" size={16} />
          {t("sum.da")}
        </span>
        <span className="kpi-v">{summary.da_path ? t("sum.daYes") : t("sum.daNo")}</span>
        <span className="kpi-s">{t("sum.daSub", { n: summary.da_path_count })}</span>
      </div>
    </div>
  );
}
