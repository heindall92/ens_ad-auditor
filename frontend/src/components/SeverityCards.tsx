import { RISK_ORDER, type RiskLevel } from "../types";
import { RISK_TONE } from "../risk";
import { useSettings } from "../settings/SettingsContext";

interface Props {
  counts: Record<RiskLevel, number>;
  total: number;
  active: RiskLevel | null;
  onSelect: (risk: RiskLevel | null) => void;
}

export default function SeverityCards({ counts, total, active, onSelect }: Props) {
  const { t } = useSettings();
  return (
    <div className="sev-cards four" role="group" aria-label={t("sev.aria")}>
      {RISK_ORDER.map((risk) => {
        const n = counts[risk] ?? 0;
        const on = active === risk;
        const pct = total ? Math.round((n / total) * 100) : 0;
        return (
          <button
            key={risk}
            type="button"
            className={`sev-card ${RISK_TONE[risk]}${on ? " on" : ""}${n === 0 ? " zero" : ""}`}
            aria-pressed={on}
            onClick={() => onSelect(on ? null : risk)}
            title={on ? t("sev.clear") : t("sev.only", { r: t(`risk.${risk}`).toLowerCase() })}
          >
            <b className="num">{n}</b>
            <span>{t(`riskPl.${risk}`)}</span>
            <small>{t("sev.pct", { p: pct })}</small>
          </button>
        );
      })}
    </div>
  );
}
