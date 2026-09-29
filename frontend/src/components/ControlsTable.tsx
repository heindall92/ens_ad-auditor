import { RISK_ORDER, type GRCAlert, type RiskLevel } from "../types";
import { RISK_TONE } from "../risk";
import { useSettings } from "../settings/SettingsContext";

export interface ControlStat {
  id: string;
  name: string;
  alerts: number;
  primary: number;
  maxRisk: RiskLevel | null;
}

// Aggregate per-control stats. `catalog` (from /api/controls) lists every
// op.acc control; controls only seen in alerts are appended.
export function buildControlStats(
  alerts: GRCAlert[],
  catalog: Record<string, string> | null,
): ControlStat[] {
  const map = new Map<string, ControlStat>();
  if (catalog) {
    for (const [id, name] of Object.entries(catalog)) {
      map.set(id, { id, name, alerts: 0, primary: 0, maxRisk: null });
    }
  }
  for (const a of alerts) {
    for (const c of a.ens_controls) {
      const s = map.get(c.id) ?? { id: c.id, name: c.name, alerts: 0, primary: 0, maxRisk: null };
      s.alerts += 1;
      if (c.is_primary) s.primary += 1;
      if (s.maxRisk === null || RISK_ORDER.indexOf(a.risk) < RISK_ORDER.indexOf(s.maxRisk)) {
        s.maxRisk = a.risk;
      }
      map.set(c.id, s);
    }
  }
  const num = (id: string) => Number(id.split(".").pop()) || 0;
  return [...map.values()].sort((x, y) => num(x.id) - num(y.id) || x.id.localeCompare(y.id));
}

interface Props {
  stats: ControlStat[];
  totalAlerts: number;
  selected: string | null;
  onSelect: (id: string | null) => void;
}

export default function ControlsTable({ stats, totalAlerts, selected, onSelect }: Props) {
  const { t } = useSettings();
  const max = Math.max(1, ...stats.map((s) => s.alerts));
  return (
    <div className="table-wrap">
      <table className="tbl">
        <thead>
          <tr>
            <th>{t("ct.control")}</th>
            <th>{t("ct.name")}</th>
            <th>{t("ct.alerts")}</th>
            <th className="c">{t("ct.asPrimary")}</th>
            <th>{t("ct.maxRisk")}</th>
          </tr>
        </thead>
        <tbody>
          {stats.map((s) => (
            <tr
              key={s.id}
              className={`${s.alerts === 0 ? "idle" : ""}${selected === s.id ? " sel" : ""}`.trim() || undefined}
            >
              <td>
                {s.alerts > 0 ? (
                  <button
                    type="button"
                    className="code-chip"
                    onClick={() => onSelect(selected === s.id ? null : s.id)}
                    title={t("f.filterByControl")}
                  >
                    {s.id}
                  </button>
                ) : (
                  <span className="chip">{s.id}</span>
                )}
              </td>
              <td className="t-strong">{s.name}</td>
              <td>
                <div className="bar-cell" title={t("ct.barTitle", { n: s.alerts, t: totalAlerts })}>
                  <span className="bar">
                    <i style={{ width: `${(s.alerts / max) * 100}%` }} />
                  </span>
                  <span className="num">{s.alerts}</span>
                </div>
              </td>
              <td className="c num">{s.primary}</td>
              <td>
                {s.maxRisk ? (
                  <span className={`badge ${RISK_TONE[s.maxRisk]}`}>{t(`risk.${s.maxRisk}`)}</span>
                ) : (
                  <span className="badge ok">{t("ct.none")}</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
