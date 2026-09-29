import Icon from "./Icon";
import { coverageCanFilter } from "../coverageFilter";
import { useSettings } from "../settings/SettingsContext";
import type { CoverageCheck } from "../types";

interface Props {
  checks: CoverageCheck[];
  active: string | null;
  onFilter: (id: string) => void;
}

export default function CoveragePanel({ checks, active, onFilter }: Props) {
  const { t } = useSettings();
  return (
    <section className="block" id="cobertura" aria-labelledby="h-cobertura">
      <div className="block-head">
        <h2 id="h-cobertura">{t("coverage.title")}</h2>
        <span className="muted small">{t("coverage.hint")}</span>
      </div>
      <div className="card flush">
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>{t("coverage.colArea")}</th>
                <th>{t("coverage.colStatus")}</th>
                <th>{t("coverage.colDetail")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {checks.map((row) => {
                const done = row.status === "comprobado";
                const blocked = !coverageCanFilter(row.id);
                return (
                  <tr key={row.id} className={active === row.id ? "sel" : undefined}>
                    <td>{row.area}</td>
                    <td>
                      <span className={`badge ${done ? "ok" : "neutral"}`}>
                        {done ? t("coverage.comprobado") : t("coverage.noComprobado")}
                      </span>
                    </td>
                    <td className="cov-detail">{row.detail}</td>
                    <td>
                      <button
                        type="button"
                        className="btn sm"
                        disabled={blocked}
                        title={blocked ? t("coverage.unavailable") : t("coverage.filter")}
                        onClick={() => onFilter(row.id)}
                      >
                        <Icon name={blocked ? "lock" : "target"} size={14} />
                        {blocked ? t("coverage.noComprobado") : t("coverage.filter")}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
      <p className="muted small">{t("coverage.legend")}</p>
    </section>
  );
}
