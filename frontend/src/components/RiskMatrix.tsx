import { RISK_TONE } from "../risk";
import { useSettings } from "../settings/SettingsContext";
import type { MatrixCell, RiskLevel, RiskMatrix } from "../types";

const LEVELS = [5, 4, 3, 2, 1] as const;

function cellAt(cells: MatrixCell[], impact: number, likelihood: number): MatrixCell | undefined {
  return cells.find((c) => c.impact === impact && c.likelihood === likelihood);
}

function tone(risk: RiskLevel | undefined, count: number): string {
  if (!count || !risk) return "";
  return RISK_TONE[risk];
}

interface Props {
  matrix: RiskMatrix;
  scanned: boolean;
}

export default function RiskMatrixGrid({ matrix, scanned }: Props) {
  const { t } = useSettings();

  if (!scanned) {
    return (
      <section className="block" id="matriz" aria-labelledby="h-matriz">
        <div className="block-head">
          <h2 id="h-matriz">{t("matrix.title")}</h2>
          <span className="muted small">{t("matrix.hint")}</span>
        </div>
        <div className="card">
          <div className="empty-state">
            <h3>{t("matrix.emptyTitle")}</h3>
            <p>{t("matrix.emptyText")}</p>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="block" id="matriz" aria-labelledby="h-matriz">
      <div className="block-head">
        <h2 id="h-matriz">{t("matrix.title")}</h2>
        <span className="muted small">{t("matrix.hint")}</span>
      </div>
      {matrix.empty ? (
        <div className="card">
          <div className="empty-state">
            <h3>{t("matrix.cleanTitle")}</h3>
            <p>{t("matrix.cleanText")}</p>
          </div>
        </div>
      ) : (
        <div className="card matrix-wrap">
          <p className="muted small">{t("matrix.axis")}</p>
          <table className="matrix" aria-label={t("matrix.title")}>
            <thead>
              <tr>
                <th scope="col">{t("matrix.impact")}</th>
                {LEVELS.slice().reverse().map((n) => (
                  <th key={n} scope="col">
                    {n}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {LEVELS.map((impact) => (
                <tr key={impact}>
                  <th scope="row">{impact}</th>
                  {LEVELS.slice().reverse().map((likelihood) => {
                    const cell = cellAt(matrix.cells, impact, likelihood);
                    const count = cell?.count ?? 0;
                    return (
                      <td key={likelihood} className={tone(cell?.risk, count)}>
                        {count > 0 ? <b className="num">{count}</b> : <span className="muted">·</span>}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted small">{t("matrix.legend")}</p>
        </div>
      )}
    </section>
  );
}
