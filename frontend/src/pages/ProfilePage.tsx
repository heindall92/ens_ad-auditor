import AccentSwatches from "../components/AccentSwatches";
import Icon from "../components/Icon";
import LangSwitch from "../components/LangSwitch";
import ThemeSeg from "../components/ThemeSeg";
import type { PageId, SectionId } from "../components/Sidebar";
import { RISK_TONE } from "../risk";
import { useSettings } from "../settings/SettingsContext";
import { RISK_ORDER, type RiskLevel, type ScanResponse } from "../types";
import PageHead from "./PageHead";

interface Props {
  data: ScanResponse | null;
  affectedControls: number;
  totalControls: number | null;
  domain: string;
  generatedAt: string | null;
  onNavigate: (section: SectionId, risk?: RiskLevel | null) => void;
  onOpenPage: (page: PageId) => void;
}

export default function ProfilePage(props: Props) {
  const { t } = useSettings();
  const { data } = props;
  const topRisk = data ? RISK_ORDER.find((r) => (data.counts_by_risk[r] ?? 0) > 0) ?? null : null;

  return (
    <>
      <PageHead id="page-title" title={t("pf.title")} lead={t("pf.lead")} />
      <div className="grid g-side">
        <div className="card profile-card">
          <span className="avatar c-teal" style={{ ["--s" as string]: "88px" }} aria-hidden="true">
            YR
          </span>
          <h2>Yoandy Ramírez Delgado</h2>
          <p className="muted">{t("user.role")}</p>
          <p className="small">ENS AD Auditor · {t("brand.sub")}</p>
          <AccentSwatches />
          <p className="muted small">{t("pf.accentNote")}</p>
          <div className="pf-stats">
            <div>
              <b className="num">{data?.total_alerts ?? 0}</b>
              <span>{t("pf.findings")}</span>
            </div>
            <div>
              <b className={`num${(data?.counts_by_risk.Critico ?? 0) > 0 ? " crit-t" : ""}`}>
                {data?.counts_by_risk.Critico ?? 0}
              </b>
              <span>{t("pf.critical")}</span>
            </div>
            <div>
              <b className="num">
                {props.affectedControls}
                {props.totalControls !== null && <small>/{props.totalControls}</small>}
              </b>
              <span>{t("pf.controls")}</span>
            </div>
          </div>
        </div>

        <div className="stack">
          <section className="card" aria-labelledby="pf-h-quick">
            <div className="card-head">
              <h3 id="pf-h-quick">{t("pf.quick")}</h3>
              <button type="button" className="btn sm ghost" onClick={() => props.onOpenPage("ajustes")}>
                <Icon name="sliders" size={15} />
                {t("pf.allSettings")}
              </button>
            </div>
            <div className="set-row first">
              <div>
                <b>{t("set.theme")}</b>
              </div>
              <div className="set-ctl">
                <ThemeSeg />
              </div>
            </div>
            <div className="set-row">
              <div>
                <b>{t("set.lang")}</b>
              </div>
              <div className="set-ctl">
                <LangSwitch />
              </div>
            </div>
          </section>

          <section className="card" aria-labelledby="pf-h-scan">
            <div className="card-head">
              <h3 id="pf-h-scan">{t("pf.scan")}</h3>
            </div>
            {data ? (
              <>
                <dl className="kv">
                  <dt>{t("pf.domain")}</dt>
                  <dd>
                    <code>{props.domain}</code>
                  </dd>
                  <dt>{t("pf.generated")}</dt>
                  <dd>{props.generatedAt ?? t("pf.none")}</dd>
                  <dt>{t("pf.type")}</dt>
                  <dd>{data.scanned ? t("pf.typeReal") : t("pf.typeIdle")}</dd>
                  <dt>{t("pf.topRisk")}</dt>
                  <dd>
                    {topRisk ? (
                      <span className={`badge ${RISK_TONE[topRisk]}`}>
                        <span className="dot" />
                        {t(`risk.${topRisk}`)}
                      </span>
                    ) : (
                      t("pf.none")
                    )}
                  </dd>
                </dl>
                <div className="row pf-actions">
                  <button type="button" className="btn" onClick={() => props.onNavigate("hallazgos", null)}>
                    <Icon name="target" size={16} />
                    {t("pf.goFindings")}
                  </button>
                  <button type="button" className="btn" onClick={() => props.onNavigate("informe")}>
                    <Icon name="fileCheck" size={16} />
                    {t("pf.goReport")}
                  </button>
                </div>
              </>
            ) : (
              <p className="muted small">{t("pf.noScan")}</p>
            )}
          </section>
        </div>
      </div>
    </>
  );
}
