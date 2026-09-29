import { useState } from "react";
import Icon from "./Icon";
import type { GRCAlert } from "../types";
import { RISK_FINDING_CLASS, RISK_TONE } from "../risk";
import { useSettings } from "../settings/SettingsContext";

interface Props {
  alert: GRCAlert;
  onControlSelect: (controlId: string) => void;
}

export default function FindingCard({ alert, onControlSelect }: Props) {
  const { t } = useSettings();
  const [open, setOpen] = useState(false);
  const { finding } = alert;
  const bodyId = `f-body-${alert.rule_id}-${finding.target}`.replace(/[^\w-]/g, "_");

  return (
    <article className={`finding ${RISK_FINDING_CLASS[alert.risk]}${open ? " open" : ""}`}>
      <button
        type="button"
        className="f-toggle"
        aria-expanded={open}
        aria-controls={bodyId}
        onClick={() => setOpen((v) => !v)}
      >
        <div className="f-hd">
          <span className={`badge ${RISK_TONE[alert.risk]}`}>
            <span className="dot" />
            {t(`risk.${alert.risk}`)}
          </span>
          <code className="muted">{alert.rule_id}</code>
          <span className="chip" title={t("f.magerit", { i: alert.impact, l: alert.likelihood, s: alert.score })}>
            {alert.impact}×{alert.likelihood}
          </span>
          {alert.da_path && <span className="badge crit">{t("f.daPath")}</span>}
          <span className="chips">
            {alert.ens_controls.map((c) => (
              <span
                key={c.id}
                className={`chip${c.is_primary ? " accent" : ""}`}
                title={`${c.name}${c.is_primary ? ` ${t("f.primarySuffix")}` : ""}`}
              >
                {c.id}
              </span>
            ))}
          </span>
          <span className="f-chev" aria-hidden="true">
            <Icon name="chevronDown" size={16} />
          </span>
        </div>
        <b className="f-t">{finding.title}</b>
        <span className="f-meta">
          <code>{finding.target}</code>
          <span>·</span>
          <span>{finding.source_module}</span>
          {finding.subtype && (
            <>
              <span>·</span>
              <span>{finding.subtype}</span>
            </>
          )}
        </span>
      </button>

      <p className="f-d">
        <b>{t("f.nonCompliance")}</b> {alert.non_compliance}
      </p>

      {open && (
        <div className="f-body" id={bodyId}>
          <div className="f-col">
            <section className="f-sec">
              <h4>{t("f.detail")}</h4>
              <p>{finding.detail}</p>
              {finding.evidence && <pre className="code">{finding.evidence}</pre>}
            </section>
            {alert.rationale && (
              <section className="f-sec">
                <h4>{t("f.rationale")}</h4>
                <p>{alert.rationale}</p>
              </section>
            )}
          </div>
          <div className="f-col">
            <section className="f-sec">
              <h4>{t("f.controls")}</h4>
              <ul className="plain">
                {alert.ens_controls.map((c) => (
                  <li key={c.id}>
                    <button
                      type="button"
                      className="code-chip"
                      onClick={() => onControlSelect(c.id)}
                      title={t("f.filterByControl")}
                    >
                      {c.id}
                    </button>
                    <span>{c.name}</span>
                    {c.is_primary && <span className="badge accent">{t("f.primary")}</span>}
                  </li>
                ))}
              </ul>
            </section>
            <section className="f-sec">
              <h4>{t("f.remediation")}</h4>
              <p className="f-r box">
                <Icon name="arrowRight" size={14} />
                <span>{alert.remediation}</span>
              </p>
            </section>
            {alert.references.length > 0 && (
              <section className="f-sec">
                <h4>{t("f.references")}</h4>
                <ul className="f-refs">
                  {alert.references.map((r) => (
                    <li key={r} className="f-ref">
                      {r}
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </div>
        </div>
      )}
    </article>
  );
}
