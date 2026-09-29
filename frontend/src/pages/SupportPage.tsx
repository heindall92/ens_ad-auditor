import { useEffect, useState, type FormEvent } from "react";
import { fetchHealth } from "../api/client";
import Icon from "../components/Icon";
import { useSettings } from "../settings/SettingsContext";
import type { TKey } from "../settings/i18n";
import PageHead from "./PageHead";

// Public project link; override at build time with VITE_REPO_URL.
const REPO_URL: string = import.meta.env.VITE_REPO_URL ?? "https://github.com/heindall92/ens_ad-auditor";
const VERSION = "0.1.0";

type Category = "bug" | "mapping" | "idea";
const CATEGORIES: [Category, TKey][] = [
  ["bug", "sup.cat.bug"],
  ["mapping", "sup.cat.mapping"],
  ["idea", "sup.cat.idea"],
];

interface Props {
  notify: (msg: string) => void;
  scanSummary: string | null;
}

export default function SupportPage({ notify, scanSummary }: Props) {
  const { t } = useSettings();
  const [subject, setSubject] = useState("");
  const [category, setCategory] = useState<Category>("bug");
  const [message, setMessage] = useState("");
  const [attach, setAttach] = useState(true);
  const [invalid, setInvalid] = useState(false);
  const [online, setOnline] = useState<boolean | null>(null);

  useEffect(() => {
    let alive = true;
    fetchHealth().then((ok) => alive && setOnline(ok));
    return () => {
      alive = false;
    };
  }, []);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!subject.trim() || !message.trim()) {
      setInvalid(true);
      return;
    }
    // Demo only: nothing leaves the browser. Confirm and clear the form.
    notify(t("sup.sent", { s: subject.trim() }));
    setSubject("");
    setMessage("");
    setCategory("bug");
    setInvalid(false);
  };

  return (
    <>
      <PageHead id="page-title" eyebrow={t("sup.eyebrow")} title={t("sup.title")} lead={t("sup.lead")} />
      <div className="grid g-main">
        <form className="card support-form" onSubmit={submit} noValidate aria-labelledby="sup-h-form">
          <div className="card-head">
            <h3 id="sup-h-form">{t("sup.formTitle")}</h3>
            <span className="badge neutral">Demo</span>
          </div>
          <div className="form-grid">
            <label className="fld">
              {t("sup.subject")}
              <input
                type="text"
                value={subject}
                maxLength={140}
                required
                aria-invalid={invalid && !subject.trim() ? true : undefined}
                placeholder={t("sup.subjectPh")}
                onChange={(e) => setSubject(e.target.value)}
              />
            </label>
            <label className="fld">
              {t("sup.category")}
              <select value={category} onChange={(e) => setCategory(e.target.value as Category)}>
                {CATEGORIES.map(([v, key]) => (
                  <option key={v} value={v}>
                    {t(key)}
                  </option>
                ))}
              </select>
            </label>
            <label className="fld span2">
              {t("sup.message")}
              <textarea
                className="tall"
                value={message}
                maxLength={4000}
                required
                aria-invalid={invalid && !message.trim() ? true : undefined}
                placeholder={t("sup.messagePh")}
                onChange={(e) => setMessage(e.target.value)}
              />
            </label>
            <label className="switch-l span2">
              <span className="switch">
                <input type="checkbox" checked={attach} onChange={(e) => setAttach(e.target.checked)} />
                <span />
              </span>
              <span>
                {t("sup.attachCtx")}
                {attach && scanSummary && <span className="muted small"> · {scanSummary}</span>}
              </span>
            </label>
          </div>
          {invalid && (
            <p className="form-err" role="alert">
              <Icon name="alert" size={15} />
              {t("sup.required")}
            </p>
          )}
          <div className="form-foot">
            <span className="muted small">{t("sup.formNote")}</span>
            <button type="submit" className="btn primary">
              <Icon name="send" size={15} />
              {t("sup.send")}
            </button>
          </div>
        </form>

        <div className="stack">
          <section className="card" aria-labelledby="sup-h-res">
            <h3 id="sup-h-res">{t("sup.resources")}</h3>
            <ul className="res-list">
              <li>
                <span className="ex-ic sm">
                  <Icon name="code" size={17} />
                </span>
                <span>
                  <a href={REPO_URL} target="_blank" rel="noopener noreferrer">
                    {t("sup.repo")}
                    <Icon name="external" size={13} />
                  </a>
                  <small>{t("sup.repoDesc")}</small>
                </span>
              </li>
              <li>
                <span className="ex-ic sm">
                  <Icon name="server" size={17} />
                </span>
                <span>
                  <b>{t("sup.api")}</b>
                  <small>{t("sup.apiDesc")}</small>
                </span>
              </li>
              <li>
                <span className="ex-ic sm">
                  <Icon name="activity" size={17} />
                </span>
                <span>
                  <b>{t("sup.status")}</b>
                  <small>{t("sup.version", { v: VERSION })}</small>
                </span>
                <span
                  className={`badge ${online === null ? "neutral" : online ? "ok" : "crit"}`}
                  role="status"
                >
                  <span className="dot" />
                  {online === null ? t("sup.checking") : online ? t("sup.online") : t("sup.offline")}
                </span>
              </li>
            </ul>
          </section>

          <section className="alert warn legal-note" aria-labelledby="sup-h-legal">
            <Icon name="alert" size={18} />
            <div>
              <b id="sup-h-legal">{t("sup.legalTitle")}</b>
              <p>{t("sup.legalText")}</p>
              <p className="muted small">{t("sup.legalDemo")}</p>
            </div>
          </section>
        </div>
      </div>
    </>
  );
}
