import { useMemo, useState } from "react";
import Icon, { type IconName } from "../components/Icon";
import type { SectionId } from "../components/Sidebar";
import { useSettings } from "../settings/SettingsContext";
import type { TKey } from "../settings/i18n";
import { HELP_CONTENT, type FlowNode } from "./helpContent";
import PageHead from "./PageHead";

type Tab = "flow" | "glossary" | "faq" | "about";

const SUITE: {
  id: "here" | "studio" | "rosetta" | "kairos";
  name: string;
  descKey: TKey;
  app?: string;
  repo: string;
}[] = [
  {
    id: "here",
    name: "ENS AD Auditor",
    descKey: "help.suite.here",
    repo: "https://github.com/heindall92/ens_ad-auditor",
  },
  {
    id: "studio",
    name: "ENS Compliance Studio",
    descKey: "help.suite.studio",
    app: "https://heindall92.github.io/grc_ens_compliance_studio/app/dist/ens-compliance-studio.html",
    repo: "https://github.com/heindall92/grc_ens_compliance_studio",
  },
  {
    id: "rosetta",
    name: "Rosetta",
    descKey: "help.suite.rosetta",
    app: "https://heindall92.github.io/rosetta_multinorma/",
    repo: "https://github.com/heindall92/rosetta_multinorma",
  },
  {
    id: "kairos",
    name: "KAIROS",
    descKey: "help.suite.kairos",
    app: "https://heindall92.github.io/kairos/",
    repo: "https://github.com/heindall92/kairos",
  },
];

const TABS: [Tab, TKey, IconName][] = [
  ["flow", "help.tab.flow", "layers"],
  ["glossary", "help.tab.glossary", "book"],
  ["faq", "help.tab.faq", "help"],
  ["about", "help.tab.about", "info"],
];

function Node({ node, big = false, size = 18 }: { node: FlowNode; big?: boolean; size?: number }) {
  return (
    <div className={`fnode${big ? " big" : ""}`}>
      <Icon name={node.icon} size={size} />
      <b>{node.title}</b>
      <small>{node.sub}</small>
    </div>
  );
}

interface Props {
  onGo: (section: SectionId) => void;
}

export default function HelpPage({ onGo }: Props) {
  const { t, lang } = useSettings();
  const c = HELP_CONTENT[lang];
  const [tab, setTab] = useState<Tab>("flow");
  const [q, setQ] = useState("");

  const glossary = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return needle
      ? c.glossary.filter(([a, b]) => `${a} ${b}`.toLowerCase().includes(needle))
      : c.glossary;
  }, [c, q]);

  const titleKey = TABS.find(([id]) => id === tab)![1];

  return (
    <>
      <PageHead id="page-title" title={t("help.title")} lead={t("help.lead")} />
      <div className="help-layout">
        <nav className="help-nav" aria-label={t("help.tabs")}>
          {TABS.map(([id, key, ic]) => (
            <button
              key={id}
              type="button"
              aria-current={tab === id ? "page" : undefined}
              onClick={() => setTab(id)}
            >
              <Icon name={ic} size={16} />
              {t(key)}
            </button>
          ))}
        </nav>

        <div className="card help-body">
          <h2>{t(titleKey)}</h2>

          {tab === "flow" && (
            <>
              <div className="flow" role="img" aria-label={t("help.flowAria")}>
                <div className="flow-col">
                  {c.flowIn.map((n) => (
                    <Node key={n.title} node={n} />
                  ))}
                </div>
                <div className="flow-arrow">
                  <Icon name="arrowRight" size={22} />
                </div>
                <div className="flow-col mid">
                  <Node node={c.flowCore} big size={22} />
                </div>
                <div className="flow-arrow">
                  <Icon name="arrowRight" size={22} />
                </div>
                <div className="flow-col">
                  {c.flowOut.map((n) => (
                    <Node key={n.title} node={n} />
                  ))}
                </div>
              </div>

              <h4 className="help-sub">{c.stepsTitle}</h4>
              <ol className="steps">
                {c.steps.map((s, i) => (
                  <li key={s.title}>
                    <span className="step-n">{i + 1}</span>
                    <div>
                      <b>{s.title}</b>
                      <p>{s.text}</p>
                    </div>
                    <button type="button" className="btn sm ghost" onClick={() => onGo(s.go)}>
                      {t("help.go")}
                      <Icon name="arrowRight" size={15} />
                    </button>
                  </li>
                ))}
              </ol>

              <div className="grid g3 help-notes">
                {c.notes.map((n) => (
                  <div key={n.title} className="card soft">
                    <h4>{n.title}</h4>
                    <p className="small">{n.text}</p>
                  </div>
                ))}
              </div>
            </>
          )}

          {tab === "glossary" && (
            <>
              <input
                type="search"
                className="w-full glossary-q"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder={t("help.search")}
                aria-label={t("help.search")}
              />
              {glossary.length > 0 ? (
                <dl className="glossary">
                  {glossary.map(([term, def]) => (
                    <div key={term}>
                      <dt>{term}</dt>
                      <dd>{def}</dd>
                    </div>
                  ))}
                </dl>
              ) : (
                <p className="muted">{t("help.noResults")}</p>
              )}
            </>
          )}

          {tab === "faq" && (
            <div className="faq">
              {c.faq.map(([question, answer]) => (
                <details key={question}>
                  <summary>{question}</summary>
                  <p>{answer}</p>
                </details>
              ))}
            </div>
          )}

          {tab === "about" && (
            <>
              <div className="about">
                {c.about.map((p, i) => (
                  <p key={i} className={i === 0 ? "about-lead" : undefined}>
                    {p}
                  </p>
                ))}
              </div>
              <section className="suite" aria-labelledby="suite-h">
                <h3 id="suite-h">{t("help.suite.title")}</h3>
                <p className="muted small">{t("help.suite.lead")}</p>
                <div className="suite-grid">
                  {SUITE.map((tool) => (
                    <article key={tool.id} className={`suite-card${tool.id === "here" ? " here" : ""}`}>
                      <div className="suite-hd">
                        <b>{tool.name}</b>
                        {tool.id === "here" && <span className="badge accent">{t("help.suite.hereBadge")}</span>}
                      </div>
                      <p>{t(tool.descKey)}</p>
                      <div className="row">
                        {tool.app && (
                          <a className="btn sm" href={tool.app} target="_blank" rel="noopener noreferrer">
                            <Icon name="external" size={14} />
                            {t("help.suite.open")}
                          </a>
                        )}
                        <a className="btn sm" href={tool.repo} target="_blank" rel="noopener noreferrer">
                          <Icon name="code" size={14} />
                          {t("help.suite.code")}
                        </a>
                      </div>
                    </article>
                  ))}
                </div>
              </section>
            </>
          )}
        </div>
      </div>
    </>
  );
}
