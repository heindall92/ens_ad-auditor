import { useEffect, useState } from "react";
import type { RiskLevel } from "../types";
import { useSettings } from "../settings/SettingsContext";
import Icon, { type IconName } from "./Icon";
import type { PageId, SectionId, View } from "./Sidebar";

interface Props {
  view: View;
  section: SectionId;
  riskFilter: RiskLevel | null;
  total: number;
  critical: number;
  onNavigate: (section: SectionId, risk?: RiskLevel | null) => void;
  onOpenPage: (page: PageId) => void;
}

function Badge({ n, tone }: { n: number; tone: "warn" | "crit" }) {
  if (n <= 0) return null;
  return <b className={`mnav__badge ${tone}`}>{n > 99 ? "99+" : n}</b>;
}

export default function MobileNav({ view, section, riskFilter, total, critical, onNavigate, onOpenPage }: Props) {
  const { t } = useSettings();
  const [moreOpen, setMoreOpen] = useState(false);
  const onDash = view === "dashboard";
  const criticalView = onDash && section === "hallazgos" && riskFilter === "Critico";
  const moreCurrent =
    (onDash && (section === "controles" || section === "matriz")) ||
    view === "ajustes" ||
    view === "ayuda" ||
    view === "soporte" ||
    view === "perfil";

  useEffect(() => {
    document.body.classList.toggle("sheet-open", moreOpen);
    if (!moreOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMoreOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => {
      document.body.classList.remove("sheet-open");
      window.removeEventListener("keydown", onKey);
    };
  }, [moreOpen]);

  const goSection = (target: SectionId, risk?: RiskLevel | null) => {
    setMoreOpen(false);
    onNavigate(target, risk);
  };
  const goPage = (page: PageId) => {
    setMoreOpen(false);
    onOpenPage(page);
  };

  const sheet: { id: string; label: string; icon: IconName; current: boolean; onClick: () => void }[] = [
    {
      id: "matriz",
      label: t("nav.matrix"),
      icon: "layers",
      current: onDash && section === "matriz",
      onClick: () => goSection("matriz"),
    },
    {
      id: "controles",
      label: t("nav.controls"),
      icon: "shieldCheck",
      current: onDash && section === "controles",
      onClick: () => goSection("controles"),
    },
    {
      id: "ajustes",
      label: t("nav.settings"),
      icon: "sliders",
      current: view === "ajustes",
      onClick: () => goPage("ajustes"),
    },
    {
      id: "ayuda",
      label: t("nav.help"),
      icon: "help",
      current: view === "ayuda",
      onClick: () => goPage("ayuda"),
    },
    {
      id: "soporte",
      label: t("nav.support"),
      icon: "lifeBuoy",
      current: view === "soporte",
      onClick: () => goPage("soporte"),
    },
    {
      id: "perfil",
      label: t("nav.profile"),
      icon: "user",
      current: view === "perfil",
      onClick: () => goPage("perfil"),
    },
  ];

  return (
    <>
      <nav className="mnav" aria-label={t("nav.aria")}>
        <button
          type="button"
          className="mnav__btn"
          aria-current={onDash && section === "panel" ? "page" : undefined}
          onClick={() => goSection("panel")}
        >
          <Icon name="dashboard" size={19} />
          <span>{t("nav.panel")}</span>
        </button>
        <button
          type="button"
          className="mnav__btn"
          aria-current={onDash && section === "hallazgos" && !criticalView ? "page" : undefined}
          onClick={() => goSection("hallazgos", null)}
        >
          <Icon name="target" size={19} />
          <span>{t("nav.findings")}</span>
          <Badge n={total} tone="warn" />
        </button>
        <button
          type="button"
          className="mnav__btn"
          aria-current={criticalView ? "page" : undefined}
          onClick={() => goSection("hallazgos", "Critico")}
        >
          <Icon name="alert" size={19} />
          <span>{t("nav.critical")}</span>
          <Badge n={critical} tone="crit" />
        </button>
        <button
          type="button"
          className="mnav__btn"
          aria-current={onDash && section === "informe" ? "page" : undefined}
          onClick={() => goSection("informe")}
        >
          <Icon name="fileCheck" size={19} />
          <span>{t("nav.report")}</span>
        </button>
        <button
          type="button"
          className="mnav__btn"
          aria-expanded={moreOpen}
          aria-current={moreCurrent ? "page" : undefined}
          onClick={() => setMoreOpen((o) => !o)}
        >
          <Icon name="grid" size={19} />
          <span>{t("nav.more")}</span>
        </button>
      </nav>

      {moreOpen && (
        <div className="msheet-backdrop" onClick={() => setMoreOpen(false)}>
          <div
            className="msheet"
            role="dialog"
            aria-modal="true"
            aria-label={t("nav.sections")}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="msheet__head">
              <span>{t("nav.sections")}</span>
              <button type="button" className="icon-btn sm" onClick={() => setMoreOpen(false)} aria-label={t("nav.close")}>
                <Icon name="x" size={16} />
              </button>
            </div>
            <div className="msheet__grid">
              {sheet.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  className="msheet__item"
                  aria-current={item.current ? "page" : undefined}
                  onClick={item.onClick}
                >
                  <span className="msheet__icon">
                    <Icon name={item.icon} size={20} />
                  </span>
                  <span>{item.label}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
