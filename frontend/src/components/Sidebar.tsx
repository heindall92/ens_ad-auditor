import Icon, { Logo, type IconName } from "./Icon";
import type { RiskLevel } from "../types";
import { useSettings } from "../settings/SettingsContext";

/** Scroll sections of the dashboard view. */
export type SectionId = "panel" | "hallazgos" | "controles" | "informe";
/** Stand-alone pages rendered instead of the dashboard. */
export type PageId = "ajustes" | "ayuda" | "soporte" | "perfil";
export type View = "dashboard" | PageId;

interface Props {
  view: View;
  section: SectionId;
  riskFilter: RiskLevel | null;
  total: number;
  critical: number;
  controlsAffected: number;
  domain: string;
  isSample: boolean;
  hasData: boolean;
  onNavigate: (section: SectionId, risk?: RiskLevel | null) => void;
  onOpenPage: (page: PageId) => void;
}

interface NavItemProps {
  label: string;
  icon: IconName;
  current: boolean;
  onClick: () => void;
  count?: number;
  countTone?: "" | "warn" | "crit";
}

function NavItem({ label, icon, current, onClick, count, countTone = "" }: NavItemProps) {
  return (
    <button
      type="button"
      className="nav-item"
      aria-current={current ? "page" : undefined}
      onClick={onClick}
    >
      <Icon name={icon} />
      <span>{label}</span>
      {count !== undefined && count > 0 && (
        <span className={`count ${countTone}`.trim()}>{count}</span>
      )}
    </button>
  );
}

export default function Sidebar(props: Props) {
  const { view, section, riskFilter, onNavigate, onOpenPage } = props;
  const { t, theme, toggleTheme } = useSettings();
  const onDash = view === "dashboard";
  const criticalView = onDash && section === "hallazgos" && riskFilter === "Critico";

  return (
    <aside className="side" aria-label={t("nav.aria")}>
      <div className="brand">
        <Logo />
        <span>
          <b>ENS AD Auditor</b>
          <small>{t("brand.sub")}</small>
        </span>
      </div>

      <div className="proj-switch static" role="status">
        <span className={`proj-ic ${props.isSample ? "demo" : ""}`.trim()}>
          <Icon name="server" size={16} />
        </span>
        <span className="proj-txt">
          <b>{props.domain}</b>
          <small>
            {!props.hasData ? t("ctx.noData") : props.isSample ? t("ctx.demo") : t("ctx.real")}
          </small>
        </span>
      </div>

      <nav className="nav" aria-label={t("nav.sections")}>
        <div className="nav-group">{t("nav.group.audit")}</div>
        <NavItem
          label={t("nav.panel")}
          icon="dashboard"
          current={onDash && section === "panel"}
          onClick={() => onNavigate("panel")}
        />
        <NavItem
          label={t("nav.findings")}
          icon="target"
          current={onDash && section === "hallazgos" && !criticalView}
          onClick={() => onNavigate("hallazgos", null)}
          count={props.total}
          countTone="warn"
        />
        <NavItem
          label={t("nav.critical")}
          icon="alert"
          current={criticalView}
          onClick={() => onNavigate("hallazgos", "Critico")}
          count={props.critical}
          countTone="crit"
        />
        <div className="nav-group">{t("nav.group.framework")}</div>
        <NavItem
          label={t("nav.controls")}
          icon="shieldCheck"
          current={onDash && section === "controles"}
          onClick={() => onNavigate("controles")}
          count={props.controlsAffected}
        />
        <NavItem
          label={t("nav.report")}
          icon="fileCheck"
          current={onDash && section === "informe"}
          onClick={() => onNavigate("informe")}
        />
        <div className="nav-group">{t("nav.group.app")}</div>
        <NavItem
          label={t("nav.settings")}
          icon="sliders"
          current={view === "ajustes"}
          onClick={() => onOpenPage("ajustes")}
        />
        <NavItem
          label={t("nav.help")}
          icon="help"
          current={view === "ayuda"}
          onClick={() => onOpenPage("ayuda")}
        />
        <NavItem
          label={t("nav.support")}
          icon="lifeBuoy"
          current={view === "soporte"}
          onClick={() => onOpenPage("soporte")}
        />
      </nav>

      <div className="side-foot">
        <button
          type="button"
          className="nav-item"
          onClick={toggleTheme}
          aria-label={theme === "dark" ? t("theme.toLight") : t("theme.toDark")}
        >
          <Icon name={theme === "dark" ? "sun" : "moon"} />
          <span>{theme === "dark" ? t("theme.light") : t("theme.dark")}</span>
        </button>
        <button
          type="button"
          className="me"
          aria-current={view === "perfil" ? "page" : undefined}
          aria-label={t("user.open")}
          title={t("nav.profile")}
          onClick={() => onOpenPage("perfil")}
        >
          <span className="avatar c-teal" style={{ ["--s" as string]: "30px" }}>
            YR
          </span>
          <span>
            <b>Yoandy Ramírez Delgado</b>
            <small>{t("user.role")}</small>
          </span>
        </button>
      </div>
    </aside>
  );
}
