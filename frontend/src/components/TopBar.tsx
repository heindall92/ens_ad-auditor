import Icon from "./Icon";
import LangSwitch from "./LangSwitch";
import { useSettings } from "../settings/SettingsContext";

interface Props {
  current: string;
  showActions: boolean;
  loading: boolean;
  downloading: boolean;
  canDownload: boolean;
  onRescan: () => void;
  onDownload: () => void;
  onOpenDrawer: () => void;
  onOpenHelp: () => void;
}

export default function TopBar(props: Props) {
  const { t, theme, toggleTheme } = useSettings();
  return (
    <header className="top">
      <button
        type="button"
        className="icon-btn only-mobile"
        onClick={props.onOpenDrawer}
        aria-label={t("top.menu")}
      >
        <Icon name="menu" size={20} />
      </button>
      <nav className="crumbs" aria-label={t("top.crumbs")}>
        <span className="crumb-proj">ENS AD Auditor</span>
        <Icon name="chevronRight" size={14} className="muted" />
        <span className="crumb-cur">{props.current}</span>
      </nav>
      <div className="top-actions">
        {props.showActions && (
          <>
            <button type="button" className="btn" onClick={props.onRescan} disabled={props.loading}>
              <Icon name="refresh" size={16} className={props.loading ? "spin" : ""} />
              <span className="lbl">{props.loading ? t("top.scanning") : t("top.rescan")}</span>
            </button>
            <button
              type="button"
              className="btn primary"
              onClick={props.onDownload}
              disabled={props.downloading || !props.canDownload}
            >
              <Icon name="download" size={16} />
              <span className="lbl">{props.downloading ? t("top.generating") : t("top.download")}</span>
            </button>
          </>
        )}
        <LangSwitch />
        <button
          type="button"
          className="icon-btn"
          onClick={toggleTheme}
          aria-label={theme === "dark" ? t("theme.toLight") : t("theme.toDark")}
          title={theme === "dark" ? t("theme.toLight") : t("theme.toDark")}
        >
          <Icon name={theme === "dark" ? "sun" : "moon"} size={18} />
        </button>
        <button
          type="button"
          className="icon-btn hide-sm"
          onClick={props.onOpenHelp}
          aria-label={t("top.help")}
          title={t("top.help")}
        >
          <Icon name="help" size={18} />
        </button>
      </div>
    </header>
  );
}
