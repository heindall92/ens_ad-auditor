import Icon from "./Icon";
import { useSettings, type Theme } from "../settings/SettingsContext";

/** Light/dark segmented control (.seg from the reference design system). */
export default function ThemeSeg() {
  const { theme, setTheme, t } = useSettings();
  const opts: [Theme, string, "sun" | "moon"][] = [
    ["light", t("set.light"), "sun"],
    ["dark", t("set.dark"), "moon"],
  ];
  return (
    <div className="seg" role="group" aria-label={t("set.theme")}>
      {opts.map(([v, label, ic]) => (
        <button key={v} type="button" aria-pressed={theme === v} onClick={() => setTheme(v)}>
          <Icon name={ic} size={15} />
          {label}
        </button>
      ))}
    </div>
  );
}
