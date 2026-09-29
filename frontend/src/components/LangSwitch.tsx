import { useSettings } from "../settings/SettingsContext";
import type { Lang } from "../settings/i18n";

const LANGS: Lang[] = ["es", "en"];

/** Compact ES/EN toggle (.lang-switch from the reference design system). */
export default function LangSwitch() {
  const { lang, setLang, t } = useSettings();
  return (
    <div className="lang-switch" role="group" aria-label={t("top.lang")}>
      {LANGS.map((l) => (
        <button
          key={l}
          type="button"
          aria-pressed={lang === l}
          title={t(`lang.${l}`)}
          lang={l}
          onClick={() => setLang(l)}
        >
          {l.toUpperCase()}
        </button>
      ))}
    </div>
  );
}
