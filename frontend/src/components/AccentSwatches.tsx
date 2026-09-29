import { ACCENTS, useSettings } from "../settings/SettingsContext";

/** Accent colour picker (.swatches/.swatch from the reference design system). */
export default function AccentSwatches() {
  const { accent, setAccent, t } = useSettings();
  return (
    <div className="swatches" role="group" aria-label={t("set.accent")}>
      {ACCENTS.map((a) => (
        <button
          key={a}
          type="button"
          aria-pressed={accent === a}
          className={`swatch a-${a}${accent === a ? " on" : ""}`}
          aria-label={t(`accent.${a}`)}
          title={t(`accent.${a}`)}
          onClick={() => setAccent(a)}
        />
      ))}
    </div>
  );
}
