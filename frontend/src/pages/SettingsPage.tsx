import type { ReactNode } from "react";
import AccentSwatches from "../components/AccentSwatches";
import Icon from "../components/Icon";
import LangSwitch from "../components/LangSwitch";
import ThemeSeg from "../components/ThemeSeg";
import { useSettings, type Density } from "../settings/SettingsContext";
import { translate } from "../settings/i18n";
import PageHead from "./PageHead";

function SetRow({ title, desc, children, id }: { title: string; desc?: string; children: ReactNode; id?: string }) {
  return (
    <div className="set-row">
      <div>
        <b id={id}>{title}</b>
        {desc && <p>{desc}</p>}
      </div>
      <div className="set-ctl">{children}</div>
    </div>
  );
}

function Switch({ checked, onChange, labelledBy }: { checked: boolean; onChange: (v: boolean) => void; labelledBy: string }) {
  return (
    <label className="switch">
      <input
        type="checkbox"
        role="switch"
        checked={checked}
        aria-labelledby={labelledBy}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span />
    </label>
  );
}

interface Props {
  notify: (msg: string) => void;
}

export default function SettingsPage({ notify }: Props) {
  const s = useSettings();
  const { t } = s;
  const densities: [Density, string][] = [
    ["comoda", t("set.comfortable")],
    ["compacta", t("set.compact")],
  ];

  return (
    <>
      <PageHead id="page-title" eyebrow={t("set.eyebrow")} title={t("set.title")} lead={t("set.lead")} />
      <div className="settings">
        <section className="card" aria-labelledby="set-h-appearance">
          <h3 id="set-h-appearance">{t("set.appearance")}</h3>
          <SetRow title={t("set.theme")} desc={t("set.themeDesc")}>
            <ThemeSeg />
          </SetRow>
          <SetRow title={t("set.accent")} desc={t("set.accentDesc")}>
            <AccentSwatches />
          </SetRow>
          <SetRow title={t("set.lang")} desc={t("set.langDesc")}>
            <LangSwitch />
          </SetRow>
          <SetRow title={t("set.density")} desc={t("set.densityDesc")}>
            <div className="seg" role="group" aria-label={t("set.density")}>
              {densities.map(([v, label]) => (
                <button key={v} type="button" aria-pressed={s.density === v} onClick={() => s.setDensity(v)}>
                  {label}
                </button>
              ))}
            </div>
          </SetRow>
        </section>

        <section className="card" aria-labelledby="set-h-a11y">
          <h3 id="set-h-a11y">{t("set.a11y")}</h3>
          <SetRow id="set-l-motion" title={t("set.motion")} desc={t("set.motionDesc")}>
            <Switch checked={s.reduceMotion} onChange={s.setReduceMotion} labelledBy="set-l-motion" />
          </SetRow>
          <SetRow id="set-l-transp" title={t("set.transparency")} desc={t("set.transparencyDesc")}>
            <Switch
              checked={s.reduceTransparency}
              onChange={s.setReduceTransparency}
              labelledBy="set-l-transp"
            />
          </SetRow>
        </section>

        <section className="card" aria-labelledby="set-h-data">
          <h3 id="set-h-data">{t("set.data")}</h3>
          <SetRow title={t("set.storage")} desc={t("set.storageDesc")}>
            <span className="badge neutral">
              <Icon name="lock" size={13} />
              localStorage
            </span>
          </SetRow>
          <SetRow title={t("set.reset")} desc={t("set.resetDesc")}>
            <button
              type="button"
              className="btn danger"
              onClick={() => {
                s.reset();
                // Reset returns to Spanish, so confirm in the resulting language.
                notify(translate("es", "set.resetDone"));
              }}
            >
              <Icon name="refresh" size={15} />
              {t("set.resetBtn")}
            </button>
          </SetRow>
        </section>
      </div>
    </>
  );
}
