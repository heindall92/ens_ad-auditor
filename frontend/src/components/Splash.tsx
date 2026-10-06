import { useEffect, useRef, useState } from "react";
import { Logo } from "./Icon";
import { usePrefersReducedMotion, useSettings } from "../settings/SettingsContext";

const MIN_VISIBLE_MS = 700;
const FADE_MS = 320;

interface Props {
  ready: boolean;
  onDone: () => void;
}

export default function Splash({ ready, onDone }: Props) {
  const { t } = useSettings();
  const reduced = usePrefersReducedMotion();
  const startedAt = useRef(performance.now());
  const [phase, setPhase] = useState<"in" | "out" | "done">("in");

  useEffect(() => {
    if (!ready) return;
    const elapsed = performance.now() - startedAt.current;
    const wait = reduced ? 0 : Math.max(0, MIN_VISIBLE_MS - elapsed);
    const id = window.setTimeout(() => setPhase("out"), wait);
    return () => window.clearTimeout(id);
  }, [ready, reduced]);

  useEffect(() => {
    if (phase !== "out") return;
    const id = window.setTimeout(() => {
      setPhase("done");
      onDone();
    }, reduced ? 0 : FADE_MS);
    return () => window.clearTimeout(id);
  }, [phase, reduced, onDone]);

  if (phase === "done") return null;

  return (
    <div className={`splash${phase === "out" ? " out" : ""}`} aria-busy={!ready}>
      <p className="sr-only" role="status">
        {t("splash.loading")}
      </p>
      <div className="splash-inner">
        <div className="splash-logo" aria-hidden="true">
          <Logo size={64} className="splash-mark" />
        </div>
        <h1 className="splash-title">ENS AD Auditor</h1>
        <p className="splash-sub">{t("splash.sub")}</p>
        <div
          className={`splash-bar${ready ? " done" : ""}`}
          role="progressbar"
          aria-label={t("splash.loading")}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={ready ? 100 : undefined}
        >
          <i />
        </div>
      </div>
      <p className="splash-foot" aria-hidden="true">
        {t("legal")}
      </p>
    </div>
  );
}
