import { useEffect, useRef, useState } from "react";
import { Logo } from "./Icon";
import { usePrefersReducedMotion, useSettings } from "../settings/SettingsContext";
import type { TKey } from "../settings/i18n";

const MIN_VISIBLE_MS = 900;
const FADE_MS = 450;
const STEP_MS = 700;
const STEPS: TKey[] = ["splash.s1", "splash.s2", "splash.s3", "splash.s4"];

interface Props {
  ready: boolean;
  onDone: () => void;
}

export default function Splash({ ready, onDone }: Props) {
  const { t } = useSettings();
  const reduced = usePrefersReducedMotion();
  const startedAt = useRef(performance.now());
  const [phase, setPhase] = useState<"in" | "out" | "done">("in");
  const [step, setStep] = useState(0);
  const [videoFailed, setVideoFailed] = useState(false);
  const [videoEnded, setVideoEnded] = useState(false);
  const playVideo = !reduced && !videoFailed;

  useEffect(() => {
    if (playVideo || ready) return;
    const id = window.setInterval(() => setStep((s) => Math.min(s + 1, STEPS.length - 1)), STEP_MS);
    return () => window.clearInterval(id);
  }, [ready, playVideo]);

  useEffect(() => {
    if (playVideo) {
      if (!videoEnded || !ready) return;
      setPhase("out");
      return;
    }
    if (!ready) return;
    const elapsed = performance.now() - startedAt.current;
    const id = window.setTimeout(() => {
      setStep(STEPS.length - 1);
      setPhase("out");
    }, Math.max(0, MIN_VISIBLE_MS - elapsed));
    return () => window.clearTimeout(id);
  }, [ready, playVideo, videoEnded]);

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
    <div className={`splash${phase === "out" ? " out" : ""}${playVideo ? " video" : ""}`} aria-busy={!ready}>
      <p className="sr-only" role="status">
        {t("splash.loading")}
      </p>
      {playVideo ? (
        <video
          className="splash-video"
          src="/intro.mp4"
          autoPlay
          muted
          playsInline
          preload="auto"
          aria-hidden="true"
          onEnded={() => setVideoEnded(true)}
          onError={() => setVideoFailed(true)}
        />
      ) : (
        <>
          <div className="splash-inner">
            <div className="splash-logo" aria-hidden="true">
              <span className="splash-ring" />
              <span className="splash-ring r2" />
              <Logo size={76} className="splash-mark" />
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
            <p className="splash-step" aria-hidden="true">
              <span key={step}>{t(STEPS[step])}</span>
            </p>
          </div>
          <p className="splash-foot" aria-hidden="true">
            {t("legal")}
          </p>
        </>
      )}
    </div>
  );
}
