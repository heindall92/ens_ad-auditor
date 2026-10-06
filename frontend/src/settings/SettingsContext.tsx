import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { LOCALE, translate, type Lang, type TFn } from "./i18n";

export type Theme = "light" | "dark";
export type Accent = "teal" | "blue" | "green" | "amber" | "rose" | "graphite";
export type Density = "comoda" | "compacta";

export const ACCENTS: Accent[] = ["teal", "blue", "green", "amber", "rose", "graphite"];

export interface Settings {
  theme: Theme;
  accent: Accent;
  lang: Lang;
  density: Density;
  reduceMotion: boolean;
  reduceTransparency: boolean;
}

interface SettingsContextValue extends Settings {
  setTheme: (theme: Theme) => void;
  toggleTheme: () => void;
  setAccent: (accent: Accent) => void;
  setLang: (lang: Lang) => void;
  setDensity: (density: Density) => void;
  setReduceMotion: (on: boolean) => void;
  setReduceTransparency: (on: boolean) => void;
  reset: () => void;
  t: TFn;
  locale: string;
}

// Storage keys. The theme key predates this module and is also read by
// public/theme-boot.js to avoid a flash of the wrong theme.
const KEY = {
  theme: "ens-ad-auditor.theme",
  accent: "ens-ad-auditor.accent",
  lang: "ens-ad-auditor.lang",
  density: "ens-ad-auditor.density",
  reduceMotion: "ens-ad-auditor.reduceMotion",
  reduceTransparency: "ens-ad-auditor.reduceTransparency",
} as const;

const DEFAULTS: Settings = {
  theme: "light",
  accent: "teal",
  lang: "es",
  density: "comoda",
  reduceMotion: false,
  reduceTransparency: false,
};

function read(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function write(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* storage unavailable (private mode): keep in memory only */
  }
}

function oneOf<T extends string>(value: string | null, allowed: readonly T[], fallback: T): T {
  return value !== null && (allowed as readonly string[]).includes(value) ? (value as T) : fallback;
}

function loadInitial(): Settings {
  const storedTheme = read(KEY.theme);
  const theme: Theme =
    storedTheme === "light" || storedTheme === "dark"
      ? storedTheme
      : window.matchMedia?.("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
  return {
    theme,
    accent: oneOf(read(KEY.accent), ACCENTS, DEFAULTS.accent),
    lang: oneOf<Lang>(read(KEY.lang), ["es", "en"], DEFAULTS.lang),
    density: oneOf<Density>(read(KEY.density), ["comoda", "compacta"], DEFAULTS.density),
    reduceMotion: read(KEY.reduceMotion) === "1",
    reduceTransparency: read(KEY.reduceTransparency) === "1",
  };
}

const SettingsContext = createContext<SettingsContextValue | null>(null);

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [s, setS] = useState<Settings>(loadInitial);

  // Reflect every preference on <html> and persist it.
  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = s.theme;
    root.dataset.accent = s.accent;
    root.dataset.density = s.density;
    root.lang = s.lang;
    if (s.reduceMotion) root.dataset.motion = "reduce";
    else delete root.dataset.motion;
    if (s.reduceTransparency) root.dataset.transparency = "reduce";
    else delete root.dataset.transparency;

    write(KEY.theme, s.theme);
    write(KEY.accent, s.accent);
    write(KEY.lang, s.lang);
    write(KEY.density, s.density);
    write(KEY.reduceMotion, s.reduceMotion ? "1" : "0");
    write(KEY.reduceTransparency, s.reduceTransparency ? "1" : "0");
  }, [s]);

  const patch = useCallback((p: Partial<Settings>) => setS((prev) => ({ ...prev, ...p })), []);

  const t = useCallback<TFn>((key, vars) => translate(s.lang, key, vars), [s.lang]);

  const value = useMemo<SettingsContextValue>(
    () => ({
      ...s,
      setTheme: (theme) => patch({ theme }),
      toggleTheme: () => setS((prev) => ({ ...prev, theme: prev.theme === "dark" ? "light" : "dark" })),
      setAccent: (accent) => patch({ accent }),
      setLang: (lang) => patch({ lang }),
      setDensity: (density) => patch({ density }),
      setReduceMotion: (reduceMotion) => patch({ reduceMotion }),
      setReduceTransparency: (reduceTransparency) => patch({ reduceTransparency }),
      reset: () => setS({ ...DEFAULTS }),
      t,
      locale: LOCALE[s.lang],
    }),
    [s, patch, t],
  );

  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>;
}

export function useSettings(): SettingsContextValue {
  const ctx = useContext(SettingsContext);
  if (!ctx) throw new Error("useSettings must be used inside <SettingsProvider>");
  return ctx;
}

/** True when the user (in-app setting) or the OS asks for reduced motion. */
export function usePrefersReducedMotion(): boolean {
  const { reduceMotion } = useSettings();
  const [os, setOs] = useState(
    () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false,
  );
  useEffect(() => {
    const mq = window.matchMedia?.("(prefers-reduced-motion: reduce)");
    if (!mq) return;
    const onChange = () => setOs(mq.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);
  return reduceMotion || os;
}
