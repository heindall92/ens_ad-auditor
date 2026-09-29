import type { RiskLevel } from "./types";

// Mapping of backend risk levels to design-system modifiers.
// Critico/Alto -> "mayor" (red family), Medio -> "menor" (amber), Bajo -> accent.
export const RISK_TONE: Record<RiskLevel, "crit" | "high" | "warn" | "accent"> = {
  Critico: "crit",
  Alto: "high",
  Medio: "warn",
  Bajo: "accent",
};

export const RISK_FINDING_CLASS: Record<RiskLevel, string> = {
  Critico: "mayor critico",
  Alto: "mayor alto",
  Medio: "menor medio",
  Bajo: "bajo",
};

export const RISK_PLURAL: Record<RiskLevel, string> = {
  Critico: "Críticas",
  Alto: "Altas",
  Medio: "Medias",
  Bajo: "Bajas",
};
