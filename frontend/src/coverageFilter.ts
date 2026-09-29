import type { GRCAlert } from "./types";

const POLICY_TYPES: Record<string, string[]> = {
  politica: ["weak_password_policy", "weak_lockout_policy"],
  krbtgt: ["krbtgt_password_age"],
  privilegiadas: ["protected_users_gap", "admin_with_spn", "stale_privileged_account"],
  ldap: ["ldap_signing_not_required", "ldap_channel_binding_weak"],
  confianza: ["trust_sid_filtering", "laps_not_deployed", "machine_account_quota"],
};

const MODULE_OF: Record<string, string> = {
  kerberos: "enumeration.kerberos",
  delegacion: "enumeration.delegation",
  adcs: "enumeration.adcs",
  smb: "enumeration.smb",
  acl: "enumeration.acl",
  secretos: "enumeration.secrets",
};

export function coverageCanFilter(id: string): boolean {
  return id !== "tiering" && id !== "entra";
}

export function alertMatchesCoverage(alert: GRCAlert, id: string | null): boolean {
  if (!id) return true;
  if (id === "gpo") return alert.finding.finding_type === "gpo_weak_setting";
  if (id === "monitorizacion") return alert.finding.finding_type === "audit_policy_gap";
  const types = POLICY_TYPES[id];
  if (types) return types.includes(alert.finding.finding_type);
  const moduleName = MODULE_OF[id];
  return !!moduleName && alert.finding.source_module === moduleName;
}
