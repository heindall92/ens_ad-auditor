import type { GRCAlert, RiskLevel } from "./types";

/** Studio hallazgo_categorias. Keep in sync with backend/app/studio_evidencia.py */
const CATEGORIA: Record<string, string> = {
  smb_signing_disabled: "TLS",
  kerberoasting: "AUTH_MFA",
  asrep_roasting: "AUTH_MFA",
  unconstrained_delegation: "IDOR",
  constrained_rbcd_delegation: "IDOR",
  excessive_privileges: "IDOR",
  adcs_esc: "AUTH_MFA",
  weak_password_policy: "BRUTE",
  weak_lockout_policy: "BRUTE",
  krbtgt_password_age: "AUTH_MFA",
  protected_users_gap: "IDOR",
  admin_with_spn: "AUTH_MFA",
  stale_privileged_account: "IDOR",
  ldap_signing_not_required: "AUTH_MFA",
  ldap_channel_binding_weak: "AUTH_MFA",
  trust_sid_filtering: "IDOR",
  laps_not_deployed: "DEFCREDS",
  machine_account_quota: "IDOR",
  acl_control_path: "IDOR",
  cleartext_secret_attr: "INFOLEAK",
  gpo_weak_setting: "TLS",
  audit_policy_gap: "LOGGING",
};

const CVSS: Record<RiskLevel, number> = {
  Critico: 9.0,
  Alto: 7.5,
  Medio: 5.0,
  Bajo: 2.5,
};

const ACTIVO_ID = "AD";

export const STUDIO_NOTA =
  "Importa este JSON en ENS Compliance Studio → Evidencia técnica. Crea antes un activo con id AD (Active Directory). Sin alertas el array va vacío: no se inventan hallazgos.";

function itemId(ruleId: string, index: number): string {
  const safe = `${ruleId}-${index}`.replace(/[^\w.-]/g, "-");
  return `AD-${safe}`.slice(0, 40);
}

export function buildStudioEvidencia(alerts: GRCAlert[], domain: string | null): object {
  const hallazgos = alerts
    .filter((a) => !a.finding.is_sample)
    .map((a, i) => {
      const categoria = CATEGORIA[a.finding.finding_type];
      if (!categoria) return null;
      return {
        id: itemId(a.rule_id, i + 1),
        titulo: a.finding.title,
        categoria,
        cvss: CVSS[a.risk],
        activoId: ACTIVO_ID,
        estado: "abierto",
        fuente: "ENS AD Auditor",
        ens: a.ens_controls.map((c) => c.id),
        objetivo: a.finding.target,
      };
    })
    .filter((row) => row !== null);

  return {
    formato: "ens-studio-hallazgos",
    is_sample: false,
    origen: "ENS AD Auditor",
    dominio: domain,
    activo_sugerido: { id: ACTIVO_ID, nombre: domain || "Active Directory" },
    nota: STUDIO_NOTA,
    hallazgos,
  };
}
