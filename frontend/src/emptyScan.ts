import type { ControlsCatalog, CoverageCheck, ScanResponse } from "./types";

/** Same catalogue as backend/app/mapping/ens_mapping.py ENS_CONTROLS. */
export const ENS_CONTROLS: Record<string, string> = {
  "op.acc.1": "Identificación",
  "op.acc.2": "Requisitos de acceso",
  "op.acc.3": "Segregación de funciones y tareas",
  "op.acc.4": "Proceso de gestión de derechos de acceso",
  "op.acc.5": "Mecanismo de autenticación",
  "op.acc.6": "Acceso local (local logon)",
  "op.acc.7": "Acceso remoto (remote login)",
};

export const LOCAL_CONTROLS: ControlsCatalog = {
  family: "op.acc",
  controls: ENS_CONTROLS,
};

/** Same rows as backend/app/enumeration/coverage.py CATALOG. */
const COVERAGE_AREAS: [string, string][] = [
  ["kerberos", "Kerberos"],
  ["delegacion", "Delegación"],
  ["adcs", "AD CS"],
  ["smb", "Firma SMB"],
  ["politica", "Política de contraseñas"],
  ["krbtgt", "krbtgt"],
  ["privilegiadas", "Cuentas privilegiadas"],
  ["ldap", "LDAP"],
  ["confianza", "Confianza, cuota y LAPS"],
  ["acl", "ACL y rutas de control"],
  ["gpo", "GPO"],
  ["secretos", "Atributos con secreto"],
  ["monitorizacion", "Monitorización"],
  ["tiering", "Tiering"],
  ["entra", "Híbrido Entra ID"],
];

const EMPTY_DETAIL = "Sin enumeración autorizada. Esta fila no se simula.";

export function emptyCoverage(): CoverageCheck[] {
  return COVERAGE_AREAS.map(([id, area]) => ({
    id,
    area,
    status: "no_comprobado",
    detail: EMPTY_DETAIL,
  }));
}

/** Empty scan: 0 alerts, every coverage row unchecked. Not a clean domain. */
export function emptyScan(generatedAt?: string): ScanResponse {
  return {
    generated_at: generatedAt ?? new Date().toISOString(),
    is_sample: false,
    scanned: false,
    total_alerts: 0,
    counts_by_risk: { Critico: 0, Alto: 0, Medio: 0, Bajo: 0 },
    alerts: [],
    domain: null,
    dc_host: null,
    errors: [],
    matrix: { empty: true, cells: [] },
    summary: {
      highest_risk: null,
      controls_hit: 0,
      da_path: false,
      da_path_count: 0,
      total_alerts: 0,
    },
    coverage: emptyCoverage(),
  };
}
