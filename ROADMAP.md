# Hoja de ruta — ENS AD Auditor

Este repositorio es un ecosistema de auditoría real, no una maqueta. Lo que está hecho ahora se ejecuta contra un Active Directory autorizado. Lo que queda, queda escrito aquí. Nada de esta lista se finge en el panel ni en la API.

## Ahora (en el código)

- Enumeración de solo lectura con `ldap3`, `impacket` y `certipy-ad` (`find`).
- Superficies: Kerberos (SPN/RC4, AS-REP), delegación (no restringida, restringida, RBCD), AD CS ESC1–ESC8, firma SMB.
- Higiene de dominio: política de contraseñas y bloqueo, edad de `krbtgt`, Protected Users, cuentas privilegiadas con SPN, cuentas privilegiadas inactivas, LDAP signing / channel binding observado, trusts sin SID filtering, LAPS en esquema (sin leer contraseñas), `ms-DS-MachineAccountQuota`.
- Motor ENS `[op.acc]` (RD 311/2022, catálogo del proyecto) con control principal, incumplimiento y remediación.
- Criticidad MAGERIT: impacto × probabilidad (1–5). Bandas: Crítico ≥ 16, Alto ≥ 10, Medio ≥ 5, Bajo el resto. Matriz 5×5 y resumen de dominio (riesgo más alto, controles afectados, camino a Domain Admin).
- Panel ES/EN, informe Markdown/JSON, autorización por escrito obligatoria, credenciales no persistidas.
- Contrato duro: sin credenciales no hay hallazgos. `GET /api/scan` devuelve lista vacía e `is_sample: false`.

## Más adelante

- Políticas de contraseña de grano fino (PSO / FGPP).
- Recorrido de bosque y trusts con más atributos (SID history, PIM, Selective Auth).
- Ingesta de un grafo BloodHound ya recogido en una auditoría autorizada (sin recoger el grafo desde aquí si no hay autorización).
- GPO de endurecimiento (LDAP signing exigido, SMB, NTLM) más allá del bind observado.
- Inventario de cuentas de servicio y gMSA.
- Azure AD Connect / Entra ID híbrido, si el alcance de la autorización lo cubre.
- Cola de auditorías y retención del informe en el servidor del auditor (hoy el resultado vive en la sesión del navegador).

## Fuera de alcance a propósito

- Hallazgos inventados, dominios de ejemplo o recuentos de muestra.
- Explotación, relay, roast de tickets, solicitud de certificados, lectura de contraseñas LAPS.
- Escaneo sin autorización por escrito y sin credenciales reales.
- Guardar la contraseña o el hash NT en disco, `localStorage` o el repositorio.
