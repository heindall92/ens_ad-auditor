# Seguridad

ENS AD Auditor enumera un Active Directory **solo con autorización expresa por escrito**. Las credenciales viajan en `POST /api/audit` y **no se guardan**: ni en disco, ni en `localStorage`, ni en el repositorio, ni en el informe.

## Credenciales

| Dato | Dónde vive | Persistencia |
|---|---|---|
| Dominio, DC, usuario | Cuerpo de `POST /api/audit` (RAM de la petición) | Se descarta al terminar la petición |
| Contraseña o hash NT | El mismo cuerpo | Se descarta al terminar la petición |
| Preferencias de la interfaz | `localStorage` de este navegador | Tema, acento, idioma, densidad, movimiento y transparencia |
| Plan de tratamiento | `localStorage` de este navegador | Responsable, estado y plazo por hallazgo. No es un secreto de directorio |

No hay cuentas de usuario, ni cookies de sesión, ni fichero `.env` de credenciales en este repositorio. Un `GET /api/scan` sin credenciales devuelve **cero alertas** e `is_sample: false`.

## Modelo de amenazas (resumen)

| Vector | Defensa |
|---|---|
| Credenciales en disco o en el repo | El modelo `AuditRequest` no se serializa a fichero. `.gitignore` cubre `.env` y salidas accidentales de Certipy |
| Hallazgos inventados | El API no sirve datos de demostración. Los fixtures de test llevan `is_sample: true` y no salen por HTTP |
| Uso no autorizado | `authorized: true` es obligatorio. Sin ese acuse la API rechaza la petición |
| Alcance | Enumeración de solo lectura. No hay explotación, relay, roast de tickets ni lectura de contraseñas LAPS |
| Informe / exportación a Studio | Sale de las alertas ya enumeradas. Si no hay alertas, el JSON va vacío. No se copian secretos |

## Versiones con soporte

| Versión | Soporte |
|---|---|
| 0.3.x | Sí — versión actual |
| < 0.3 | No — actualizar |

## Informar de una vulnerabilidad

**No abras una *issue* pública.** Usa el aviso de seguridad privado del repositorio o escribe a **yoandyramirezdelgado@gmail.com** con el asunto `[SECURITY] ens-ad-auditor`.

Incluye versión o *commit*, pasos y, si puedes, una prueba de concepto. No envíes contraseñas ni hashes reales.

| Plazo | Compromiso |
|---|---|
| 72 h | Acuse de recibo |
| 7 días | Primer diagnóstico |
| Tras la corrección | Aviso en el CHANGELOG |

No hay programa de recompensas.
