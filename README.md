![header](https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=0,2,2,5,30&height=200&section=header&text=ENS%20AD%20Auditor&fontSize=52&fontColor=fff&animation=twinkling&fontAlignY=35&desc=Auditor%C3%ADa%20de%20Active%20Directory%20mapeada%20al%20ENS&descSize=18&descAlignY=55&descAlign=50)

<p align="center">
  <b><i>Enumera un Active Directory autorizado y convierte cada debilidad en una alerta GRC ligada a los controles de acceso del ENS.</i></b>
</p>

<p align="center">
  <a href="LICENSE"><img alt="Licencia GPLv2" src="https://img.shields.io/badge/LICENCIA-GPLv2-4169A1?style=flat"/></a>
  <img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-Python-009688?style=flat&logo=fastapi&logoColor=white"/>
  <img alt="React" src="https://img.shields.io/badge/React-TypeScript-61DAFB?style=flat&logo=react&logoColor=black"/>
  <img alt="ENS op.acc" src="https://img.shields.io/badge/ENS-op.acc-0F766E?style=flat"/>
  <img alt="Interfaz ES/EN" src="https://img.shields.io/badge/UI-ES%20%2F%20EN-2E8B57?style=flat"/>
</p>

<p align="center">
  <img src="docs/img/readme/panel.png" alt="Panel de conformidad de ENS AD Auditor" width="880"/>
</p>

**ENS AD Auditor** revisa la configuración de un dominio de Active Directory (Kerberos, delegación, AD CS, firma SMB, política de dominio, LDAP, trusts, LAPS, ACL del dominio, atributos de secreto y GPO leída en SYSVOL) y traduce cada hallazgo a un incumplimiento de los controles de acceso del Esquema Nacional de Seguridad, familia **`[op.acc]`**, con criticidad MAGERIT, descripción y remediación.

La regla del proyecto es sencilla: **ningún dato inventado**. Sin conexión a un dominio autorizado no hay alertas: `GET /api/scan` devuelve una lista vacía e `is_sample: false`. No hay escaneo sin autorización por escrito y credenciales reales.

Interfaz en el navegador: [https://heindall92.github.io/ens_ad-auditor/](https://heindall92.github.io/ens_ad-auditor/) (modo navegador; auditar un dominio exige el motor local y autorización por escrito).

---

## <img src="docs/assets/icons/list.svg" width="20" height="20" valign="middle"/> Índice

- [Cómo funciona](#cómo-funciona)
- [Arquitectura](#arquitectura)
- [Qué incluye](#qué-incluye)
- [Capturas](#capturas)
- [Arranque rápido](#arranque-rápido)
- [Aviso](#aviso)
- [Limitaciones conocidas](#limitaciones-conocidas)
- [Hoja de ruta](#hoja-de-ruta)
- [Seguridad](#seguridad)
- [Estructura](#estructura)
- [Licencia](#licencia)
- [Autor](#autor)

---

## <img src="docs/assets/icons/scan-search.svg" width="20" height="20" valign="middle"/> Cómo funciona

1. **Se enumeran superficies de solo lectura**, contra un dominio autorizado. Kerberos (cuentas con SPN y sin preautenticación), delegación (no restringida, restringida y RBCD), AD CS (cualquier clave ESC que devuelva Certipy `find`), firma SMB, política de contraseñas y bloqueo, `krbtgt`, Protected Users, cuentas privilegiadas con SPN o inactivas, LDAP signing / channel binding, trusts, LAPS (solo esquema), ACL del dominio (DCSync, GenericAll, WriteDacl), presencia de `userPassword` / `unixUserPassword` y `GptTmpl.inf` cuando SYSVOL se puede leer.
2. **El motor de mapeo decide el control y la criticidad.** Cada tipo de hallazgo pasa a uno o varios controles `[op.acc]`, con un control principal. El nivel ENS (Crítico, Alto, Medio o Bajo) sale del producto MAGERIT impacto × probabilidad (1–5).
3. **El panel lo muestra como trabajo de auditoría.** KPIs, matriz MAGERIT, resumen de criticidad, filtros por severidad y por control, detalle técnico y descarga del informe en Markdown o JSON.

En vez de decir solo «SMB signing deshabilitado», la alerta dice, por ejemplo, riesgo Alto e incumplimiento del mecanismo de autenticación `[op.acc.5]`, con qué falla y cómo remediarlo.

## <img src="docs/assets/icons/layers.svg" width="20" height="20" valign="middle"/> Arquitectura

```mermaid
flowchart LR
    D[Dominio AD<br/>autorizado] --> E[Enumeración<br/>Kerberos · delegación · AD CS · SMB · política · ACL · GPO]
    E --> M[Motor ENS op.acc<br/>+ MAGERIT]
    M --> A[Alertas GRC<br/>criticidad · incumplimiento · remediación]
    A --> B[API FastAPI]
    B --> F[Panel React]
    F --> U((Auditor))
```

| Pieza | Qué hace | Puerto |
|---|---|---|
| `backend` | API FastAPI, mapeo ENS e informe | `8000` |
| `frontend` | Panel React + TypeScript (Vite) | `5173` |

La enumeración en vivo usa `ldap3` (LDAP), `impacket` (firma SMB y lectura de `GptTmpl.inf`) y `certipy-ad` (`find`, solo lectura). Las credenciales se envían en `POST /api/audit` y no se escriben en disco ni en el repositorio.

### <img src="docs/assets/icons/shield-check.svg" width="20" height="20" valign="middle"/> Motor de mapeo

`backend/app/mapping/ens_mapping.py` traduce cada tipo de hallazgo a los controles que le tocan. `backend/app/mapping/magerit.py` calcula el producto impacto × probabilidad y las bandas ENS. Está cubierto con `pytest`.

| Hallazgo técnico | Control ENS principal |
|---|---|
| Firma SMB deshabilitada | `op.acc.5` / `op.acc.7` |
| Kerberoasting (SPN con RC4) | `op.acc.5` |
| AS-REP roasting (sin preautenticación) | `op.acc.5` / `op.acc.6` |
| Delegación no restringida, restringida o RBCD | `op.acc.4` |
| Privilegios excesivos | `op.acc.2` / `op.acc.4` |
| AD CS (clave ESC devuelta por Certipy) | `op.acc.5` / `op.acc.4` |
| Política de contraseñas / bloqueo | `op.acc.5` / `op.acc.6` |
| krbtgt sin rotar, admin con SPN | `op.acc.5` |
| Protected Users / cuentas privilegiadas inactivas | `op.acc.4` / `op.acc.2` |
| LDAP sin firma / channel binding | `op.acc.5` / `op.acc.7` |
| Trust sin SID filtering | `op.acc.4` |
| LAPS no desplegado | `op.acc.6` |
| Cuota de cuentas de equipo | `op.acc.4` |
| ACL de dominio (DCSync, GenericAll, WriteDacl) | `op.acc.4` |
| Atributo `userPassword` / `unixUserPassword` presente | `op.acc.5` |
| GPO con firma o integridad LDAP débil | `op.acc.5` |
| Auditoría de directorio a cero en la GPO leída | `op.acc.4` |

Controles de referencia: `op.acc.1` identificación · `op.acc.2` requisitos de acceso · `op.acc.3` segregación de funciones · `op.acc.4` gestión de derechos · `op.acc.5` mecanismo de autenticación · `op.acc.6` acceso local · `op.acc.7` acceso remoto. Marco: Real Decreto 311/2022. Las técnicas de AD CS siguen la clave ESC que devuelve Certipy. La ausencia de `[Event Audit]` se cita también como `op.exp.8` en las referencias del hallazgo, sin ampliar el catálogo principal.

## <img src="docs/assets/icons/list-checks.svg" width="20" height="20" valign="middle"/> Qué incluye

| Sección | Qué resuelve |
|---|---|
| **Conexión** | Dominio, DC, usuario y contraseña o hash NT. Exige confirmar autorización por escrito. El secreto no se guarda. |
| **Panel** | Alertas totales, críticas, altas y controles `[op.acc]` afectados. Resumen de criticidad del dominio. |
| **Matriz MAGERIT** | Impacto × probabilidad (1–5). Vacía si no hay hallazgos. |
| **Hallazgos** | Lista por riesgo, con evidencia, incumplimiento, remediación, filtro por área y plan de tratamiento en el navegador. |
| **Cobertura** | Cada fila de la hoja de ruta como comprobado o no comprobado. Tiering y Entra ID no se ejecutan. |
| **Controles ENS** | Los siete `op.acc`, cuántas alertas toca cada uno y cuál es el principal. |
| **Informe** | Markdown y JSON para el informe de auditoría, más un anexo de tratamiento. Exportación opcional a evidencia técnica de ENS Compliance Studio, vacía si no hay alertas. Los textos del informe salen en español. |
| **Ajustes** | Tema claro y oscuro, acento, idioma ES/EN, densidad y reducción de movimiento. |
| **Ayuda** | Flujo, glosario, preguntas frecuentes y enlaces a Studio, Rosetta y KAIROS. |
| **Soporte y perfil** | Formulario local (no se envía a ningún sitio) y ficha del auditor. |
| **Arranque** | Splash estático: logo, nombre y barra. Con movimiento reducido, sin transiciones. |
| **Móvil** | Por debajo de 900 px, barra inferior y hoja «Más». Sin menú lateral. |

Las preferencias se guardan en el `localStorage` de este navegador. No se envían al backend.

## <img src="docs/assets/icons/image.svg" width="20" height="20" valign="middle"/> Capturas

Sin enumeración autorizada. «No comprobado» no es un dominio limpio.

<p align="center">
  <img src="docs/img/readme/cobertura.png" alt="Cobertura de la hoja de ruta, todas las filas no comprobado" width="880"/>
  <br/><sub><b>Cobertura</b> · sin enumeración autorizada. Cada fila dice «No comprobado». Tiering y Entra ID no ofrecen «Ver hallazgos». «No comprobado» no es un dominio limpio.</sub>
</p>

<p align="center">
  <img src="docs/img/readme/hallazgos.png" alt="Hallazgos filtrados por Kerberos, cero alertas" width="880"/>
  <br/><sub><b>Hallazgos</b> · filtro Área: Kerberos y 0 de 0 alertas. El vacío es falta de enumeración autorizada, no un dominio limpio.</sub>
</p>

<p align="center">
  <img src="docs/img/readme/informe.png" alt="Informe con cobertura no comprobado y sin alertas" width="880"/>
  <br/><sub><b>Informe</b> · controles sin alertas. La vista previa lista la cobertura como no comprobado. «No comprobado» no es un dominio limpio.</sub>
</p>

## <img src="docs/assets/icons/rocket.svg" width="20" height="20" valign="middle"/> Arranque rápido

**Requisitos:** Python 3.11 o superior, Node.js 20 o superior y npm.

```bash
git clone https://github.com/heindall92/ens_ad-auditor.git
cd ens_ad-auditor
```

```bash
# Backend
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

```bash
# Frontend, en otra terminal
cd frontend
npm install
npm run dev
```

El panel queda en `http://localhost:5173` y hace de proxy de `/api` hacia `http://127.0.0.1:8000`.

| Servicio | Dirección |
|---|---|
| Panel | `http://localhost:5173` |
| API (vacío, sin credenciales) | `GET http://127.0.0.1:8000/api/scan` |
| Auditoría en vivo | `POST http://127.0.0.1:8000/api/audit` |
| Informe | `GET` o `POST http://127.0.0.1:8000/api/report` |

Otros endpoints: `GET|POST /api/report.json` · `GET /api/export/studio` · `GET /api/controls` · `GET /api/mapping` · `GET /api/health`.

El cuerpo de `POST /api/audit` es JSON: `domain`, `dc_host`, `username`, `password` o `nthash`, y `authorized: true`. Sin `authorized` la API rechaza la petición. El secreto no se registra.

## <img src="docs/assets/icons/triangle-alert.svg" width="20" height="20" valign="middle"/> Aviso

Solo para auditorías y pentests autorizados. Enumerar un Active Directory exige autorización expresa por escrito del propietario. El uso no autorizado es ilegal.

La enumeración es de solo lectura: Kerberos (cuentas con SPN y sin preautenticación), delegación, plantillas AD CS (claves ESC que devuelva Certipy, sin pedir certificados), firma SMB, política de dominio, `krbtgt`, Protected Users, LDAP, trusts, LAPS (esquema), ACL del dominio y `GptTmpl.inf` si SYSVOL responde. No incluye explotación, relay, solicitud de tickets, volcado de NTDS ni lectura de contraseñas LAPS. Tiering y Entra ID quedan como no comprobado.

## <img src="docs/assets/icons/info.svg" width="20" height="20" valign="middle"/> Limitaciones conocidas

- **Sin credenciales, sin hallazgos.** `GET /api/scan`, `GET /api/report` y `GET /api/export/studio` no inventan datos: lista vacía e `is_sample: false`.
- **Credenciales en la petición.** Dominio, DC, usuario y contraseña o hash NT se envían a `POST /api/audit`. No se guardan en disco, en `localStorage` ni en el repositorio. El plan de tratamiento (responsable, estado y plazo) sí vive en el navegador y no es un hallazgo de directorio.
- **Alcance de la enumeración en vivo.** LDAP (Kerberos, delegación, política, trusts, LAPS esquema, DACL del dominio y presencia de atributos de secreto), Certipy `find` (AD CS, sin pedir certificados) e Impacket (firma SMB en el DC y hasta 48 equipos con `dNSHostName`, y lectura de `GptTmpl.inf` en SYSVOL). Un dominio grande puede dejar equipos sin comprobar en SMB. Si SYSVOL no se lee, GPO y monitorización quedan no comprobado.
- **LDAP signing.** El hallazgo de firma LDAP se infiere del bind observado: si la sesión entra por LDAP sin TLS, el DC no forzó un canal íntegro. Aparte, si se lee `GptTmpl.inf`, se informa `LDAPServerIntegrity` y `RequireSecuritySignature` solo con el valor visto en ese fichero.
- **Cobertura.** Cada fila de la hoja de ruta sale como comprobado o no comprobado. Tiering y Entra ID no se ejecutan. Una fila no comprobada no cuenta como dominio limpio.
- **LAPS.** Solo presencia de atributos de esquema y caducidad. No se leen contraseñas.
- **Informe en español.** El selector ES/EN cambia la interfaz. Los textos de las alertas y del informe los genera el backend en español, el idioma del ENS.
- **Sin dominio de prueba en este repositorio.** No hay cifras de un escaneo real porque no se ha auditado ningún dominio desde aquí.

## <img src="docs/assets/icons/map.svg" width="20" height="20" valign="middle"/> Hoja de ruta

El alcance (ahora / después) está en [ROADMAP.md](ROADMAP.md). Las filas de «Después» no se simulan.

## <img src="docs/assets/icons/shield-check.svg" width="20" height="20" valign="middle"/> Seguridad

Las credenciales de la enumeración no se escriben en disco ni en el navegador. El proceso de aviso y el modelo de amenazas están en [SECURITY.md](SECURITY.md). El historial de versiones está en [CHANGELOG.md](CHANGELOG.md).

La integración continua (`.github/workflows/tests.yml`) ejecuta `pytest`, el build del panel y comprueba que el build de Pages en `dist/` está al día.

## <img src="docs/assets/icons/folder-tree.svg" width="20" height="20" valign="middle"/> Estructura

```
ens_ad-auditor/
│
├── frontend/src/                 Panel React + TypeScript + Vite
│   ├── components/               Barra, hallazgos, matriz MAGERIT, splash, navegación móvil
│   ├── pages/                    Ajustes, Ayuda, Soporte, Perfil
│   ├── settings/                 Tema, acento, idioma (ES/EN)
│   └── api/                      Cliente de la API
│
├── backend/app/                  API FastAPI
│   ├── main.py                   Endpoints (scan vacío, audit en vivo, export Studio vacío)
│   ├── enumeration/              Kerberos, delegación, AD CS, SMB, política, ACL, secretos, SYSVOL (ldap3, impacket, certipy-ad)
│   ├── mapping/ens_mapping.py    Motor ENS [op.acc]
│   ├── mapping/magerit.py        Impacto × probabilidad y matriz
│   ├── studio_evidencia.py       Adaptador JSON para evidencia técnica de Studio
│   └── report.py                 Informe Markdown y JSON
│
├── backend/tests/                Pruebas del mapeo, MAGERIT, política, API y export Studio
├── .github/workflows/tests.yml   pytest + build del panel
├── SECURITY.md                   Credenciales: no se almacenan
├── CHANGELOG.md                  Historial de versiones
├── ROADMAP.md                    Roadmap de auditoría (ahora / después)
├── docs/img/readme/              Capturas de este README
└── LICENSE                       GPLv2
```

## <img src="docs/assets/icons/scale.svg" width="20" height="20" valign="middle"/> Licencia

Distribuido bajo licencia [GPLv2](LICENSE) · © 2026 Yoandy Ramírez Delgado.

Componentes de terceros: FastAPI (MIT), React (MIT), Vite (MIT). Iconografía de la consola y de este README: [Lucide](https://lucide.dev) (ISC).

Otras herramientas GRC del autor: [ENS Compliance Studio](https://github.com/heindall92/grc_ens_compliance_studio) (categorización, riesgos MAGERIT y Declaración de Aplicabilidad), [Rosetta](https://github.com/heindall92/rosetta_multinorma) (ENS, ISO/IEC 27001, NIS2 e ISO/IEC 42001) y [KAIROS](https://github.com/heindall92/kairos) (continuidad de negocio: BIA, BCP y DRP).

## <img src="docs/assets/icons/user.svg" width="20" height="20" valign="middle"/> Autor

<table>
<tr>
<td align="center" valign="top">
<img src="https://avatars.githubusercontent.com/u/238087465?v=4" alt="Yoandy Ramírez Delgado" width="96"/><br/>
<b>Yoandy Ramírez Delgado</b><br/>
<sub>Creador y mantenedor · Junior Pentester · eJPTv2</sub><br/>
<a href="https://www.linkedin.com/in/yoandyrd92/">LinkedIn</a> · <a href="https://github.com/heindall92">GitHub</a> · <a href="https://yoandyramirez.com">Portafolio</a> · <a href="https://profile.hackthebox.com/profile/019c5812-b4ca-7315-b12f-14db6d2b42fa">HackTheBox</a>
</td>
</tr>
</table>

¿Encontraste un problema? Abre una *issue* o escribe a <a href="mailto:yoandyramirezdelgado@gmail.com">yoandyramirezdelgado@gmail.com</a>.

![footer](https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=0,2,2,5,30&height=120&section=footer&animation=twinkling)
