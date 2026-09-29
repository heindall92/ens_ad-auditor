# ENS AD Auditor

Auditor de Active Directory mapeado al Esquema Nacional de Seguridad (ENS).

Enumera un dominio (Kerberos flojo, delegación de privilegios, AD CS y SMB) y traduce cada hallazgo a un incumplimiento de los controles ENS, sobre todo de la familia **`[op.acc]`**.

En vez de decir solo "SMB Signing deshabilitado" o "Kerberoasting posible", saca una alerta GRC. Por ejemplo:

> **Riesgo Alto. Incumplimiento del control de mecanismo de autenticación del ENS `[op.acc.5]`**
> con la descripción del incumplimiento y la remediación.

---

## Aviso legal

Solo para auditorías y pentests autorizados. Enumerar un Active Directory exige autorización expresa por escrito del propietario. El uso no autorizado es ilegal. Esta versión no escanea la red: los módulos de enumeración devuelven datos de muestra marcados (`is_sample: true`).

---

## Arquitectura

```
ens-ad-auditor/
├── backend/                    # API Python (FastAPI)
│   └── app/
│       ├── main.py             # Endpoints REST
│       ├── models.py           # Modelos Pydantic (Finding, GRCAlert, EnsControl)
│       ├── enumeration/        # Módulos de enumeración (kerberos, delegation, adcs, smb)
│       ├── mapping/            # Motor de mapeo ENS [op.acc]
│       └── report.py           # Informe JSON + Markdown
└── frontend/                   # Panel GRC (React + TypeScript + Vite)
    └── src/
        ├── App.tsx
        ├── components/         # Sidebar, TopBar, FindingCard, ControlsTable, Splash…
        ├── pages/              # Ajustes, Ayuda, Soporte, Perfil
        ├── settings/           # Contexto de tema/acento/idioma + i18n ES/EN
        └── api/client.ts
```

**Flujo:** enumeración, motor de mapeo ENS, alertas GRC (riesgo, incumplimiento, remediación), panel e informe.

### Motor de mapeo

`backend/app/mapping/ens_mapping.py` tiene una tabla que traduce cada tipo de hallazgo a los controles `[op.acc]` que le tocan:

| Hallazgo técnico | Control ENS principal |
|---|---|
| SMB signing deshabilitado | `op.acc` (autenticación / protección en tránsito) |
| Kerberoasting (SPN con RC4) | `op.acc.5` mecanismo de autenticación |
| AS-REP roasting (sin preautenticación) | `op.acc.5` / `op.acc.6` |
| Delegación no restringida | `op.acc.4` gestión de derechos de acceso |
| RBCD / delegación restringida mal configurada | `op.acc.4` |
| Privilegios excesivos / mínimo privilegio | `op.acc.2` / `op.acc.4` |
| AD CS ESC1–ESC8 | `op.acc.5` / `op.acc.4` |

Controles `[op.acc]` de referencia: `op.acc.1` identificación · `op.acc.2` requisitos de acceso · `op.acc.3` segregación de funciones · `op.acc.4` gestión de derechos de acceso · `op.acc.5` mecanismo de autenticación · `op.acc.6` acceso local · `op.acc.7` acceso remoto.

---

## Cómo ejecutarlo

### Backend (API)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Endpoints: `GET /api/scan` (alertas GRC) · `GET /api/report` (Markdown) · `GET /api/report.json` · `GET /api/controls` · `GET /api/mapping`.

### Frontend (panel)

```bash
cd frontend
npm install
npm run dev            # http://localhost:5173  (proxy /api -> :8000)
```

Levanta primero el backend; el frontend proxya `/api` a `http://127.0.0.1:8000`.

---

## Estado actual

- Backend FastAPI con el pipeline completo (enumeración, mapeo, alertas e informe).
- Motor de mapeo ENS `[op.acc]` basado en datos y cubierto con `pytest`.
- Panel React/TS con resumen por riesgo, filtros y descarga de informe.
- Pendiente: sustituir los stubs de `app/enumeration/` por enumeración en vivo (`ldap3`, `impacket`, `certipy-ad`). Las dependencias ya están en `requirements.txt`.
