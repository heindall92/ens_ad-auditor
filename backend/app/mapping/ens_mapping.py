"""
ENS mapping engine — the core differentiator of the tool.

Translates a technical Active Directory finding into one or more specific
non-compliances of the Spanish ENS (Esquema Nacional de Seguridad, RD 311/2022),
focused on the access-control family [op.acc].

Design goals:
  * DATA-DRIVEN: the whole knowledge base lives in `ENS_MAPPING`, a dict keyed
    by FindingType. Adding/adjusting a rule = editing data, not code.
  * VERSIONED & DEFENSIBLE: each rule maps to the *most defensible* op.acc
    control(s) and records why in `rationale`.
  * EXTENSIBLE: extra ENS dimensions (mp.com.*, op.exp.*) are noted in
    `references` while op.acc stays the cited primary family.

ENS [op.acc] control catalogue used here (RD 311/2022, marco operacional -
control de acceso):
  op.acc.1  Identificación
  op.acc.2  Requisitos de acceso
  op.acc.3  Segregación de funciones y tareas
  op.acc.4  Proceso de gestión de derechos de acceso
  op.acc.5  Mecanismo de autenticación
  op.acc.6  Acceso local (local logon)
  op.acc.7  Acceso remoto (remote login)

NOTE on numbering: this catalogue follows the numbering specified for this
project (legacy ENS RD 3/2010 lineage). In RD 311/2022 op.acc.5/op.acc.6 are
"Mecanismo de autenticación (usuarios externos / de la organización)" and local
/ remote access moved to op.acc.7 / op.acc.8. Because every rule references
controls only through ENS_CONTROLS ids, re-targeting to RD 311/2022 is a pure
data change (see README).
"""

from __future__ import annotations

from typing import Dict, List

from app.mapping.magerit import level_from_factors, score as magerit_score
from app.models import EnsControl, Finding, FindingType, GRCAlert, RiskLevel


# ---------------------------------------------------------------------------
# ENS [op.acc] control catalogue (single source of truth for names).
# ---------------------------------------------------------------------------
ENS_CONTROLS: Dict[str, str] = {
    "op.acc.1": "Identificación",
    "op.acc.2": "Requisitos de acceso",
    "op.acc.3": "Segregación de funciones y tareas",
    "op.acc.4": "Proceso de gestión de derechos de acceso",
    "op.acc.5": "Mecanismo de autenticación",
    "op.acc.6": "Acceso local (local logon)",
    "op.acc.7": "Acceso remoto (remote login)",
}


def _control(control_id: str, is_primary: bool = False) -> EnsControl:
    """Build an EnsControl from the catalogue, failing loud on typos."""
    if control_id not in ENS_CONTROLS:
        raise KeyError(f"Unknown ENS control id: {control_id}")
    return EnsControl(id=control_id, name=ENS_CONTROLS[control_id], is_primary=is_primary)


# ---------------------------------------------------------------------------
# The mapping knowledge base.
# Each entry is intentionally verbose so it reads as an auditable GRC rule.
# ---------------------------------------------------------------------------
ENS_MAPPING: Dict[FindingType, dict] = {
    # -- SMB signing ------------------------------------------------------
    FindingType.SMB_SIGNING_DISABLED: {
        "risk": RiskLevel.ALTO,
        "impact": 4,
        "likelihood": 3,
        "da_path": False,
        "controls": [
            ("op.acc.5", True),   # autenticación (integridad/autenticidad de sesión)
            ("op.acc.7", False),  # acceso remoto sobre canal no protegido
        ],
        "non_compliance": (
            "Riesgo Alto — Incumplimiento del control de protección de la "
            "confidencialidad e integridad en tránsito y de la autenticidad de "
            "la sesión del ENS. La ausencia de firma SMB (SMB signing no "
            "requerido) permite ataques de retransmisión (NTLM relay) y "
            "manipulación de tráfico (man-in-the-middle), comprometiendo la "
            "autenticación mutua exigida por [op.acc.5]."
        ),
        "remediation": (
            "Requerir la firma SMB en todos los sistemas mediante GPO: "
            "'Microsoft network server: Digitally sign communications (always) = "
            "Enabled' y su equivalente en cliente. Deshabilitar SMBv1, forzar "
            "EPA/channel binding en LDAP/HTTP y planificar la retirada de NTLM en "
            "favor de Kerberos."
        ),
        "references": [
            "mp.com.2 Protección de la confidencialidad (canal)",
            "mp.com.3 Protección de la integridad y autenticidad (canal)",
        ],
        "rationale": (
            "Se cita op.acc.5 como primario porque el impacto directo es sobre la "
            "autenticidad de la sesión (NTLM relay = suplantación de credenciales); "
            "mp.com.* se referencia por el componente de canal."
        ),
    },
    # -- Kerberoasting ----------------------------------------------------
    FindingType.KERBEROASTING: {
        "risk": RiskLevel.ALTO,
        "impact": 4,
        "likelihood": 3,
        "da_path": False,
        "controls": [
            ("op.acc.5", True),   # mecanismo de autenticación (cifrado débil RC4)
            ("op.acc.6", False),  # calidad de credenciales de cuentas de servicio
        ],
        "non_compliance": (
            "Riesgo Alto — Incumplimiento del mecanismo de autenticación del ENS "
            "[op.acc.5]. Existen cuentas con SPN que admiten cifrado RC4-HMAC "
            "(etype 23), permitiendo Kerberoasting: extracción offline y crackeo "
            "de contraseñas de cuentas de servicio. El mecanismo de autenticación "
            "no garantiza credenciales robustas ni algoritmos criptográficos "
            "adecuados."
        ),
        "remediation": (
            "Migrar cuentas de servicio a gMSA/dMSA con rotación automática; "
            "forzar AES (deshabilitar RC4 vía 'msDS-SupportedEncryptionTypes'); "
            "aplicar contraseñas largas (>25 caracteres) donde no sea posible "
            "gMSA; retirar SPN innecesarios y monitorizar solicitudes TGS masivas."
        ),
        "references": [
            "op.acc.1 Identificación (cuentas de servicio identificadas)",
            "op.exp.8 Registro de la actividad (detección de TGS anómalos)",
        ],
        "rationale": (
            "op.acc.5 es el control más defendible: el hallazgo es un fallo del "
            "mecanismo de autenticación (algoritmo débil + credencial crackeable)."
        ),
    },
    # -- AS-REP roasting --------------------------------------------------
    FindingType.ASREP_ROASTING: {
        "risk": RiskLevel.ALTO,
        "impact": 4,
        "likelihood": 3,
        "da_path": False,
        "controls": [
            ("op.acc.5", True),   # mecanismo de autenticación (sin pre-auth)
            ("op.acc.6", False),
        ],
        "non_compliance": (
            "Riesgo Alto — Incumplimiento del mecanismo de autenticación del ENS "
            "[op.acc.5]. Cuentas con el flag DONT_REQUIRE_PREAUTH permiten "
            "AS-REP Roasting: un atacante no autenticado obtiene material cifrado "
            "con el hash de la contraseña para crackeo offline. Se debilita la "
            "pre-autenticación de Kerberos exigida por un mecanismo robusto."
        ),
        "remediation": (
            "Eliminar el flag 'Do not require Kerberos preauthentication' de todas "
            "las cuentas (UAC 0x400000); si alguna cuenta legada lo necesita, "
            "aislarla, forzar contraseña larga/AES y monitorizar. Revisar "
            "periódicamente con consultas LDAP el atributo userAccountControl."
        ),
        "references": [
            "op.acc.1 Identificación",
            "op.exp.8 Registro de la actividad",
        ],
        "rationale": (
            "El defecto reside en la pre-autenticación (mecanismo de "
            "autenticación), de ahí op.acc.5 como primario."
        ),
    },
    # -- Unconstrained delegation ----------------------------------------
    FindingType.UNCONSTRAINED_DELEGATION: {
        "risk": RiskLevel.CRITICO,
        "impact": 5,
        "likelihood": 4,
        "da_path": True,
        "controls": [
            ("op.acc.4", True),   # proceso de gestión de derechos de acceso
            ("op.acc.2", False),  # requisitos de acceso
            ("op.acc.3", False),  # segregación de funciones
        ],
        "non_compliance": (
            "Riesgo Crítico — Incumplimiento del proceso de gestión de derechos "
            "de acceso del ENS [op.acc.4]. La delegación no restringida "
            "(unconstrained delegation) permite que un host almacene TGT de "
            "cualquier usuario que se autentique contra él, incluidos "
            "administradores de dominio, habilitando la suplantación total y la "
            "escalada a Domain Admin. Los derechos de acceso concedidos exceden "
            "cualquier necesidad legítima."
        ),
        "remediation": (
            "Eliminar la delegación no restringida; sustituir por delegación "
            "restringida basada en recursos (RBCD) con el mínimo de servicios. "
            "Marcar las cuentas sensibles como 'Account is sensitive and cannot "
            "be delegated' y añadirlas al grupo 'Protected Users'. Revisar el "
            "atributo TrustedForDelegation en todos los equipos."
        ),
        "references": [
            "op.acc.3 Segregación de funciones y tareas",
            "op.acc.2 Requisitos de acceso",
        ],
        "rationale": (
            "op.acc.4 es primario porque es un derecho de acceso mal gestionado "
            "que rompe el principio de mínimo privilegio a nivel de dominio."
        ),
    },
    # -- Constrained / RBCD misconfig ------------------------------------
    FindingType.CONSTRAINED_RBCD_DELEGATION: {
        "risk": RiskLevel.ALTO,
        "impact": 4,
        "likelihood": 3,
        "da_path": False,
        "controls": [
            ("op.acc.4", True),   # proceso de gestión de derechos de acceso
            ("op.acc.3", False),  # segregación de funciones
        ],
        "non_compliance": (
            "Riesgo Alto — Incumplimiento del proceso de gestión de derechos de "
            "acceso del ENS [op.acc.4]. Una configuración incorrecta de "
            "delegación restringida (con protocol transition / S4U2Self) o de "
            "RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity escribible por "
            "principales no privilegiados) permite la suplantación de usuarios "
            "hacia servicios concretos y rutas de escalada de privilegios."
        ),
        "remediation": (
            "Auditar msDS-AllowedToDelegateTo y "
            "msDS-AllowedToActOnBehalfOfOtherIdentity; limitar quién puede "
            "escribir estos atributos; evitar 'protocol transition' salvo "
            "necesidad justificada; documentar y revisar periódicamente cada "
            "relación de delegación bajo control de cambios."
        ),
        "references": [
            "op.acc.3 Segregación de funciones y tareas",
            "op.acc.2 Requisitos de acceso",
        ],
        "rationale": (
            "Igual que la delegación no restringida, es un derecho de acceso mal "
            "gestionado (op.acc.4), aunque el alcance es más acotado -> Alto."
        ),
    },
    # -- Excessive privileges / least privilege --------------------------
    FindingType.EXCESSIVE_PRIVILEGES: {
        "risk": RiskLevel.ALTO,
        "impact": 4,
        "likelihood": 3,
        "da_path": True,
        "controls": [
            ("op.acc.2", True),   # requisitos de acceso (mínimo privilegio)
            ("op.acc.4", False),  # gestión de derechos de acceso
            ("op.acc.3", False),  # segregación de funciones
        ],
        "non_compliance": (
            "Riesgo Alto — Incumplimiento de los requisitos de acceso del ENS "
            "[op.acc.2] y del principio de mínimo privilegio. Se detectan usuarios "
            "en grupos privilegiados (Domain Admins, Enterprise Admins, Account "
            "Operators, etc.) sin necesidad justificada, ampliando la superficie "
            "de ataque y vulnerando la segregación de funciones."
        ),
        "remediation": (
            "Aplicar mínimo privilegio y modelo de administración por niveles "
            "(tiering); retirar miembros innecesarios de grupos privilegiados; "
            "usar cuentas administrativas dedicadas y PAM/JIT; revisar "
            "periódicamente la pertenencia a grupos y documentar la necesidad de "
            "cada asignación."
        ),
        "references": [
            "op.acc.3 Segregación de funciones y tareas",
            "op.acc.4 Proceso de gestión de derechos de acceso",
        ],
        "rationale": (
            "op.acc.2 es primario: el hallazgo es que los derechos concedidos no "
            "responden a un requisito de acceso legítimo (mínimo privilegio)."
        ),
    },
    # -- ADCS ESC1-ESC8 ---------------------------------------------------
    FindingType.ADCS_ESC: {
        "risk": RiskLevel.CRITICO,
        "impact": 5,
        "likelihood": 4,
        "da_path": True,
        "controls": [
            ("op.acc.5", True),   # mecanismo de autenticación (certificados)
            ("op.acc.4", False),  # gestión de derechos (enrollment rights)
        ],
        "non_compliance": (
            "Riesgo Crítico — Incumplimiento del mecanismo de autenticación del "
            "ENS [op.acc.5] y de la gestión de derechos de acceso [op.acc.4]. "
            "Plantillas de certificado o configuraciones de AD CS vulnerables "
            "(ESC1-ESC8: SAN arbitrario, EKU de autenticación de cliente con "
            "enrolamiento amplio, agentes de inscripción, ESC6/EDITF_ATTRIBUTESUBJECTALTNAME2, "
            "ESC8 relay a la web enrollment) permiten emitir certificados que "
            "suplantan a cualquier usuario, incluido Domain Admin, comprometiendo "
            "la autenticación basada en PKI."
        ),
        "remediation": (
            "Revisar plantillas con Certipy/PSPKIAudit; desactivar "
            "'ENROLLEE_SUPPLIES_SUBJECT' en plantillas con EKU de autenticación; "
            "restringir derechos de inscripción y de escritura sobre plantillas; "
            "deshabilitar EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6); habilitar "
            "aprobación del gestor de certificados; deshabilitar HTTP/NTLM en la "
            "inscripción web y exigir HTTPS+EPA (ESC8); aplicar el parche de "
            "certificate mapping fuerte (KB5014754)."
        ),
        "references": [
            "op.acc.1 Identificación (identidad ligada al certificado)",
            "op.exp.8 Registro de la actividad (auditoría de emisión de certs)",
        ],
        "rationale": (
            "op.acc.5 es primario porque el abuso de ADCS es, en esencia, una "
            "ruptura del mecanismo de autenticación (emisión de credenciales PKI "
            "falsas); op.acc.4 acompaña por los derechos de inscripción excesivos."
        ),
    },
    FindingType.WEAK_PASSWORD_POLICY: {
        "risk": RiskLevel.ALTO,
        "impact": 4,
        "likelihood": 3,
        "da_path": False,
        "controls": [
            ("op.acc.5", True),
            ("op.acc.6", False),
        ],
        "non_compliance": (
            "Riesgo Alto — Incumplimiento del mecanismo de autenticación del ENS "
            "[op.acc.5]. La política de contraseñas del dominio no impone longitud, "
            "caducidad o historial suficientes, lo que debilita las credenciales "
            "de toda la organización."
        ),
        "remediation": (
            "Elevar minPwdLength (14 o más), historial y complejidad; evitar "
            "contraseñas que no caduquen en cuentas de usuario; aplicar Fine-Grained "
            "Password Policies a cuentas privilegiadas."
        ),
        "references": ["op.acc.1 Identificación"],
        "rationale": "La calidad de la contraseña es el mecanismo de autenticación (op.acc.5).",
    },
    FindingType.WEAK_LOCKOUT_POLICY: {
        "risk": RiskLevel.MEDIO,
        "impact": 3,
        "likelihood": 3,
        "da_path": False,
        "controls": [
            ("op.acc.6", True),
            ("op.acc.5", False),
        ],
        "non_compliance": (
            "Riesgo Medio — Incumplimiento del acceso local del ENS [op.acc.6]. "
            "El umbral de bloqueo de cuenta es nulo o demasiado alto, lo que permite "
            "pruebas de contraseña sin contención."
        ),
        "remediation": (
            "Definir lockoutThreshold (p. ej. 5–10), lockoutDuration y la ventana "
            "de observación. Coordinar con monitorización para no facilitar DoS."
        ),
        "references": ["op.acc.5 Mecanismo de autenticación"],
        "rationale": "El bloqueo es una salvaguarda del acceso local (op.acc.6).",
    },
    FindingType.KRBTGT_PASSWORD_AGE: {
        "risk": RiskLevel.ALTO,
        "impact": 5,
        "likelihood": 2,
        "da_path": False,
        "controls": [
            ("op.acc.5", True),
            ("op.acc.4", False),
        ],
        "non_compliance": (
            "Riesgo Alto — Incumplimiento del mecanismo de autenticación del ENS "
            "[op.acc.5]. La cuenta krbtgt no ha rotado su contraseña en el plazo "
            "recomendado; un KRBTGT comprometido permite Golden Tickets."
        ),
        "remediation": (
            "Rotar krbtgt dos veces (reset secuencial) según el procedimiento de "
            "Microsoft; documentar la cadencia (180 días o menos) y vigilar TGT anómalos."
        ),
        "references": ["op.exp.8 Registro de la actividad"],
        "rationale": "krbtgt es la clave del mecanismo Kerberos (op.acc.5).",
    },
    FindingType.PROTECTED_USERS_GAP: {
        "risk": RiskLevel.ALTO,
        "impact": 4,
        "likelihood": 3,
        "da_path": False,
        "controls": [
            ("op.acc.2", True),
            ("op.acc.4", False),
        ],
        "non_compliance": (
            "Riesgo Alto — Incumplimiento de los requisitos de acceso del ENS "
            "[op.acc.2]. Cuentas privilegiadas no están en Protected Users, así que "
            "siguen expuestas a NTLM, delegación y caché de credenciales débiles."
        ),
        "remediation": (
            "Incluir las cuentas administrativas de usuario en Protected Users "
            "tras validar compatibilidad (no equipos, no servicios con NTLM)."
        ),
        "references": ["op.acc.4 Proceso de gestión de derechos de acceso"],
        "rationale": "Protected Users es un requisito de acceso para privilegio (op.acc.2).",
    },
    FindingType.ADMIN_WITH_SPN: {
        "risk": RiskLevel.CRITICO,
        "impact": 5,
        "likelihood": 4,
        "da_path": True,
        "controls": [
            ("op.acc.5", True),
            ("op.acc.4", False),
        ],
        "non_compliance": (
            "Riesgo Crítico — Incumplimiento del mecanismo de autenticación del ENS "
            "[op.acc.5]. Una cuenta privilegiada tiene SPN: es kerberoasteable y, "
            "si se rompe la contraseña, da un camino directo a administrador de dominio."
        ),
        "remediation": (
            "Retirar SPN de cuentas privilegiadas; usar gMSA para servicios; "
            "separar la identidad administrativa de la de servicio."
        ),
        "references": ["op.acc.2 Requisitos de acceso"],
        "rationale": "Privilegio más SPN es autenticación débil con impacto de DA (op.acc.5).",
    },
    FindingType.STALE_PRIVILEGED_ACCOUNT: {
        "risk": RiskLevel.MEDIO,
        "impact": 3,
        "likelihood": 3,
        "da_path": False,
        "controls": [
            ("op.acc.4", True),
            ("op.acc.2", False),
        ],
        "non_compliance": (
            "Riesgo Medio — Incumplimiento del proceso de gestión de derechos del ENS "
            "[op.acc.4]. Hay cuentas privilegiadas sin inicio de sesión reciente: "
            "derechos que no se revisan y que permanecen atacables."
        ),
        "remediation": (
            "Revisar lastLogonTimestamp de grupos privilegiados; deshabilitar o "
            "retirar cuentas inactivas; aplicar recertificación periódica."
        ),
        "references": ["op.acc.3 Segregación de funciones y tareas"],
        "rationale": "La vigencia del derecho es gestión de accesos (op.acc.4).",
    },
    FindingType.LDAP_SIGNING_NOT_REQUIRED: {
        "risk": RiskLevel.ALTO,
        "impact": 4,
        "likelihood": 3,
        "da_path": False,
        "controls": [
            ("op.acc.5", True),
            ("op.acc.7", False),
        ],
        "non_compliance": (
            "Riesgo Alto — Incumplimiento del mecanismo de autenticación del ENS "
            "[op.acc.5]. El DC aceptó un enlace LDAP sin firma ni TLS: el canal de "
            "directorio no exige integridad."
        ),
        "remediation": (
            "Exigir LDAP signing (LdapServerIntegrity=2) y preferir LDAPS; "
            "deshabilitar LDAP unsigned en los DC."
        ),
        "references": ["mp.com.3 Protección de la integridad y autenticidad (canal)"],
        "rationale": "La integridad del enlace LDAP es autenticación de sesión (op.acc.5).",
    },
    FindingType.LDAP_CHANNEL_BINDING_WEAK: {
        "risk": RiskLevel.ALTO,
        "impact": 4,
        "likelihood": 3,
        "da_path": False,
        "controls": [
            ("op.acc.5", True),
            ("op.acc.7", False),
        ],
        "non_compliance": (
            "Riesgo Alto — Incumplimiento del mecanismo de autenticación del ENS "
            "[op.acc.5]. Channel binding LDAP no está en modo Always, o el DC "
            "aceptó LDAP sin TLS, lo que facilita relay NTLM contra LDAP."
        ),
        "remediation": (
            "Poner msDS-LdapEnforceChannelBinding en 2 (always) y exigir LDAPS; "
            "aplicar EPA en los servicios que hablen LDAP."
        ),
        "references": ["op.acc.7 Acceso remoto"],
        "rationale": "Channel binding cierra el relay contra el autenticador (op.acc.5).",
    },
    FindingType.TRUST_SID_FILTERING: {
        "risk": RiskLevel.ALTO,
        "impact": 4,
        "likelihood": 3,
        "da_path": False,
        "controls": [
            ("op.acc.4", True),
            ("op.acc.2", False),
        ],
        "non_compliance": (
            "Riesgo Alto — Incumplimiento de la gestión de derechos del ENS "
            "[op.acc.4]. Hay un trust externo o de bosque sin SID filtering "
            "(quarantine), lo que permite SID history desde el dominio de confianza."
        ),
        "remediation": (
            "Activar SID filtering (quarantine) en trusts externos; revisar "
            "dirección y transividad; documentar cada trust."
        ),
        "references": ["op.acc.2 Requisitos de acceso"],
        "rationale": "Un trust es un derecho de acceso entre dominios (op.acc.4).",
    },
    FindingType.LAPS_NOT_DEPLOYED: {
        "risk": RiskLevel.ALTO,
        "impact": 4,
        "likelihood": 3,
        "da_path": False,
        "controls": [
            ("op.acc.5", True),
            ("op.acc.6", False),
        ],
        "non_compliance": (
            "Riesgo Alto — Incumplimiento del mecanismo de autenticación del ENS "
            "[op.acc.5] y del acceso local [op.acc.6]. LAPS (legacy o Windows LAPS) "
            "no está en el esquema o no hay equipos con caducidad de contraseña local: "
            "la cuenta local de administrador puede estar reutilizada."
        ),
        "remediation": (
            "Extender el esquema con Windows LAPS, aplicar la GPO y conceder lectura "
            "solo a quien administre esos equipos. No reutilizar la clave local."
        ),
        "references": ["op.acc.4 Proceso de gestión de derechos de acceso"],
        "rationale": "La contraseña local del equipo es autenticación local (op.acc.5 / op.acc.6).",
    },
    FindingType.MACHINE_ACCOUNT_QUOTA: {
        "risk": RiskLevel.MEDIO,
        "impact": 3,
        "likelihood": 3,
        "da_path": False,
        "controls": [
            ("op.acc.4", True),
            ("op.acc.1", False),
        ],
        "non_compliance": (
            "Riesgo Medio — Incumplimiento de la gestión de derechos del ENS "
            "[op.acc.4]. ms-DS-MachineAccountQuota permite a un usuario unir "
            "equipos al dominio sin control de altas."
        ),
        "remediation": (
            "Poner ms-DS-MachineAccountQuota a 0 y unir equipos solo con cuentas "
            "delegadas (pre-stage o grupos de alta de equipos)."
        ),
        "references": ["op.acc.1 Identificación"],
        "rationale": "Unir un equipo es un alta de identidad (op.acc.4 / op.acc.1).",
    },
}


# ---------------------------------------------------------------------------
# Optional per-subtype overrides. Lets one FindingType (e.g. ADCS_ESC) refine
# risk / controls / text for a specific variant (ESC1..ESC8) without adding a
# new FindingType. Only the provided keys override the base rule.
# ---------------------------------------------------------------------------
SUBTYPE_OVERRIDES: Dict[FindingType, Dict[str, dict]] = {
    FindingType.CONSTRAINED_RBCD_DELEGATION: {
        "rbcd_writable": {
            "da_path": True,
            "impact": 4,
            "likelihood": 3,
        },
    },
    FindingType.ADCS_ESC: {
        "ESC1": {
            "non_compliance": (
                "Riesgo Crítico — ESC1. Incumplimiento del mecanismo de "
                "autenticación del ENS [op.acc.5] y de la gestión de derechos "
                "[op.acc.4]. Una plantilla con ENROLLEE_SUPPLIES_SUBJECT, EKU de "
                "autenticación de cliente y derechos de inscripción amplios permite "
                "a cualquier usuario emitir un certificado con un SAN arbitrario y "
                "suplantar a un administrador de dominio."
            ),
            "remediation": (
                "Deshabilitar ENROLLEE_SUPPLIES_SUBJECT en la plantilla o restringir "
                "los derechos de inscripción a un grupo mínimo; exigir aprobación del "
                "gestor de certificados; auditar la plantilla con Certipy."
            ),
        },
        "ESC6": {
            "non_compliance": (
                "Riesgo Crítico — ESC6. Incumplimiento del mecanismo de "
                "autenticación del ENS [op.acc.5]. El flag "
                "EDITF_ATTRIBUTESUBJECTALTNAME2 a nivel de CA permite especificar un "
                "SAN arbitrario en CUALQUIER solicitud, habilitando la suplantación "
                "de cualquier principal aunque la plantilla no lo permita."
            ),
            "remediation": (
                "Deshabilitar EDITF_ATTRIBUTESUBJECTALTNAME2 en la CA "
                "('certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2' "
                "y reiniciar el servicio); aplicar el mapeo fuerte de certificados "
                "(KB5014754)."
            ),
        },
        "ESC8": {
            "controls": [
                ("op.acc.5", True),   # autenticación (relay NTLM -> certificado)
                ("op.acc.7", False),  # acceso remoto por canal HTTP no protegido
                ("op.acc.4", False),
            ],
            "impact": 5,
            "likelihood": 4,
            "da_path": True,
            "non_compliance": (
                "Riesgo Crítico — ESC8. Incumplimiento del mecanismo de "
                "autenticación del ENS [op.acc.5] y del acceso remoto [op.acc.7]. La "
                "inscripción web (Web Enrollment) acepta NTLM sobre HTTP, permitiendo "
                "un relay de la autenticación de una cuenta de equipo hacia la CA para "
                "obtener un certificado de autenticación."
            ),
            "remediation": (
                "Deshabilitar la inscripción web por HTTP/NTLM; exigir HTTPS con EPA "
                "(Extended Protection for Authentication); habilitar firma de canal y "
                "considerar deshabilitar NTLM en la CA."
            ),
        },
    },
}


# ---------------------------------------------------------------------------
# Engine functions.
# ---------------------------------------------------------------------------
def map_finding(finding: Finding) -> GRCAlert:
    """Translate a single technical Finding into an ENS GRCAlert.

    The base rule is selected by ``finding.finding_type``. If the finding carries
    a ``subtype`` (e.g. "ESC1") and a matching override exists, the override keys
    are merged on top of the base rule so a single FindingType can express many
    concrete variants without new code.
    """
    rule = ENS_MAPPING.get(finding.finding_type)
    if rule is None:
        impact, likelihood = 3, 3
        return GRCAlert(
            rule_id=f"{finding.finding_type.value}:unmapped",
            finding=finding,
            risk=RiskLevel.MEDIO,
            ens_controls=[_control("op.acc.4", is_primary=True)],
            non_compliance=(
                "Hallazgo técnico sin regla ENS específica. Revisar manualmente "
                "su encaje en el marco [op.acc]."
            ),
            remediation="Analizar el hallazgo y asignar el control ENS adecuado.",
            references=[],
            rationale="Sin regla en ENS_MAPPING; se asigna un control por defecto.",
            impact=impact,
            likelihood=likelihood,
            score=magerit_score(impact, likelihood),
            da_path=False,
        )

    # Start from the base rule, then apply subtype overrides if any.
    merged = dict(rule)
    rule_id = finding.finding_type.value
    subtype = getattr(finding, "subtype", None)
    if subtype:
        rule_id = f"{rule_id}:{subtype}"
        override = SUBTYPE_OVERRIDES.get(finding.finding_type, {}).get(subtype)
        if override:
            merged.update(override)

    controls = [_control(cid, is_primary=prim) for cid, prim in merged["controls"]]
    impact = int(merged.get("impact", 3))
    likelihood = int(merged.get("likelihood", 3))
    return GRCAlert(
        rule_id=rule_id,
        finding=finding,
        risk=level_from_factors(impact, likelihood),
        ens_controls=controls,
        non_compliance=merged["non_compliance"],
        remediation=merged["remediation"],
        references=list(merged.get("references", [])),
        rationale=merged.get("rationale"),
        impact=impact,
        likelihood=likelihood,
        score=magerit_score(impact, likelihood),
        da_path=bool(merged.get("da_path", False)),
    )


def map_findings(findings: List[Finding]) -> List[GRCAlert]:
    """Translate a batch of findings, sorted by descending risk severity."""
    alerts = [map_finding(f) for f in findings]
    alerts.sort(key=lambda a: a.risk.order, reverse=True)
    return alerts


def export_rules() -> List[dict]:
    """Return the knowledge base as plain JSON-friendly dicts (for /api/mapping)."""
    out: List[dict] = []
    for ftype, rule in ENS_MAPPING.items():
        out.append(
            {
                "finding_type": ftype.value,
                "risk": rule["risk"].value,
                "controls": [
                    {"id": cid, "name": ENS_CONTROLS[cid], "is_primary": prim}
                    for cid, prim in rule["controls"]
                ],
                "non_compliance": rule["non_compliance"],
                "remediation": rule["remediation"],
                "references": rule.get("references", []),
                "rationale": rule.get("rationale"),
                "impact": rule.get("impact"),
                "likelihood": rule.get("likelihood"),
                "da_path": bool(rule.get("da_path", False)),
                "magerit_risk": level_from_factors(
                    int(rule.get("impact", 3)), int(rule.get("likelihood", 3))
                ).value,
                "subtypes": sorted(SUBTYPE_OVERRIDES.get(ftype, {}).keys()),
            }
        )
    return out
