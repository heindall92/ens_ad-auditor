import type { Lang } from "../settings/i18n";
import type { IconName } from "../components/Icon";
import type { SectionId } from "../components/Sidebar";

// Long-form help content, kept apart from the flat UI dictionary.

export interface FlowNode {
  icon: IconName;
  title: string;
  sub: string;
}

export interface HelpContent {
  flowIn: FlowNode[];
  flowCore: FlowNode;
  flowOut: FlowNode[];
  stepsTitle: string;
  steps: { title: string; text: string; go: SectionId }[];
  notes: { title: string; text: string }[];
  glossary: [term: string, definition: string][];
  faq: [question: string, answer: string][];
  about: string[];
}

const es: HelpContent = {
  flowIn: [
    { icon: "lock", title: "Kerberos", sub: "Kerberoasting · AS-REP roasting" },
    { icon: "layers", title: "Delegación y privilegios", sub: "No restringida · RBCD · Domain Admins" },
    { icon: "fileCheck", title: "AD CS", sub: "Plantillas y CA · ESC1–ESC8" },
    { icon: "server", title: "SMB", sub: "Firma de mensajes" },
  ],
  flowCore: {
    icon: "shieldCheck",
    title: "Motor de mapeo ENS [op.acc]",
    sub: "Cada tipo de hallazgo pasa a controles op.acc (el principal y los relacionados), un nivel de riesgo, el incumplimiento y la remediación.",
  },
  flowOut: [
    { icon: "alert", title: "Alertas GRC", sub: "Riesgo · incumplimiento · remediación" },
    { icon: "dashboard", title: "Panel", sub: "KPIs, filtros y controles afectados" },
    { icon: "download", title: "Informe", sub: "Markdown · JSON" },
  ],
  stepsTitle: "Paso a paso",
  steps: [
    {
      title: "Enumeración de Active Directory",
      text: "Los módulos de Kerberos, delegación, AD CS y SMB recogen hallazgos técnicos. En esta versión devuelven datos de muestra marcados como tales.",
      go: "panel",
    },
    {
      title: "Motor de mapeo ENS [op.acc]",
      text: "Cada hallazgo se asocia a los controles de acceso del ENS afectados y se le asigna un nivel de riesgo: Crítico, Alto, Medio o Bajo.",
      go: "controles",
    },
    {
      title: "Alertas GRC",
      text: "La alerta dice qué control se incumple, por qué y cómo remediarlo, con la evidencia técnica.",
      go: "hallazgos",
    },
    {
      title: "Informe",
      text: "Descarga el Markdown con el resumen y el detalle de cada alerta, para el informe de auditoría.",
      go: "informe",
    },
  ],
  notes: [
    {
      title: "Control principal",
      text: "Cada alerta marca un control op.acc principal (el que se incumple directamente) y otros relacionados. La tabla de controles cuenta ambos.",
    },
    {
      title: "Nivel de riesgo",
      text: "Lo fija la regla de mapeo según el impacto de la técnica: una vía directa a administrador de dominio es Crítico; una credencial crackeable, Alto.",
    },
    {
      title: "Datos de muestra",
      text: "Mientras el banner de demostración esté visible, ningún dato procede de un dominio real. No hay escaneo en red en esta versión.",
    },
  ],
  glossary: [
    ["Kerberoasting", "Solicitud de tickets de servicio (TGS) para cuentas con SPN y crackeo offline de su contraseña. Especialmente grave si la cuenta admite cifrado RC4."],
    ["AS-REP roasting", "Cuentas con «No requerir preautenticación Kerberos»: cualquiera puede pedir un AS-REP cifrado con la clave del usuario y crackearlo offline."],
    ["Delegación no restringida", "El equipo o cuenta recibe y guarda el TGT de quien se autentica contra él, y puede suplantarlo ante cualquier servicio. Si se compromete, expone a los administradores que se conecten."],
    ["Delegación restringida", "La delegación se limita a una lista de servicios (msDS-AllowedToDelegateTo). Mal configurada, con transición de protocolo, sigue permitiendo suplantar usuarios."],
    ["RBCD", "Resource-Based Constrained Delegation: el recurso decide quién puede delegar en él (msDS-AllowedToActOnBehalfOfOtherIdentity). Si un principal no privilegiado puede escribir ese atributo, puede suplantar a cualquier usuario ante el recurso."],
    ["AD CS", "Active Directory Certificate Services, la PKI de Windows. Sus plantillas y la configuración de la CA son la fuente de las técnicas ESC1–ESC8."],
    ["ESC1", "Plantilla que permite al solicitante indicar el sujeto (SAN), con EKU de autenticación de cliente y sin aprobación: un usuario sin privilegios obtiene un certificado como administrador."],
    ["ESC2", "Plantilla con EKU «Any Purpose» o sin EKU inscribible por usuarios sin privilegios: el certificado sirve para cualquier uso, incluida la autenticación."],
    ["ESC3", "Plantilla con EKU de agente de inscripción (Certificate Request Agent): permite solicitar certificados en nombre de otros usuarios."],
    ["ESC4", "Permisos de escritura sobre una plantilla de certificado: el atacante la modifica para volverla vulnerable a ESC1."],
    ["ESC5", "Permisos débiles sobre objetos de la PKI en AD (equipo de la CA, contenedores de configuración) que permiten comprometer la infraestructura de certificados."],
    ["ESC6", "La CA tiene activado EDITF_ATTRIBUTESUBJECTALTNAME2: cualquier solicitud puede incluir un SAN arbitrario y suplantar a otro usuario."],
    ["ESC7", "Permisos peligrosos sobre la propia CA (ManageCA, ManageCertificates): permiten activar opciones inseguras o aprobar solicitudes pendientes."],
    ["ESC8", "NTLM relay contra la inscripción web de AD CS (HTTP sin EPA): se retransmite la autenticación de un equipo, p. ej. un DC, y se obtiene un certificado a su nombre."],
    ["SMB signing", "Firma de mensajes SMB. Si no es obligatoria, un atacante en la red puede retransmitir autenticaciones NTLM (relay) y ejecutar acciones como la víctima."],
    ["op.acc.1 · Identificación", "Cada usuario debe tener una identidad única y asignada a una persona o servicio responsable."],
    ["op.acc.2 · Requisitos de acceso", "Los derechos de acceso se conceden según la necesidad de conocer y el mínimo privilegio."],
    ["op.acc.3 · Segregación de funciones y tareas", "Ninguna persona debe acumular funciones críticas incompatibles, p. ej. administrar y auditar."],
    ["op.acc.4 · Proceso de gestión de derechos de acceso", "Alta, modificación y revisión periódica de los derechos, incluidas delegaciones y permisos sobre objetos."],
    ["op.acc.5 · Mecanismo de autenticación", "Cómo se autentica: protocolos, cifrado, certificados y protección de credenciales."],
    ["op.acc.6 · Acceso local (local logon)", "Condiciones del inicio de sesión local en los sistemas: credenciales, bloqueos y protección de secretos."],
    ["op.acc.7 · Acceso remoto (remote login)", "Protección del acceso a través de la red: canales cifrados, firmados y autenticados."],
  ],
  faq: [
    ["¿La herramienta escanea mi dominio?", "No en esta versión. Los módulos de enumeración devuelven datos de muestra marcados como demostración. Un escaneo real requiere autorización expresa por escrito."],
    ["¿Por qué una alerta afecta a varios controles op.acc?", "Una misma debilidad suele romper varias salvaguardas. Por ejemplo, ESC8 afecta al mecanismo de autenticación (op.acc.5), al acceso remoto (op.acc.7) y a la gestión de derechos (op.acc.4). El control marcado como principal es el que se incumple directamente."],
    ["¿Cómo se decide el nivel de riesgo?", "Lo define la regla de mapeo de cada tipo de hallazgo según el impacto: las vías directas a administrador de dominio son Críticas y las credenciales crackeables, Altas."],
    ["¿Puedo filtrar los hallazgos?", "Sí. Pulsa una tarjeta de severidad para filtrar por riesgo, o un control en la tabla de controles ENS para ver solo sus alertas. Los filtros activos aparecen sobre la lista."],
    ["¿En qué idioma está el informe?", "El informe y los textos de las alertas los genera el backend en español, el idioma del ENS. El selector ES/EN cambia la interfaz."],
    ["¿Dónde se guardan mis preferencias?", "En el localStorage de este navegador: tema, acento, idioma y densidad. No se envían al backend."],
  ],
  about: [
    "ENS AD Auditor 0.1.0. Auditor de Active Directory mapeado al Esquema Nacional de Seguridad.",
    "Autor: Yoandy Ramírez Delgado.",
    "Marco de referencia: Real Decreto 311/2022 (ENS), marco operacional · control de acceso [op.acc]. Técnicas de AD CS según la clasificación ESC1–ESC8 de SpecterOps.",
    "Backend en FastAPI y panel en React + TypeScript + Vite.",
  ],
};

const en: HelpContent = {
  flowIn: [
    { icon: "lock", title: "Kerberos", sub: "Kerberoasting · AS-REP roasting" },
    { icon: "layers", title: "Delegation & privileges", sub: "Unconstrained · RBCD · Domain Admins" },
    { icon: "fileCheck", title: "AD CS", sub: "Templates and CA · ESC1–ESC8" },
    { icon: "server", title: "SMB", sub: "Message signing" },
  ],
  flowCore: {
    icon: "shieldCheck",
    title: "ENS [op.acc] mapping engine",
    sub: "Each finding type maps to op.acc controls (primary and related), a risk level, the gap, and the fix.",
  },
  flowOut: [
    { icon: "alert", title: "GRC alerts", sub: "Risk · non-compliance · remediation" },
    { icon: "dashboard", title: "Dashboard", sub: "KPIs, filters and affected controls" },
    { icon: "download", title: "Report", sub: "Markdown · JSON" },
  ],
  stepsTitle: "Step by step",
  steps: [
    {
      title: "Active Directory enumeration",
      text: "The Kerberos, delegation, AD CS and SMB modules collect technical findings. In this version they return clearly flagged sample data.",
      go: "panel",
    },
    {
      title: "ENS [op.acc] mapping engine",
      text: "Each finding is linked to the affected ENS access-control measures and assigned a risk level: Critical, High, Medium or Low.",
      go: "controles",
    },
    {
      title: "GRC alerts",
      text: "The alert says which control fails, why, and how to fix it, with the technical evidence.",
      go: "hallazgos",
    },
    {
      title: "Report",
      text: "Download the Markdown with the summary and each alert, for the audit report.",
      go: "informe",
    },
  ],
  notes: [
    {
      title: "Primary control",
      text: "Each alert flags one primary op.acc control (the one directly breached) plus related ones. The controls table counts both.",
    },
    {
      title: "Risk level",
      text: "Set by the mapping rule according to impact: a direct path to domain admin is Critical; a crackable credential, High.",
    },
    {
      title: "Sample data",
      text: "While the demo banner is visible, no data comes from a real domain. This version performs no network scanning.",
    },
  ],
  glossary: [
    ["Kerberoasting", "Requesting service tickets (TGS) for accounts with an SPN and cracking their password offline. Especially severe when the account allows RC4."],
    ["AS-REP roasting", "Accounts with “Do not require Kerberos preauthentication”: anyone can request an AS-REP encrypted with the user's key and crack it offline."],
    ["Unconstrained delegation", "The host or account receives and caches the TGT of whoever authenticates to it and can impersonate them to any service. If compromised, it exposes connecting administrators."],
    ["Constrained delegation", "Delegation limited to a list of services (msDS-AllowedToDelegateTo). Misconfigured, with protocol transition, it still allows user impersonation."],
    ["RBCD", "Resource-Based Constrained Delegation: the resource decides who may delegate to it (msDS-AllowedToActOnBehalfOfOtherIdentity). If an unprivileged principal can write that attribute, it can impersonate any user to the resource."],
    ["AD CS", "Active Directory Certificate Services, the Windows PKI. Its templates and CA configuration are the source of the ESC1–ESC8 techniques."],
    ["ESC1", "Template letting the requester supply the subject (SAN), with a client-authentication EKU and no approval: an unprivileged user obtains a certificate as an administrator."],
    ["ESC2", "Template with the “Any Purpose” EKU or no EKU, enrollable by unprivileged users: the certificate is valid for any use, including authentication."],
    ["ESC3", "Template with the enrollment-agent EKU (Certificate Request Agent): allows requesting certificates on behalf of other users."],
    ["ESC4", "Write permissions on a certificate template: the attacker modifies it to make it vulnerable to ESC1."],
    ["ESC5", "Weak permissions on PKI objects in AD (CA computer, configuration containers) that allow compromising the certificate infrastructure."],
    ["ESC6", "The CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled: any request can include an arbitrary SAN and impersonate another user."],
    ["ESC7", "Dangerous permissions on the CA itself (ManageCA, ManageCertificates): allow enabling insecure options or approving pending requests."],
    ["ESC8", "NTLM relay to AD CS web enrollment (HTTP without EPA): a machine's authentication, e.g. a DC, is relayed to obtain a certificate in its name."],
    ["SMB signing", "SMB message signing. When not required, a network attacker can relay NTLM authentications and act as the victim."],
    ["op.acc.1 · Identification", "Every user must have a unique identity assigned to an accountable person or service."],
    ["op.acc.2 · Access requirements", "Access rights are granted on a need-to-know and least-privilege basis."],
    ["op.acc.3 · Segregation of duties", "No single person should hold incompatible critical functions, e.g. administering and auditing."],
    ["op.acc.4 · Access-rights management", "Granting, changing and periodically reviewing rights, including delegations and object permissions."],
    ["op.acc.5 · Authentication mechanism", "How sign-in is done: protocols, encryption, certificates, and how credentials are protected."],
    ["op.acc.6 · Local logon", "Conditions for local sign-in on systems: credentials, lockouts and protection of secrets."],
    ["op.acc.7 · Remote login", "Protection of access over the network: encrypted, signed and authenticated channels."],
  ],
  faq: [
    ["Does the tool scan my domain?", "Not in this version. The enumeration modules return sample data flagged as demo. A real scan requires express written authorisation."],
    ["Why does one alert affect several op.acc controls?", "A single weakness often breaks several safeguards. ESC8, for example, affects the authentication mechanism (op.acc.5), remote login (op.acc.7) and rights management (op.acc.4). The control flagged as primary is the one directly breached."],
    ["How is the risk level decided?", "The mapping rule for each finding type sets it by impact: direct paths to domain admin are Critical, crackable credentials are High."],
    ["Can I filter findings?", "Yes. Click a severity card to filter by risk, or a control in the ENS controls table to see only its alerts. Active filters appear above the list."],
    ["What language is the report in?", "The report and alert texts are generated by the backend in Spanish, the language of the ENS. The ES/EN switch changes the interface."],
    ["Where are my preferences stored?", "In this browser's localStorage: theme, accent, language and density. They are not sent to the backend."],
  ],
  about: [
    "ENS AD Auditor 0.1.0. Active Directory auditor mapped to the ENS (Spain's National Security Framework).",
    "Author: Yoandy Ramírez Delgado.",
    "Reference framework: Royal Decree 311/2022 (ENS), operational framework · access control [op.acc]. AD CS techniques follow SpecterOps' ESC1–ESC8 taxonomy.",
    "FastAPI backend and React + TypeScript + Vite dashboard.",
  ],
};

export const HELP_CONTENT: Record<Lang, HelpContent> = { es, en };
