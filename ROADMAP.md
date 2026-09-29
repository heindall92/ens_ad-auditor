# Roadmap de auditoría

ENS AD Auditor es un ecosistema de auditoría real. Este documento separa lo que ya cubre el motor de lo que una auditoría de Active Directory empresarial todavía debe incorporar. Nada de esta lista se rellena con hallazgos inventados: si no hay conexión autorizada, no hay alertas.

Marco de referencia: ENS (Real Decreto 311/2022), controles de acceso `[op.acc]`, MAGERIT para impacto y frecuencia, y las prácticas actuales de auditoría de AD (LDAP de solo lectura, AD CS, firma SMB, ACL de dominio y GPO leída en SYSVOL). Tiering y Entra ID siguen fuera del motor.

## Ahora

Esto ya está en el motor o entra en el pull request en curso.

| Área | Qué comprueba | Estado |
|---|---|---|
| Kerberos | Cuentas con SPN y RC4 (Kerberoasting). Cuentas sin preautenticación (AS-REP). | En el motor |
| Delegación | No restringida, restringida y RBCD. | En el motor |
| AD CS | Plantillas y CA. Cualquier clave ESC que devuelva `certipy find`, sin pedir certificados. | En el motor |
| SMB | Firma de mensajes en el DC y en equipos del dominio. | En el motor |
| Conexión | Dominio, DC, usuario y contraseña o hash NT. Autorización por escrito obligatoria. El secreto no se guarda. | En el motor |
| ENS | Cada hallazgo real se mapea a `[op.acc]` con riesgo, incumplimiento y remediación. | En el motor |
| Matriz de riesgo | Impacto por frecuencia, al estilo MAGERIT, calculada solo con hallazgos devueltos. Vacía si no hay auditoría. | En curso |
| Criticidad | Nivel por hallazgo y resumen del dominio: controles tocados, riesgo máximo, vía directa a administrador de dominio. | En curso |
| Política de contraseñas | Longitud, complejidad, antigüedad y bloqueo. | En curso, solo lectura |
| krbtgt | Antigüedad de la contraseña de `krbtgt`. | En curso, solo lectura |
| Cuentas privilegiadas | SPN en admins, cuentas privilegiadas obsoletas, Protected Users. | En curso, solo lectura |
| LDAP | Firma LDAP y channel binding, si el DC lo expone. | En curso, solo lectura |
| Confianza y cuota | Confianzas del dominio y machine account quota. Presencia de LAPS. | En curso, solo lectura |
| ACL y rutas de control | GenericAll, WriteDacl o DCSync (Get-Changes y Get-Changes-All juntos) en la DACL del dominio. Se ignoran las identidades de administración y de controlador integradas. No se modifica la ACL. | En el motor |
| GPO | `RequireSecuritySignature` y `LDAPServerIntegrity` en los `GptTmpl.inf` leídos por SMB. Si SYSVOL no se lee, la fila queda no comprobado. | En el motor |
| Atributos con secreto | Presencia de `userPassword` o `unixUserPassword`. El valor no se lee ni se copia al informe. | En el motor |
| Monitorización | Claves de `[Event Audit]` puestas a 0 en un `GptTmpl.inf` leído. Sin esa sección, no comprobado. No se estima un número de eventos. | En el motor |
| Informe de tratamiento | Responsable, estado y plazo por hallazgo, guardados solo en el navegador, con anexo Markdown. No es un hallazgo de directorio y no guarda credenciales. | En el panel |

## Después

No está implementado. No se simula.

| Área | Por qué importa | Control ENS cercano |
|---|---|---|
| Tiering | Separar cuentas de nivel 0, 1 y 2. Un admin de dominio que inicia sesión en un puesto rompe el modelo. El panel lo muestra como no comprobado: no hay evidencia del equipo de inicio de sesión. | `op.acc.2`, `op.acc.3`, `op.acc.6` |
| GPO restante | Contraseñas guardadas en la directiva y derechos de inicio de sesión. El motor solo lee firma SMB, integridad LDAP y `[Event Audit]` cuando el fichero existe. | `op.acc.6` |
| AD CS fuera de ESC | Permisos de CA que `certipy find` no etiqueta como clave ESC. No se piden certificados. | `op.acc.5` |
| Copias NTDS | Exposición de NTDS y copias de seguridad del dominio. No se vuelca la base ni se leen secretos. | `op.acc.6` |
| Híbrido Entra ID | Sincronización, cuentas cloud-only con rol alto y anclaje de autenticación. Solo con un conector propio, no inventando el tenant. El panel lo muestra como no comprobado. | `op.acc.5`, `op.acc.7` |

## Cómo se calcula el riesgo

Cuando hay hallazgos reales:

1. El impacto sale del efecto del hallazgo (una vía a administrador de dominio pesa más que una política débil aislada).
2. La frecuencia sale de lo fácil que es explotarlo con la configuración vista (cifrado débil, ausencia de aprobación, firma no exigida).
3. La celda de la matriz da el nivel: Crítico, Alto, Medio o Bajo, el mismo que ya usa el panel.
4. La criticidad del dominio es el peor nivel presente y el recuento de controles `[op.acc]` afectados.

Sin auditoría, la matriz no muestra números.

## Criterio para dar por hecha una fila

Una comprobación pasa de «después» a «ahora» solo si el motor la obtiene por LDAP, certipy-ad o impacket en modo lectura, los tests cubren el caso vacío, y el informe distingue «no comprobado» de «comprobado y limpio».
