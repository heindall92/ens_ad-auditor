# Cambios

## 0.4.0 · octubre de 2026

**Ecosistema**
- Nuevo sobre `yrd-ecosistema` (versión 1, tipo `hallazgos`) para CTEM-Nexus: lleva las alertas tal como las emite el informe JSON, más un resumen con el dominio, el recuento por riesgo y las rutas hacia Domain Admins. CTEM-Nexus las convierte en hallazgos de identidad con técnicas ATT&CK y rutas de ataque hacia el controlador de dominio.
- Panel: botón «Exportar para CTEM-Nexus» en Informe. API: `GET /api/export/ecosistema` (vacío sin credenciales) y `POST /api/export/ecosistema` (auditoría en vivo). Como la exportación a Studio, sin alertas el sobre va vacío y los hallazgos de muestra no salen nunca.
- Ayuda → Acerca de: las otras seis herramientas GRC del autor (se suman CTEM-Nexus, ARGOS y Norvik).

**Accesibilidad**
- axe-core encontraba 41 nodos con contraste insuficiente en claro y 3 en oscuro. Se corrige en los tokens: `--muted` pasa a `#5a6a72` (5,1:1 sobre el fondo), `--ok` a `#17703e`, las etiquetas y segmentos activos mezclan el acento con la tinta y el enlace «Cómo instalarlo» usa la tinta subrayada. Ahora hay 0 infracciones en todas las vistas, en claro y en oscuro.

**Pruebas**
- 4 nuevas de `pytest` para el sobre (45 en total): cabecera válida, vacío honesto, muestras excluidas, alerta intacta y endpoint.
- La versión mostrada en Acerca de y en Soporte vuelve a coincidir con la del paquete (0.4.0).

## 0.3.1 · octubre de 2026

**GitHub Pages**
- `index.html` en la raíz redirige a `dist/` (mismo patrón que KAIROS). `.nojekyll` evita que Jekyll toque el build.
- `npm run build:pages` genera el panel estático con base `/ens_ad-auditor/dist/`.
- Modo navegador: shell vacío, 0 alertas, cobertura «No comprobado» (no es un dominio limpio). El botón de enumerar queda desactivado. Hace falta el motor local.
- «Abrir resultado JSON» lee un informe exportado por el motor, en el navegador (FileReader, sin red). Rechaza muestras y ficheros con secretos.
- CSP estricta (`connect-src 'none'`) y `referrer: no-referrer`. Las credenciales no se almacenan.
- CI: `pytest`, `npm run build` y fallo si `dist/` no coincide con el fuente.

No se amplia la enumeración. No hay datos de demostración en el repositorio.

## 0.3.0 · octubre de 2026

**Interfaz** (mismo criterio que ENS Compliance Studio, Rosetta y KAIROS)
- Cristal solo en el cromo: barra lateral, barra superior y hoja móvil. Los paneles de contenido van opacos, con línea de 1 px.
- Sin cejas de sección. Sin barra de color de 4 px en los hallazgos: el riesgo va en la etiqueta.
- Pulsar escala a `0.97`. El hover solo se aplica con puntero fino (`hover: hover`).
- Aviso con entrada y salida. Movimiento reducido: duraciones casi nulas, sin cortar propiedades.
- Controles táctiles de al menos 44 px. Arranque estático: logo, nombre y barra, sin vídeo ni brillos.

**Producto**
- CI: `pytest` del backend y `npm run build` del panel, con acciones fijadas por SHA.
- `SECURITY.md`: las credenciales no se almacenan.
- Este CHANGELOG.
- Ayuda y README enlazan ENS Compliance Studio, Rosetta y KAIROS.
- Exportación opcional a evidencia técnica de Studio, solo a partir de alertas reales. Sin alertas el JSON va vacío (`is_sample: false`). «No comprobado» sigue sin significar dominio limpio.

No se amplia la enumeración de Active Directory. No hay datos de demostración.

## 0.2.0

Panel conectado a la API, cobertura de la hoja de ruta, ACL, secretos, GPO y plan de tratamiento. Iconos Lucide. Capturas del README sin enumeración autorizada.

## 0.1.0

Primera publicación: mapeo `[op.acc]`, panel React y enumeración de solo lectura.
