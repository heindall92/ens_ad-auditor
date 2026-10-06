# Cambios

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
