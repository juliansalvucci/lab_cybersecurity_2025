🛡️ Ejercicio 1 — Reporte de Auditoría S3

Laboratorio de Ciberseguridad — Clase 7

🧾 Información General

Fecha: 23/11/2025

Estudiante/Grupo: a definir

Región: us-east-1 (LocalStack)

📦 Buckets Analizados

Total de buckets: 2

Buckets públicos: 1

🔍 Hallazgos
### Bucket 1 — mi-bucket-privado-lab

Estado: Privado

Riesgo asignado: Bajo

🔐 Permisos

ACL

Público: No

Permisos: Sin permisos públicos

Política

Tiene política: No

Es pública: No

🚫 Bloqueo de acceso público

enabled: true

block_public_acls: true

ignore_public_acls: true

block_public_policy: true

restrict_public_buckets: true

Bucket 2 — mi-bucket-publico-lab

Estado: Público

Riesgo asignado: Alto

🔐 Permisos

ACL

Público: Sí

Permisos otorgados:

AllUsers → READ
(cualquiera en Internet puede leer/consultar objetos)

Política

Tiene política: No

Es pública: No

🚫 Bloqueo de acceso público

Aunque aparece habilitado, el bucket conserva una ACL pública (comportamiento típico en LocalStack).

enabled: true

block_public_acls: true

ignore_public_acls: true

block_public_policy: true

restrict_public_buckets: true

🖼️ Capturas de Pantalla

(Agregar aquí capturas de consola, ejecución del script, JSON formateado, etc.)

📝 Análisis

Durante la auditoría se detectó que uno de los buckets (mi-bucket-publico-lab) está configurado como público debido a una ACL que permite acceso al grupo AllUsers. Esto representa un riesgo significativo porque:

Cualquier usuario en Internet puede listar o leer su contenido.

Puede llevar a exposición de datos sensibles.

Riesgo de recolección automatizada por bots, malware o scrapers.

Aunque la opción Block Public Access se encuentra habilitada, LocalStack no replica completamente las restricciones de AWS y permite mantener ACL públicas existentes.

El bucket privado no presenta problemas:

No tiene ACL pública

No posee políticas que lo expongan

Tiene el Bloqueo de Acceso Público correctamente configurado

🧠 Conclusiones

Se auditaron dos buckets:

Uno privado (seguro)

Uno público (riesgo alto)

Las ACL públicas son el principal vector de riesgo.

El análisis permitió identificar permisos, políticas y configuración de bloqueo.

Buenas prácticas reforzadas:

Evitar ACL públicas

Mantener habilitado Block Public Access

Aplicar políticas basadas en IAM

Realizar auditorías periódicas
