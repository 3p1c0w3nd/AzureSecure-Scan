#!/usr/bin/env python3
"""
AzureSecure Scan — Escáner integral de seguridad para cuentas Azure.

Analiza la suscripción en busca de:
  • Malas configuraciones en Storage, Network, Key Vault, SQL, App Services, VMs
  • Claves y secrets expuestos en Azure DevOps (pipelines + repositorios)
  • Pipelines mal configurados (fork triggers, service connections permisivas)
  • Container Registry inseguro, IAM/RBAC excesivo, Defender deshabilitado
  • Recursos sin diagnósticos/logging habilitados

Uso:
  python scanner.py --all                  # Escaneo completo
  python scanner.py --storage --network    # Solo módulos específicos
  python scanner.py --devops               # Solo Azure DevOps
  python scanner.py --help                 # Ver todas las opciones
"""

import argparse
import os
import re
import sys
import base64
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timezone

import pandas as pd
from dotenv import load_dotenv

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except ImportError:
    # Fallback si colorama no está instalado
    class _Noop:
        def __getattr__(self, _):
            return ""
    Fore = Style = _Noop()

from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient

# ─────────────────────────────── Constantes ─────────────────────────────────

SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?[^\s"\']{4,}', "Posible password en texto plano"),
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{8,}', "API Key expuesta"),
    (r'(?i)(secret|client_secret)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{8,}', "Secret expuesto"),
    (r'(?i)(access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*["\']?[A-Za-z0-9_\.\-]{10,}', "Token de acceso expuesto"),
    (r'(?i)(connection[_-]?string)\s*[:=]\s*["\']?[^\s"\']{20,}', "Connection string expuesta"),
    (r'AccountKey=[A-Za-z0-9+/=]{20,}', "Azure Storage Account Key"),
    (r'(?i)DefaultEndpointsProtocol=https?;Account', "Azure Storage connection string"),
    (r'(?i)(SAS|sv=)\s*=?\s*[A-Za-z0-9%&=\-]{20,}', "SAS token posible"),
    (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', "Clave privada expuesta"),
    (r'(?i)ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token"),
    (r'(?i)AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
]

SENSITIVE_FILE_PATTERNS = [
    ".env", ".env.local", ".env.production", ".env.staging",
    "credentials.json", "service-account.json", "key.json",
    ".pem", ".key", ".pfx", ".p12", ".cer",
    "id_rsa", "id_ed25519", "id_ecdsa",
    "web.config", "appsettings.json", "appsettings.Development.json",
    "docker-compose.yml", ".npmrc", ".pypirc",
]

SEVERITY_ORDER = {"Crítica": 0, "Alta": 1, "Media": 2, "Baja": 3, "Info": 4}


# ────────────────────── GUI para credenciales DevOps ─────────────────────────

def _prompt_devops_credentials() -> tuple[str, str]:
    """Abre una ventana GUI para solicitar PAT y Organización de Azure DevOps.
    Retorna (pat, org) o ('', '') si el usuario cancela/skip."""

    result = {"pat": "", "org": "", "save": False}

    root = tk.Tk()
    root.title("🔐 AzureSecure Scan — Credenciales DevOps")
    root.geometry("520x380")
    root.resizable(False, False)
    root.configure(bg="#1e1e2e")

    # Center on screen
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - 260
    y = (root.winfo_screenheight() // 2) - 190
    root.geometry(f"+{x}+{y}")

    # Styles
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Dark.TFrame", background="#1e1e2e")
    style.configure("Dark.TLabel", background="#1e1e2e", foreground="#cdd6f4",
                    font=("Segoe UI", 10))
    style.configure("Title.TLabel", background="#1e1e2e", foreground="#89b4fa",
                    font=("Segoe UI", 14, "bold"))
    style.configure("Sub.TLabel", background="#1e1e2e", foreground="#a6adc8",
                    font=("Segoe UI", 9))
    style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))
    style.configure("Dark.TCheckbutton", background="#1e1e2e", foreground="#cdd6f4",
                    font=("Segoe UI", 9))

    frame = ttk.Frame(root, style="Dark.TFrame", padding=25)
    frame.pack(fill="both", expand=True)

    # Title
    ttk.Label(frame, text="🛡️ Azure DevOps Credentials", style="Title.TLabel").pack(pady=(0, 5))
    ttk.Label(frame, text="Ingresa tus credenciales para escanear pipelines y repos",
              style="Sub.TLabel").pack(pady=(0, 15))

    # Organization
    ttk.Label(frame, text="Organización Azure DevOps:", style="Dark.TLabel").pack(anchor="w")
    org_entry = tk.Entry(frame, font=("Segoe UI", 11), bg="#313244", fg="#cdd6f4",
                         insertbackground="#cdd6f4", relief="flat", bd=5)
    org_entry.pack(fill="x", pady=(2, 10), ipady=4)

    # PAT
    ttk.Label(frame, text="Personal Access Token (PAT):", style="Dark.TLabel").pack(anchor="w")
    pat_entry = tk.Entry(frame, font=("Segoe UI", 11), bg="#313244", fg="#cdd6f4",
                         insertbackground="#cdd6f4", relief="flat", bd=5, show="•")
    pat_entry.pack(fill="x", pady=(2, 5), ipady=4)
    ttk.Label(frame, text="Scopes necesarios: Code(Read), Build(Read), Service Connections(Read)",
              style="Sub.TLabel").pack(anchor="w", pady=(0, 10))

    # Save checkbox
    save_var = tk.BooleanVar(value=True)
    save_check = ttk.Checkbutton(frame, text="Guardar en archivo .env (para futuros escaneos)",
                                  variable=save_var, style="Dark.TCheckbutton")
    save_check.pack(anchor="w", pady=(0, 15))

    # Buttons
    btn_frame = ttk.Frame(frame, style="Dark.TFrame")
    btn_frame.pack(fill="x")

    def on_submit():
        result["pat"] = pat_entry.get().strip()
        result["org"] = org_entry.get().strip()
        result["save"] = save_var.get()
        if not result["pat"] or not result["org"]:
            messagebox.showwarning("Campos vacíos", "Ingresa tanto la Organización como el PAT.")
            return
        root.destroy()

    def on_skip():
        root.destroy()

    skip_btn = tk.Button(btn_frame, text="Omitir DevOps", font=("Segoe UI", 10),
                         bg="#45475a", fg="#cdd6f4", activebackground="#585b70",
                         relief="flat", padx=15, pady=6, command=on_skip)
    skip_btn.pack(side="left")

    submit_btn = tk.Button(btn_frame, text="✓  Conectar", font=("Segoe UI", 10, "bold"),
                           bg="#89b4fa", fg="#1e1e2e", activebackground="#74c7ec",
                           relief="flat", padx=20, pady=6, command=on_submit)
    submit_btn.pack(side="right")

    # Enter key submits
    root.bind("<Return>", lambda e: on_submit())
    org_entry.focus_set()

    root.mainloop()

    # Save to .env if requested
    if result["save"] and result["pat"] and result["org"]:
        env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
        existing = ""
        if os.path.exists(env_path):
            with open(env_path, "r", encoding="utf-8") as f:
                existing = f.read()

        lines = existing.splitlines()
        new_lines = []
        found_pat = found_org = False
        for line in lines:
            if line.startswith("AZURE_DEVOPS_PAT="):
                new_lines.append(f'AZURE_DEVOPS_PAT={result["pat"]}')
                found_pat = True
            elif line.startswith("AZURE_DEVOPS_ORG="):
                new_lines.append(f'AZURE_DEVOPS_ORG={result["org"]}')
                found_org = True
            else:
                new_lines.append(line)

        if not found_pat:
            new_lines.append(f'AZURE_DEVOPS_PAT={result["pat"]}')
        if not found_org:
            new_lines.append(f'AZURE_DEVOPS_ORG={result["org"]}')

        with open(env_path, "w", encoding="utf-8") as f:
            f.write("\n".join(new_lines) + "\n")

        print(f"  {Fore.GREEN}✅ Credenciales guardadas en .env{Style.RESET_ALL}")

    return result["pat"], result["org"]


# ──────────────────────────── Clase principal ────────────────────────────────

class AzureSecurityScanner:
    """Motor de escaneo de seguridad Azure."""

    def __init__(self, subscription_id: str | None = None, no_gui: bool = False):
        self.credential = DefaultAzureCredential()
        self.hallazgos: list[dict] = []
        self.no_gui = no_gui

        sub_client = SubscriptionClient(self.credential)
        if subscription_id:
            self.sub_id = subscription_id
            self.sub_name = subscription_id
        else:
            sub = next(sub_client.subscriptions.list())
            self.sub_id = sub.subscription_id
            self.sub_name = sub.display_name

        # DevOps config (opcional) — load from .env first
        load_dotenv()
        self.devops_pat = os.getenv("AZURE_DEVOPS_PAT", "")
        self.devops_org = os.getenv("AZURE_DEVOPS_ORG", "")

        # If not found and GUI is allowed, prompt the user
        if (not self.devops_pat or not self.devops_org) and not self.no_gui:
            try:
                pat, org = _prompt_devops_credentials()
                if pat and org:
                    self.devops_pat = pat
                    self.devops_org = org
            except Exception:
                pass  # tkinter not available (headless), continue without

    # ─────────────────────── Utilidades internas ────────────────────────────

    def _add(self, recurso: str, tipo: str, categoria: str,
             severidad: str, detalle: str, remediacion: str = ""):
        self.hallazgos.append({
            "Recurso": recurso,
            "Tipo": tipo,
            "Categoría": categoria,
            "Severidad": severidad,
            "Detalle": detalle,
            "Remediación": remediacion,
        })

    def _print_module(self, name: str):
        print(f"\n{Fore.CYAN}{'━'*60}")
        print(f"  🔍  {name}")
        print(f"{'━'*60}{Style.RESET_ALL}")

    def _devops_headers(self):
        token_b64 = base64.b64encode(f":{self.devops_pat}".encode()).decode()
        return {"Authorization": f"Basic {token_b64}",
                "Content-Type": "application/json"}

    def _devops_get(self, url: str):
        import requests
        resp = requests.get(url, headers=self._devops_headers(), timeout=30)
        resp.raise_for_status()
        return resp.json()

    # ═══════════════════════════════════════════════════════════════════════
    #  1. STORAGE ACCOUNTS
    # ═══════════════════════════════════════════════════════════════════════

    def scan_storage(self):
        self._print_module("Storage Accounts")
        from azure.mgmt.storage import StorageManagementClient
        client = StorageManagementClient(self.credential, self.sub_id)
        count = 0

        for sa in client.storage_accounts.list():
            count += 1
            name = sa.name
            rg = sa.id.split("/")[4]  # resource group

            # 1a. Acceso público a blobs
            if sa.allow_blob_public_access:
                self._add(name, "Storage Account", "Storage",
                          "Alta", "Acceso público a blobs habilitado",
                          "Deshabilitar 'Allow Blob public access' en la cuenta")

            # 1b. HTTPS only
            if not sa.enable_https_traffic_only:
                self._add(name, "Storage Account", "Storage",
                          "Alta", "Tráfico HTTP permitido (sin HTTPS-only)",
                          "Habilitar 'Secure transfer required'")

            # 1c. Encryption (infrastructure encryption)
            if sa.encryption and not getattr(sa.encryption, "require_infrastructure_encryption", False):
                self._add(name, "Storage Account", "Storage",
                          "Media", "Infrastructure encryption no habilitada",
                          "Habilitar doble cifrado (infrastructure encryption)")

            # 1d. Shared Key access
            if getattr(sa, "allow_shared_key_access", True) is not False:
                self._add(name, "Storage Account", "Storage",
                          "Media", "Acceso con Shared Key habilitado",
                          "Deshabilitar Shared Key access y usar Azure AD/RBAC")

            # 1e. Network rules — allow all
            if sa.network_rule_set:
                if sa.network_rule_set.default_action == "Allow":
                    self._add(name, "Storage Account", "Storage",
                              "Alta", "Firewall: acceso permitido desde todas las redes",
                              "Configurar firewall con 'Selected networks' o Private Endpoints")

            # 1f. Minimum TLS version
            tls = getattr(sa, "minimum_tls_version", None)
            if tls and tls != "TLS1_2":
                self._add(name, "Storage Account", "Storage",
                          "Media", f"TLS mínimo: {tls} (debería ser TLS1_2)",
                          "Configurar minimum TLS version a TLS 1.2")

            # 1g. Soft delete for blobs
            try:
                blob_props = client.blob_services.get_service_properties(rg, name)
                if blob_props.delete_retention_policy and not blob_props.delete_retention_policy.enabled:
                    self._add(name, "Storage Account", "Storage",
                              "Media", "Soft delete para blobs no habilitado",
                              "Habilitar soft delete con retención mínima de 7 días")
                if blob_props.container_delete_retention_policy and not blob_props.container_delete_retention_policy.enabled:
                    self._add(name, "Storage Account", "Storage",
                              "Baja", "Soft delete para contenedores no habilitado",
                              "Habilitar container soft delete")
            except Exception:
                pass

        print(f"  Cuentas analizadas: {count}")

    # ═══════════════════════════════════════════════════════════════════════
    #  2. NETWORK SECURITY GROUPS
    # ═══════════════════════════════════════════════════════════════════════

    def scan_network(self):
        self._print_module("Network Security Groups")
        from azure.mgmt.network import NetworkManagementClient
        client = NetworkManagementClient(self.credential, self.sub_id)
        count = 0

        dangerous_ports = {"22": "SSH", "3389": "RDP", "445": "SMB",
                           "1433": "SQL Server", "3306": "MySQL",
                           "5432": "PostgreSQL", "27017": "MongoDB",
                           "6379": "Redis", "*": "TODOS"}

        for nsg in client.network_security_groups.list_all():
            count += 1
            all_rules = list(nsg.security_rules or [])

            for rule in all_rules:
                if rule.access != "Allow" or rule.direction != "Inbound":
                    continue

                src = rule.source_address_prefix or ""
                src_list = rule.source_address_prefixes or []

                is_any_source = (src in ("*", "0.0.0.0/0", "Internet", "Any")
                                 or any(s in ("*", "0.0.0.0/0", "Internet") for s in src_list))
                if not is_any_source:
                    continue

                # Check port ranges
                ports = []
                if rule.destination_port_range:
                    ports.append(rule.destination_port_range)
                if rule.destination_port_ranges:
                    ports.extend(rule.destination_port_ranges)

                for port in ports:
                    svc = dangerous_ports.get(port, None)
                    if svc or port == "*":
                        sev = "Crítica" if port in ("*", "22", "3389") else "Alta"
                        self._add(
                            nsg.name, "Network Security Group", "Red",
                            sev,
                            f"Puerto {port} ({svc or 'Todos'}) abierto a Internet (regla: {rule.name})",
                            f"Restringir source IP en la regla '{rule.name}' a IPs/rangos conocidos"
                        )

            # Check for missing deny-all inbound
            has_custom_deny = any(
                r.access == "Deny" and r.direction == "Inbound"
                and r.source_address_prefix == "*"
                and r.destination_port_range == "*"
                for r in all_rules
            )
            if not has_custom_deny and all_rules:
                self._add(nsg.name, "Network Security Group", "Red",
                          "Baja", "Sin regla explícita deny-all inbound",
                          "Agregar regla deny-all con prioridad baja como safety net")

        print(f"  NSGs analizados: {count}")

    # ═══════════════════════════════════════════════════════════════════════
    #  3. KEY VAULT
    # ═══════════════════════════════════════════════════════════════════════

    def scan_keyvault(self):
        self._print_module("Key Vaults")
        from azure.mgmt.keyvault import KeyVaultManagementClient
        client = KeyVaultManagementClient(self.credential, self.sub_id)
        count = 0

        for vault in client.vaults.list_by_subscription():
            count += 1
            name = vault.name
            props = vault.properties

            # 3a. Soft delete
            if not getattr(props, "enable_soft_delete", True):
                self._add(name, "Key Vault", "Key Vault",
                          "Alta", "Soft delete deshabilitado",
                          "Habilitar soft delete (es default, verificar si fue deshabilitado)")

            # 3b. Purge protection
            if not getattr(props, "enable_purge_protection", False):
                self._add(name, "Key Vault", "Key Vault",
                          "Alta", "Purge protection deshabilitado",
                          "Habilitar purge protection para evitar eliminación permanente accidental")

            # 3c. Public network access
            network_acls = getattr(props, "network_acls", None)
            if network_acls:
                if getattr(network_acls, "default_action", "Allow") == "Allow":
                    self._add(name, "Key Vault", "Key Vault",
                              "Alta", "Acceso de red público permitido (sin firewall)",
                              "Configurar firewall o Private Endpoint")
            else:
                self._add(name, "Key Vault", "Key Vault",
                          "Media", "Sin configuración de red (acceso público por defecto)",
                          "Configurar network ACLs con Private Endpoint")

            # 3d. RBAC vs Access Policies
            if not getattr(props, "enable_rbac_authorization", False):
                self._add(name, "Key Vault", "Key Vault",
                          "Media", "Usa Access Policies en lugar de RBAC",
                          "Migrar a RBAC authorization para control granular")

        # 3e. Key expiration check
        try:
            from azure.keyvault.keys import KeyClient
            for vault in client.vaults.list_by_subscription():
                vault_url = f"https://{vault.name}.vault.azure.net"
                try:
                    key_client = KeyClient(vault_url=vault_url, credential=self.credential)
                    for key_props in key_client.list_properties_of_keys():
                        if key_props.expires_on is None:
                            self._add(vault.name, "Key Vault Key", "Key Vault",
                                      "Media", f"Clave '{key_props.name}' sin fecha de expiración",
                                      "Configurar fecha de expiración en todas las claves")
                        elif key_props.expires_on.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
                            self._add(vault.name, "Key Vault Key", "Key Vault",
                                      "Alta", f"Clave '{key_props.name}' expirada ({key_props.expires_on})",
                                      "Rotar la clave expirada inmediatamente")
                except Exception:
                    pass
        except ImportError:
            print(f"  {Fore.YELLOW}⚠ azure-keyvault-keys no instalado, omitiendo revisiĂ³n de claves")

        print(f"  Vaults analizados: {count}")

    # ═══════════════════════════════════════════════════════════════════════
    #  4. SQL DATABASES
    # ═══════════════════════════════════════════════════════════════════════

    def scan_sql(self):
        self._print_module("SQL Databases")
        from azure.mgmt.sql import SqlManagementClient
        client = SqlManagementClient(self.credential, self.sub_id)
        count = 0

        for server in client.servers.list():
            count += 1
            name = server.name
            rg = server.id.split("/")[4]

            # 4a. Azure AD admin
            try:
                admins = list(client.server_azure_ad_administrators.list_by_server(rg, name))
                if not admins:
                    self._add(name, "SQL Server", "SQL",
                              "Alta", "Sin Azure AD admin configurado",
                              "Configurar un Azure AD administrator para el servidor SQL")
            except Exception:
                pass

            # 4b. Public network access
            if getattr(server, "public_network_access", "Enabled") == "Enabled":
                self._add(name, "SQL Server", "SQL",
                          "Alta", "Acceso público habilitado",
                          "Deshabilitar public network access y usar Private Endpoints")

            # 4c. Minimum TLS
            tls = getattr(server, "minimal_tls_version", None)
            if tls and tls != "1.2":
                self._add(name, "SQL Server", "SQL",
                          "Media", f"TLS mĂ­nimo: {tls} (deberĂ­a ser 1.2)",
                          "Configurar minimal TLS version a 1.2")

            # 4d. Firewall rules — allow all Azure
            try:
                for rule in client.firewall_rules.list_by_server(rg, name):
                    if rule.start_ip_address == "0.0.0.0" and rule.end_ip_address == "0.0.0.0":
                        self._add(name, "SQL Server", "SQL",
                                  "Media", "Regla firewall: 'Allow Azure services' habilitada",
                                  "Revisar si es necesario o restringir a IPs especĂ­ficas")
                    elif rule.start_ip_address == "0.0.0.0" and rule.end_ip_address == "255.255.255.255":
                        self._add(name, "SQL Server", "SQL",
                                  "CrĂ­tica", "Regla firewall: abierto a TODAS las IPs (0.0.0.0 - 255.255.255.255)",
                                  "Eliminar esta regla inmediatamente y restringir acceso")
            except Exception:
                pass

            # 4e. Auditing
            try:
                audit = client.server_blob_auditing_policies.get(rg, name)
                if getattr(audit, "state", "Disabled") != "Enabled":
                    self._add(name, "SQL Server", "SQL",
                              "Media", "Auditing no habilitado",
                              "Habilitar SQL auditing con retenciĂ³n mĂ­nima de 90 dĂ­as")
            except Exception:
                pass

            # 4f. TDE en databases
            try:
                for db in client.databases.list_by_server(rg, name):
                    if db.name == "master":
                        continue
                    try:
                        tde = client.transparent_data_encryptions.get(rg, name, db.name, "current")
                        if getattr(tde, "status", "Enabled") != "Enabled":
                            self._add(f"{name}/{db.name}", "SQL Database", "SQL",
                                      "Alta", "Transparent Data Encryption deshabilitado",
                                      "Habilitar TDE para cifrado de datos en reposo")
                    except Exception:
                        pass
            except Exception:
                pass

        print(f"  Servidores SQL analizados: {count}")

    # ═══════════════════════════════════════════════════════════════════════
    #  5. APP SERVICES / WEB APPS
    # ═══════════════════════════════════════════════════════════════════════

    def scan_web_apps(self):
        self._print_module("App Services / Web Apps")
        from azure.mgmt.web import WebSiteManagementClient
        client = WebSiteManagementClient(self.credential, self.sub_id)
        count = 0

        for app in client.web_apps.list():
            count += 1
            name = app.name
            rg = app.resource_group

            # 5a. HTTPS only
            if not getattr(app, "https_only", False):
                self._add(name, "App Service", "Web Apps",
                          "Alta", "HTTPS-only no habilitado (permite HTTP)",
                          "Habilitar 'HTTPS Only' en la configuraciĂ³n del App Service")

            # 5b. Managed Identity
            identity = getattr(app, "identity", None)
            if not identity or getattr(identity, "type", "None") == "None":
                self._add(name, "App Service", "Web Apps",
                          "Media", "Sin Managed Identity asignada",
                          "Asignar System o User Assigned Managed Identity")

            # 5c. Site config details
            try:
                config = client.web_apps.get_configuration(rg, name)

                # TLS version
                min_tls = getattr(config, "min_tls_version", None)
                if min_tls and min_tls != "1.2":
                    self._add(name, "App Service", "Web Apps",
                              "Media", f"TLS mĂ­nimo: {min_tls} (deberĂ­a ser 1.2)",
                              "Configurar minimum TLS version a 1.2")

                # FTP
                ftp_state = getattr(config, "ftps_state", None)
                if ftp_state and ftp_state not in ("Disabled", "FtpsOnly"):
                    self._add(name, "App Service", "Web Apps",
                              "Alta", f"FTP habilitado en modo: {ftp_state}",
                              "Deshabilitar FTP o configurar FTPS-only")

                # Remote debugging
                if getattr(config, "remote_debugging_enabled", False):
                    self._add(name, "App Service", "Web Apps",
                              "CrĂ­tica", "Remote debugging habilitado",
                              "Deshabilitar remote debugging inmediatamente")

                # HTTP 2.0
                if not getattr(config, "http20_enabled", False):
                    self._add(name, "App Service", "Web Apps",
                              "Baja", "HTTP/2 no habilitado",
                              "Habilitar HTTP/2 para mejor rendimiento")

            except Exception:
                pass

        print(f"  App Services analizados: {count}")

    # ═══════════════════════════════════════════════════════════════════════
    #  6. VIRTUAL MACHINES
    # ═══════════════════════════════════════════════════════════════════════

    def scan_vms(self):
        self._print_module("Virtual Machines")
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.network import NetworkManagementClient
        compute = ComputeManagementClient(self.credential, self.sub_id)
        network = NetworkManagementClient(self.credential, self.sub_id)
        count = 0

        # Pre-load public IPs
        public_ips = {}
        for pip in network.public_ip_addresses.list_all():
            if pip.ip_configuration:
                public_ips[pip.ip_configuration.id.lower()] = pip.ip_address or pip.name

        for vm in compute.virtual_machines.list_all():
            count += 1
            name = vm.name
            rg = vm.id.split("/")[4]

            # 6a. Managed Identity
            identity = getattr(vm, "identity", None)
            if not identity or getattr(identity, "type", "None") == "None":
                self._add(name, "Virtual Machine", "VMs",
                          "Media", "Sin Managed Identity asignada",
                          "Asignar Managed Identity para autenticación sin secrets")

            # 6b. OS profile security
            os_profile = getattr(vm, "os_profile", None)
            if os_profile:
                linux_cfg = getattr(os_profile, "linux_configuration", None)
                if linux_cfg:
                    if getattr(linux_cfg, "disable_password_authentication", False) is False:
                        self._add(name, "Virtual Machine", "VMs",
                                  "Alta", "Autenticación por password SSH habilitada",
                                  "Deshabilitar password auth y usar solo SSH keys")

            # 6c. Disk encryption
            storage_profile = getattr(vm, "storage_profile", None)
            if storage_profile:
                os_disk = getattr(storage_profile, "os_disk", None)
                if os_disk:
                    encryption = getattr(os_disk, "managed_disk", None)
                    if encryption:
                        disk_enc_set = getattr(encryption, "disk_encryption_set", None)
                        enc_settings = getattr(os_disk, "encryption_settings", None)
                        if not disk_enc_set and not enc_settings:
                            self._add(name, "Virtual Machine", "VMs",
                                      "Media", "Disco OS sin cifrado con clave gestionada por cliente",
                                      "Considerar usar Azure Disk Encryption o Customer Managed Keys")

            # 6d. Public IP check
            net_profile = getattr(vm, "network_profile", None)
            if net_profile:
                for nic_ref in (net_profile.network_interfaces or []):
                    try:
                        nic_name = nic_ref.id.split("/")[-1]
                        nic_rg = nic_ref.id.split("/")[4]
                        nic = network.network_interfaces.get(nic_rg, nic_name)
                        for ip_cfg in (nic.ip_configurations or []):
                            if ip_cfg.public_ip_address:
                                pip_addr = public_ips.get(
                                    ip_cfg.id.lower(),
                                    ip_cfg.public_ip_address.id.split("/")[-1]
                                )
                                self._add(name, "Virtual Machine", "VMs",
                                          "Alta", f"IP pĂşblica asignada: {pip_addr}",
                                          "Evaluar si la IP pĂşblica es necesaria; usar Bastion o VPN")
                    except Exception:
                        pass

        print(f"  VMs analizadas: {count}")

    # ═══════════════════════════════════════════════════════════════════════
    #  7. AZURE DEVOPS — PIPELINES
    # ═══════════════════════════════════════════════════════════════════════

    def scan_devops_pipelines(self):
        self._print_module("Azure DevOps — Pipelines & Service Connections")

        if not self.devops_pat or not self.devops_org:
            print(f"  {Fore.YELLOW}⚠ Requiere AZURE_DEVOPS_PAT y AZURE_DEVOPS_ORG en .env")
            print(f"  {Fore.YELLOW}  Crear un PAT con scopes: Code(Read), Build(Read), ServiceConnections(Read)")
            return

        import requests
        base = f"https://dev.azure.com/{self.devops_org}"
        count_pipelines = 0
        count_sc = 0

        try:
            # List projects
            projects = self._devops_get(f"{base}/_apis/projects?api-version=7.1")
            for proj in projects.get("value", []):
                pname = proj["name"]
                pid = proj["id"]

                # ── 7a. Pipeline definitions & variables ──
                try:
                    defs = self._devops_get(
                        f"{base}/{pname}/_apis/build/definitions?api-version=7.1"
                    )
                    for d in defs.get("value", []):
                        count_pipelines += 1
                        def_id = d["id"]
                        def_name = d["name"]

                        # Get full definition for variables
                        try:
                            full_def = self._devops_get(
                                f"{base}/{pname}/_apis/build/definitions/{def_id}?api-version=7.1"
                            )

                            # Check variables not marked as secret
                            variables = full_def.get("variables", {})
                            for var_name, var_info in variables.items():
                                is_secret = var_info.get("isSecret", False)
                                value = var_info.get("value", "")
                                if not is_secret and value:
                                    lower = var_name.lower()
                                    sensitive_words = ["password", "secret", "key", "token",
                                                       "credential", "connection", "pat", "apikey",
                                                       "sas", "accountkey"]
                                    if any(w in lower for w in sensitive_words):
                                        self._add(
                                            f"{pname}/{def_name}", "Pipeline Variable", "DevOps Pipelines",
                                            "Crítica",
                                            f"Variable '{var_name}' con nombre sensible NO marcada como secret (valor visible)",
                                            "Marcar la variable como 'secret' en la definición del pipeline"
                                        )

                            # Check triggers (fork PR)
                            triggers = full_def.get("triggers", [])
                            for t in triggers:
                                if t.get("triggerType") == "pullRequest":
                                    forks = t.get("forks", {})
                                    if forks.get("enabled", False) and forks.get("allowSecrets", False):
                                        self._add(
                                            f"{pname}/{def_name}", "Pipeline Trigger", "DevOps Pipelines",
                                            "Crítica",
                                            "Fork PR trigger habilitado CON acceso a secrets",
                                            "Deshabilitar 'allowSecrets' en fork triggers o requerir aprobación manual"
                                        )

                        except Exception:
                            pass
                except Exception:
                    pass

                # ── 7b. Variable Groups ──
                try:
                    vgs = self._devops_get(
                        f"{base}/{pname}/_apis/distributedtask/variablegroups?api-version=7.1"
                    )
                    for vg in vgs.get("value", []):
                        vg_name = vg.get("name", "unknown")
                        variables = vg.get("variables", {})
                        for var_name, var_info in variables.items():
                            is_secret = var_info.get("isSecret", False)
                            value = var_info.get("value", "")
                            if not is_secret and value:
                                lower = var_name.lower()
                                sensitive_words = ["password", "secret", "key", "token",
                                                   "credential", "pat", "apikey", "sas"]
                                if any(w in lower for w in sensitive_words):
                                    self._add(
                                        f"{pname}/VarGroup:{vg_name}", "Variable Group", "DevOps Pipelines",
                                        "Crítica",
                                        f"Variable '{var_name}' en grupo '{vg_name}' con nombre sensible NO marcada como secret",
                                        "Marcar la variable como 'secret' en el Variable Group"
                                    )
                except Exception:
                    pass

                # ── 7c. Service Connections ──
                try:
                    scs = self._devops_get(
                        f"{base}/{pname}/_apis/serviceendpoint/endpoints?api-version=7.1"
                    )
                    for sc in scs.get("value", []):
                        count_sc += 1
                        sc_name = sc.get("name", "unknown")
                        sc_type = sc.get("type", "unknown")
                        is_shared = sc.get("isShared", False)

                        # Check if shared across projects
                        if is_shared:
                            self._add(
                                f"{pname}/{sc_name}", "Service Connection", "DevOps Pipelines",
                                "Alta",
                                f"Service Connection '{sc_name}' ({sc_type}) compartida entre proyectos",
                                "Limitar service connections a un solo proyecto; no compartir sin necesidad"
                            )

                        # Check authorization — all pipelines
                        auth_all = sc.get("data", {}).get("pipelineAuth", "")
                        if sc.get("isReady", True):
                            # Check if all pipelines have access
                            try:
                                auth_url = (f"{base}/{pname}/_apis/pipelines/pipelinepermissions/"
                                            f"endpoint/{sc['id']}?api-version=7.1-preview.1")
                                perms = self._devops_get(auth_url)
                                if perms.get("allPipelines", {}).get("authorized", False):
                                    self._add(
                                        f"{pname}/{sc_name}", "Service Connection", "DevOps Pipelines",
                                        "Alta",
                                        f"Service Connection '{sc_name}' accesible por TODOS los pipelines",
                                        "Restringir a pipelines específicos en Pipeline Permissions"
                                    )
                            except Exception:
                                pass
                except Exception:
                    pass

            print(f"  Pipelines analizados: {count_pipelines}")
            print(f"  Service Connections analizadas: {count_sc}")

        except Exception as e:
            print(f"  {Fore.RED}❌ Error conectando a Azure DevOps: {e}")

    # ═══════════════════════════════════════════════════════════════════════
    #  8. AZURE DEVOPS — REPOSITORIES (SECRET SCANNING)
    # ═══════════════════════════════════════════════════════════════════════

    def scan_devops_repos(self):
        self._print_module("Azure DevOps — Repository Secret Scanning")

        if not self.devops_pat or not self.devops_org:
            print(f"  {Fore.YELLOW}⚠ Requiere AZURE_DEVOPS_PAT y AZURE_DEVOPS_ORG en .env")
            return

        import requests
        base = f"https://dev.azure.com/{self.devops_org}"
        count = 0

        try:
            projects = self._devops_get(f"{base}/_apis/projects?api-version=7.1")
            for proj in projects.get("value", []):
                pname = proj["name"]

                repos = self._devops_get(
                    f"{base}/{pname}/_apis/git/repositories?api-version=7.1"
                )
                for repo in repos.get("value", []):
                    count += 1
                    rname = repo["name"]
                    repo_id = repo["id"]

                    # Check for sensitive files in root and common paths
                    for sensitive_file in SENSITIVE_FILE_PATTERNS:
                        try:
                            items_url = (f"{base}/{pname}/_apis/git/repositories/{repo_id}"
                                         f"/items?path=/{sensitive_file}&api-version=7.1")
                            resp = requests.get(items_url, headers=self._devops_headers(), timeout=15)
                            if resp.status_code == 200:
                                self._add(
                                    f"{pname}/{rname}", "Repository File", "DevOps Repos",
                                    "Crítica" if sensitive_file.endswith((".key", ".pem", ".pfx", ".p12"))
                                    else "Alta",
                                    f"Archivo sensible encontrado en repo: {sensitive_file}",
                                    f"Eliminar '{sensitive_file}' del repositorio y del historial con git-filter-repo"
                                )
                        except Exception:
                            pass

                    # Scan key files for hardcoded secrets
                    files_to_scan = [
                        "azure-pipelines.yml", ".azure-pipelines.yml",
                        "pipeline.yml", "docker-compose.yml",
                        "appsettings.json", "appsettings.Development.json",
                        "web.config", ".env.example", "config.json", "config.yaml",
                        "Dockerfile", "startup.sh", "deploy.sh",
                    ]

                    for fname in files_to_scan:
                        try:
                            content_url = (f"{base}/{pname}/_apis/git/repositories/{repo_id}"
                                           f"/items?path=/{fname}&includeContent=true&api-version=7.1")
                            resp = requests.get(content_url, headers=self._devops_headers(), timeout=15)
                            if resp.status_code == 200:
                                content = resp.text
                                for pattern, desc in SECRET_PATTERNS:
                                    matches = re.findall(pattern, content)
                                    if matches:
                                        self._add(
                                            f"{pname}/{rname}", "Repository Secret", "DevOps Repos",
                                            "Crítica",
                                            f"{desc} en archivo '{fname}'",
                                            "Eliminar secret del código y rotarlo; usar Azure Key Vault o variables secretas"
                                        )
                                        break  # One finding per file per pattern type
                        except Exception:
                            pass

            print(f"  Repositorios analizados: {count}")

        except Exception as e:
            print(f"  {Fore.RED}❌ Error escaneando repos: {e}")

    # ═══════════════════════════════════════════════════════════════════════
    #  9. CONTAINER REGISTRY
    # ═══════════════════════════════════════════════════════════════════════

    def scan_container_registry(self):
        self._print_module("Container Registries")
        from azure.mgmt.containerregistry import ContainerRegistryManagementClient
        client = ContainerRegistryManagementClient(self.credential, self.sub_id)
        count = 0

        for reg in client.registries.list():
            count += 1
            name = reg.name

            # 9a. Admin user
            if getattr(reg, "admin_user_enabled", False):
                self._add(name, "Container Registry", "Container Registry",
                          "Alta", "Admin user habilitado",
                          "Deshabilitar admin user y usar Azure AD / Service Principal")

            # 9b. Public access
            if getattr(reg, "public_network_access", "Enabled") == "Enabled":
                self._add(name, "Container Registry", "Container Registry",
                          "Media", "Acceso de red público habilitado",
                          "Configurar Private Endpoint o restringir con firewall rules")

            # 9c. Encryption
            encryption = getattr(reg, "encryption", None)
            if encryption and getattr(encryption, "status", "disabled") != "enabled":
                self._add(name, "Container Registry", "Container Registry",
                          "Baja", "Sin cifrado con Customer Managed Key",
                          "Considerar habilitar CMK encryption para cumplimiento regulatorio")

            # 9d. SKU check — Basic has limited security features
            sku = getattr(reg, "sku", None)
            if sku and getattr(sku, "name", "").lower() == "basic":
                self._add(name, "Container Registry", "Container Registry",
                          "Media", "SKU Basic — sin soporte para Private Link, Content Trust, etc.",
                          "Considerar actualizar a Premium para funciones de seguridad avanzadas")

        print(f"  Registries analizados: {count}")

    # ═══════════════════════════════════════════════════════════════════════
    #  10. IAM / RBAC
    # ═══════════════════════════════════════════════════════════════════════

    def scan_iam(self):
        self._print_module("IAM / RBAC")
        from azure.mgmt.authorization import AuthorizationManagementClient
        client = AuthorizationManagementClient(self.credential, self.sub_id)

        # 10a. Role assignments at subscription scope
        owner_count = 0
        contributor_count = 0
        sub_scope = f"/subscriptions/{self.sub_id}"

        # Map role definition IDs to names
        role_defs = {}
        for rd in client.role_definitions.list(sub_scope):
            role_defs[rd.id] = rd.role_name

        for ra in client.role_assignments.list_for_scope(sub_scope):
            role_name = role_defs.get(ra.role_definition_id, "Unknown")

            if role_name == "Owner":
                owner_count += 1
                # Flag service principals with Owner
                if ra.principal_type and "ServicePrincipal" in str(ra.principal_type):
                    self._add(
                        ra.principal_id or "unknown", "Role Assignment", "IAM",
                        "Crítica",
                        f"Service Principal con rol Owner en la suscripción",
                        "Asignar rol mínimo necesario (Contributor o role custom)"
                    )

            if role_name == "Contributor":
                contributor_count += 1

        if owner_count > 3:
            self._add(
                "Subscription", "Role Assignment", "IAM",
                "Alta",
                f"{owner_count} asignaciones de Owner en la suscripción (recomendado: máx 3)",
                "Reducir el número de Owners; usar Contributor o roles custom"
            )

        # 10b. Custom roles with * actions
        for rd in client.role_definitions.list(sub_scope, filter="type eq 'CustomRole'"):
            for perm in (rd.permissions or []):
                actions = perm.actions or []
                if "*" in actions:
                    self._add(
                        rd.role_name, "Custom Role", "IAM",
                        "Alta",
                        f"Rol custom '{rd.role_name}' con acción wildcard (*)",
                        "Restringir acciones al mĂ­nimo necesario"
                    )

        # 10c. Classic Administrators
        try:
            for admin in client.classic_administrators.list():
                role = getattr(admin, "role", "")
                self._add(
                    admin.name or "unknown", "Classic Admin", "IAM",
                    "Media",
                    f"Administrador clásico detectado con rol: {role}",
                    "Migrar de Classic Administrators a Azure RBAC"
                )
        except Exception:
            pass

        print(f"  Owners en suscripción: {owner_count}")
        print(f"  Contributors en suscripción: {contributor_count}")

    # ═══════════════════════════════════════════════════════════════════════
    #  11. MICROSOFT DEFENDER FOR CLOUD
    # ═══════════════════════════════════════════════════════════════════════

    def scan_defender(self):
        self._print_module("Microsoft Defender for Cloud")
        from azure.mgmt.security import SecurityCenter

        # SecurityCenter requires a special ascLocation
        client = SecurityCenter(self.credential, self.sub_id, asc_location="centralus")

        expected_providers = {
            "VirtualMachines": "Defender for Servers",
            "SqlServers": "Defender for SQL",
            "AppServices": "Defender for App Service",
            "StorageAccounts": "Defender for Storage",
            "KeyVaults": "Defender for Key Vault",
            "ContainerRegistry": "Defender for Container Registry",
            "KubernetesService": "Defender for Kubernetes",
            "Arm": "Defender for Resource Manager",
            "Dns": "Defender for DNS",
        }

        try:
            scope_id = f"/subscriptions/{self.sub_id}"
            for pricing in client.pricings.list(scope_id).value:
                name = pricing.name
                tier = pricing.pricing_tier

                if name in expected_providers and tier == "Free":
                    self._add(
                        name, "Defender for Cloud", "Defender",
                        "Alta",
                        f"{expected_providers[name]} en tier FREE (sin protección)",
                        f"Habilitar {expected_providers[name]} en tier Standard"
                    )
        except Exception as e:
            print(f"  {Fore.YELLOW}⚠ No se pudo consultar Defender pricing: {e}")

        print(f"  Módulo Defender analizado")

    # ═══════════════════════════════════════════════════════════════════════
    #  12. DIAGNOSTIC SETTINGS
    # ═══════════════════════════════════════════════════════════════════════

    def scan_diagnostics(self):
        self._print_module("Diagnostic Settings (Activity Log)")
        from azure.mgmt.monitor import MonitorManagementClient
        client = MonitorManagementClient(self.credential, self.sub_id)

        # Check subscription-level diagnostic settings (Activity Log)
        sub_scope = f"/subscriptions/{self.sub_id}"
        try:
            # Try different attribute names across SDK versions
            diag_ops = None
            for attr in ("diagnostic_settings", "subscription_diagnostic_settings"):
                diag_ops = getattr(client, attr, None)
                if diag_ops:
                    break

            if diag_ops is None:
                # Fallback: use REST API directly
                from azure.mgmt.monitor.operations import DiagnosticSettingsOperations
                diag_ops = client.diagnostic_settings

            diag_settings = list(diag_ops.list(sub_scope))
            if not diag_settings:
                self._add(
                    "Subscription", "Diagnostic Settings", "Diagnósticos",
                    "Alta",
                    "Sin Diagnostic Settings para Activity Log de la suscripción",
                    "Configurar Diagnostic Settings para enviar Activity Log a Log Analytics / Storage"
                )
            else:
                for ds in diag_settings:
                    # Check if logs are enabled
                    logs = getattr(ds, "logs", []) or []
                    if logs:
                        all_disabled = all(not getattr(log, "enabled", False) for log in logs)
                        if all_disabled:
                            self._add(
                                ds.name or "unknown", "Diagnostic Settings", "Diagnósticos",
                                "Media",
                                f"Diagnostic Setting '{ds.name}' existe pero todos los logs están deshabilitados",
                                "Habilitar las categorías de log necesarias"
                            )
        except Exception as e:
            # If SDK doesn't support it, report as info
            self._add(
                "Subscription", "Diagnostic Settings", "Diagnósticos",
                "Info",
                "No se pudo verificar Diagnostic Settings automáticamente",
                "Verificar manualmente en Azure Portal > Monitor > Diagnostic Settings"
            )
            print(f"  {Fore.YELLOW}⚠ Verificación automática no disponible con esta versión del SDK")

        print(f"  Módulo Diagnósticos analizado")

    # ═══════════════════════════════════════════════════════════════════════
    #  REPORT GENERATION
    # ═══════════════════════════════════════════════════════════════════════

    def export_report(self, filename: str = "reporte_seguridad_azure.xlsx"):
        """Genera reporte Excel y resumen en terminal."""

        print(f"\n{Fore.CYAN}{'═'*60}")
        print(f"  📊  RESUMEN DEL ESCANEO")
        print(f"{'═'*60}{Style.RESET_ALL}")

        if not self.hallazgos:
            print(f"\n  {Fore.GREEN}✅ No se encontraron vulnerabilidades.")
            return

        # Sort by severity
        self.hallazgos.sort(key=lambda h: SEVERITY_ORDER.get(h["Severidad"], 99))

        # Count by severity
        counts = {}
        for h in self.hallazgos:
            sev = h["Severidad"]
            counts[sev] = counts.get(sev, 0) + 1

        sev_colors = {
            "Crítica": Fore.RED,
            "Alta": Fore.LIGHTRED_EX,
            "Media": Fore.YELLOW,
            "Baja": Fore.BLUE,
            "Info": Fore.WHITE,
        }

        total = len(self.hallazgos)
        print(f"\n  Total de hallazgos: {Fore.WHITE}{total}{Style.RESET_ALL}\n")

        for sev in ["Crítica", "Alta", "Media", "Baja", "Info"]:
            c = counts.get(sev, 0)
            if c > 0:
                color = sev_colors.get(sev, "")
                bar = "█" * min(c, 40)
                print(f"  {color}{sev:10s} {bar} {c}{Style.RESET_ALL}")

        # Count by category
        cat_counts = {}
        for h in self.hallazgos:
            cat = h["Categoría"]
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

        print(f"\n  Por categoría:")
        for cat, c in sorted(cat_counts.items(), key=lambda x: -x[1]):
            print(f"    {cat:25s} {c}")

        # Export Excel
        df = pd.DataFrame(self.hallazgos)
        try:
            with pd.ExcelWriter(filename, engine="openpyxl") as writer:
                df.to_excel(writer, index=False, sheet_name="Hallazgos")

                # Auto-adjust column widths
                ws = writer.sheets["Hallazgos"]
                for col in ws.columns:
                    max_len = max(len(str(cell.value or "")) for cell in col)
                    adjusted = min(max_len + 2, 80)
                    ws.column_dimensions[col[0].column_letter].width = adjusted

            print(f"\n  {Fore.GREEN}✅ Reporte guardado: {filename}{Style.RESET_ALL}")
        except Exception as e:
            # Fallback to CSV
            csv_name = filename.replace(".xlsx", ".csv")
            df.to_csv(csv_name, index=False)
            print(f"\n  {Fore.YELLOW}⚠ Error creando Excel ({e}), guardado como CSV: {csv_name}")

    # ═══════════════════════════════════════════════════════════════════════
    #  SCAN ALL
    # ═══════════════════════════════════════════════════════════════════════

    def scan_all(self, modules: list[str] | None = None):
        """Ejecuta todos los módulos de escaneo (o los seleccionados)."""

        all_modules = {
            "storage":    self.scan_storage,
            "network":    self.scan_network,
            "keyvault":   self.scan_keyvault,
            "sql":        self.scan_sql,
            "webapps":    self.scan_web_apps,
            "vms":        self.scan_vms,
            "pipelines":  self.scan_devops_pipelines,
            "repos":      self.scan_devops_repos,
            "acr":        self.scan_container_registry,
            "iam":        self.scan_iam,
            "defender":   self.scan_defender,
            "diagnostics": self.scan_diagnostics,
        }

        # "devops" shortcut
        if modules and "devops" in modules:
            modules.remove("devops")
            modules.extend(["pipelines", "repos"])

        targets = modules if modules else list(all_modules.keys())

        for mod in targets:
            fn = all_modules.get(mod)
            if fn:
                try:
                    fn()
                except Exception as e:
                    print(f"  {Fore.RED}❌ Error en módulo '{mod}': {e}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.YELLOW}⚠ Módulo desconocido: {mod}")


# ─────────────────────────────── CLI ──────────────────────────────────────

def main():
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════╗
║  {Fore.WHITE}🛡️  AzureSecure Scan — Security Auditor{Fore.CYAN}              ║
║  {Fore.WHITE}   Escáner integral de seguridad Azure{Fore.CYAN}               ║
╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    parser = argparse.ArgumentParser(
        description="AzureSecure Scan — Escáner integral de seguridad Azure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Módulos disponibles:
  --storage       Storage Accounts (acceso público, cifrado, firewall)
  --network       Network Security Groups (puertos abiertos, reglas permisivas)
  --keyvault      Key Vaults (soft-delete, claves expiradas, RBAC)
  --sql           SQL Servers/DBs (TDE, auditoría, firewall)
  --webapps       App Services (HTTPS, TLS, FTP, remote debug)
  --vms           Virtual Machines (cifrado, SSH, IP pública)
  --devops        Azure DevOps (equivalente a --pipelines + --repos)
  --pipelines     DevOps Pipelines (secrets, service connections, triggers)
  --repos         DevOps Repos (claves hardcoded, archivos sensibles)
  --acr           Container Registries (admin user, acceso público)
  --iam           IAM/RBAC (roles excesivos, custom roles con *)
  --defender      Microsoft Defender for Cloud (tiers)
  --diagnostics   Diagnostic Settings (Activity Log)

Ejemplos:
  python scanner.py --all
  python scanner.py --storage --network --keyvault
  python scanner.py --devops
  python scanner.py --iam --defender --diagnostics
"""
    )

    parser.add_argument("--all", action="store_true", help="Ejecutar todos los módulos")
    parser.add_argument("--storage", action="store_true", help="Escanear Storage Accounts")
    parser.add_argument("--network", action="store_true", help="Escanear NSGs")
    parser.add_argument("--keyvault", action="store_true", help="Escanear Key Vaults")
    parser.add_argument("--sql", action="store_true", help="Escanear SQL Servers")
    parser.add_argument("--webapps", action="store_true", help="Escanear App Services")
    parser.add_argument("--vms", action="store_true", help="Escanear VMs")
    parser.add_argument("--devops", action="store_true", help="Escanear Azure DevOps (pipelines + repos)")
    parser.add_argument("--pipelines", action="store_true", help="Escanear DevOps Pipelines")
    parser.add_argument("--repos", action="store_true", help="Escanear DevOps Repos")
    parser.add_argument("--acr", action="store_true", help="Escanear Container Registries")
    parser.add_argument("--iam", action="store_true", help="Escanear IAM/RBAC")
    parser.add_argument("--defender", action="store_true", help="Escanear Defender for Cloud")
    parser.add_argument("--diagnostics", action="store_true", help="Escanear Diagnostic Settings")
    parser.add_argument("--subscription", "-s", type=str, default=None,
                        help="ID de suscripción Azure (por defecto: primera disponible)")
    parser.add_argument("--output", "-o", type=str, default="reporte_seguridad_azure.xlsx",
                        help="Nombre del archivo de reporte (default: reporte_seguridad_azure.xlsx)")
    parser.add_argument("--no-gui", action="store_true",
                        help="No mostrar ventana GUI para credenciales DevOps (modo headless/CI)")

    args = parser.parse_args()

    print(banner)

    # Determine modules
    module_flags = {
        "storage": args.storage, "network": args.network, "keyvault": args.keyvault,
        "sql": args.sql, "webapps": args.webapps, "vms": args.vms,
        "devops": args.devops, "pipelines": args.pipelines, "repos": args.repos,
        "acr": args.acr, "iam": args.iam, "defender": args.defender,
        "diagnostics": args.diagnostics,
    }

    selected = [k for k, v in module_flags.items() if v]
    if args.all or not selected:
        selected = None  # None = all

    try:
        scanner = AzureSecurityScanner(subscription_id=args.subscription, no_gui=args.no_gui)
        print(f"  Suscripción: {Fore.WHITE}{scanner.sub_name}{Style.RESET_ALL}")
        print(f"  ID: {scanner.sub_id}")
        print(f"  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        if scanner.devops_org:
            print(f"  Azure DevOps Org: {Fore.WHITE}{scanner.devops_org}{Style.RESET_ALL}")
        else:
            print(f"  Azure DevOps: {Fore.YELLOW}No configurado (set AZURE_DEVOPS_PAT + AZURE_DEVOPS_ORG)")

        scanner.scan_all(modules=selected)
        scanner.export_report(filename=args.output)

    except StopIteration:
        print(f"\n  {Fore.RED}❌ No se encontraron suscripciones Azure.")
        print(f"  Ejecuta 'az login' primero.{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n  {Fore.RED}❌ Error fatal: {e}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()