'''
Repo Scanner - Leer Todos los Archivos de un Proyecto.
Copyright (C) 2025 Santiago Potes Giraldo
SPDX-License-Identifier: GPL-3.0-or-later

Este archivo es parte de Repo-Scanner.

Repo-Scanner is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

'''
#!/usr/bin/env python3
import os
import re
import subprocess
import sys
import shutil

# -------------------------------
# Carpetas a ignorar
# -------------------------------
IGNORE_DIRS = {"auditor","venv", ".git", "node_modules", "__pycache__", ".mypy_cache"}

# -------------------------------
# Filtros por stack para limpiar salida
# -------------------------------
FILTERS_BY_STACK = {
    "django": [
        (r"(SECRET_KEY\s*=\s*['\"].*?['\"])", "SECRET_KEY = '***REDACTED***'"),
        (r"(PASSWORD\s*=\s*['\"].*?['\"])", "PASSWORD = '***REDACTED***'"),
        (r"(API_KEY\s*=\s*['\"].*?['\"])", "API_KEY = '***REDACTED***'"),
        (r"(DEBUG\s*=\s*True)", r"\1  # DEV MODE: No usar en producción"),
        (r"(ALLOWED_HOSTS\s*=\s*\[.*?\])", "ALLOWED_HOSTS = ['*']  # DEV ONLY")
    ],
    "flask": [
        (r"(SECRET_KEY\s*=\s*['\"].*?['\"])", "SECRET_KEY = '***REDACTED***'"),
        (r"(SQLALCHEMY_DATABASE_URI\s*=\s*['\"].*?['\"])", "SQLALCHEMY_DATABASE_URI = '***REDACTED***'"),
        (r"(DEBUG\s*=\s*True)", r"\1  # DEV MODE: No usar en producción")
    ],
    "node": [
        (r"(process\.env\.(?:[A-Z_]+_?KEY|PASSWORD|TOKEN|SECRET)[^\n]*)", "/* ***REDACTED*** */"),
        (r"(['\"](?:AIza|sk-|ghp_)[A-Za-z0-9_\-]+['\"])", "'***REDACTED***'"),
        (r"(app\.listen\(\s*\d+\s*\))", r"\1 // DEV PORT, ajustar en producción")
    ],
    "react": [
        (r"(process\.env\.REACT_APP_[A-Z0-9_]+)", "/* ***REDACTED*** */"),
        (r"(https?:\/\/[^\s'\"]+\/api[^\s'\"]*)", "'***REDACTED_URL***'"),
        (r"(mode:\s*'development')", r"\1 // DEV BUILD")
    ],
    "restapi": [
        (r"(Bearer\s+[A-Za-z0-9_\-\.]+)", "Bearer ***REDACTED***"),
        (r"(Authorization:\s*['\"]?[A-Za-z0-9_\-\.]+['\"]?)", "Authorization: ***REDACTED***"),
        (r"(https?:\/\/(?:localhost|127\.0\.0\.1|192\.\d+\.\d+\.\d+)[^\s'\"]*)", "'***LOCAL_URL***'"),
        (r"(sandbox|dev|staging)", r"\1 // TEST ENVIRONMENT")
    ]
}

# -------------------------------
# Dependencias: detect-secrets
# -------------------------------
def ensure_dependencies():
    if shutil.which("detect-secrets") is None:
        print("[*] Instalando detect-secrets...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "detect-secrets"])

# -------------------------------
# Escaneo con detect-secrets
# -------------------------------
def run_detect_secrets(path="."):
    print(f"[*] Ejecutando detect-secrets en {path}...")
    try:
        subprocess.check_call(["detect-secrets", "scan", path])
    except subprocess.CalledProcessError:
        print("[!] detect-secrets encontró secretos.")
        return False
    return True

# -------------------------------
# Escaneo manual de malware
# -------------------------------
def scan_for_malware(path="."):
    suspicious_patterns = [
        r"os\.fork\(",
        r"subprocess\.Popen",
        r"subprocess\.call",
        r"eval\(",
        r"exec\(",
        r"while\s+True",
    ]
    regex = re.compile("|".join(suspicious_patterns))

    for root, dirs, files in os.walk(path):
        # Ignorar carpetas definidas
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

        for f in files:
            if f.endswith(".py") or f.endswith(".js"):
                file_path = os.path.join(root, f)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                        if regex.search(content):
                            print(f"[!] Posible código peligroso en: {file_path}")
                            return False
                except Exception as e:
                    print(f"[!] No se pudo leer {file_path}: {e}")
    return True

# -------------------------------
# Aplicar filtros por stack
# -------------------------------
def apply_filters(content, stack="django"):
    if stack not in FILTERS_BY_STACK:
        return content
    for pattern, repl in FILTERS_BY_STACK[stack]:
        content = re.sub(pattern, repl, content)
    return content

# -------------------------------
# Pipeline principal
# -------------------------------
def main():
    print("=== PIPELINE DE DETECCIÓN DE SECRETOS Y MALWARE ===")
    ensure_dependencies()

    safe = True
    safe &= run_detect_secrets(".")
    safe &= scan_for_malware(".")

    if safe:
        print("[✓] Escaneo limpio. Puedes ejecutar tu código con seguridad.")
    else:
        print("[✗] Se encontraron riesgos. Corrige antes de ejecutar.")

if __name__ == "__main__":
    main()

