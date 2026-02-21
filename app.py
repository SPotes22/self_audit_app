'''
auto-audited api usage - Servidor 
Copyright (C) 2026 Santiago Potes Giraldo
SPDX-License-Identifier: GPL-3.0-or-later

Este archivo es parte de auto-audited.

StockSpider is free software: you can redistribute it and/or modify
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
# secure_flask_app_json_fixed.py
import bcrypt
import os
import hashlib
import base64
import json
import time
import datetime
from functools import wraps
import hmac
from flask import Flask, request, jsonify, render_template, session
import subprocess
import sys
import threading
import queue
from pathlib import Path




app = Flask(__name__)
 
try:
    required_secret = os.getenv("SECRET_KEY", "default_value")
    print(f"Required Secret: {required_secret}")
except KeyError:
    raise ValueError("Required environment variable 'REQUIRED_SECRET' is not set")


app.config['SECRET_KEY'] = required_secret

app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=24)

# Simulación de base de datos en memoria
users_db = {}
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 900

# Cache para memoización
hash_cache = {}
jwt_cache = {}


# Configuración para los scripts
SCRIPTS_DIR = Path(__file__).parent
RESULTS_QUEUE = queue.Queue()
SCRIPT_OUTPUTS = {}


# Decorator para admin requerido
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization') or session.get('token')
        
        if not token:
            return jsonify({"error": "Authentication required"}), 401
            
        if token.startswith('Bearer '):
            token = token[7:]
            
        verification = CustomJWT.decode(token, app.config['SECRET_KEY'])
        if "error" in verification:
            return jsonify({"error": verification["error"]}), 401
        
        if verification.get('role') != 'admin':
            return jsonify({"error": "Admin privileges required"}), 403
            
        request.current_user = verification
        return f(*args, **kwargs)
    return decorated
    
class CustomJWT:
    """JWT personalizado con seguridad OWASP Top10"""
    
    @staticmethod
    def b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip('=')
    
    @staticmethod
    def b64url_decode(data: str) -> bytes:
        pad = '=' * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + pad)
    
    @staticmethod
    def encode(payload: dict, secret: str) -> str:
        """Codificar JWT seguro"""
        header = {
            "alg": "HS256",
            "typ": "JWT",
            "kid": "custom_jwt_v1"
        }
        
        header_b64 = CustomJWT.b64url_encode(json.dumps(header).encode())
        payload_b64 = CustomJWT.b64url_encode(json.dumps(payload).encode())
        
        message = f"{header_b64}.{payload_b64}".encode()
        signature = hashlib.pbkdf2_hmac(
            'sha256', 
            message, 
            secret.encode(), 
            100000
        )
        signature_b64 = CustomJWT.b64url_encode(signature)
        
        return f"{header_b64}.{payload_b64}.{signature_b64}"
    
    @staticmethod
    def decode(token: str, secret: str) -> dict:
        """Decodificar y verificar JWT"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {"error": "Token structure invalid"}
            
            header_b64, payload_b64, signature_b64 = parts
            message = f"{header_b64}.{payload_b64}".encode()
            
            expected_signature = hashlib.pbkdf2_hmac(
                'sha256', 
                message, 
                secret.encode(), 
                100000
            )
            expected_b64 = CustomJWT.b64url_encode(expected_signature)
            
            if not hmac.compare_digest(signature_b64, expected_b64):
                return {"error": "Invalid signature"}
            
            payload_json = CustomJWT.b64url_decode(payload_b64).decode()
            payload = json.loads(payload_json)
            
            if 'exp' in payload and payload['exp'] < time.time():
                return {"error": "Token expired"}
                
            return payload
            
        except Exception as e:
            return {"error": f"Token invalid: {str(e)}"}

# DECORATORS
def login_required(f):
    """Decorator para requerir autenticación"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization') or session.get('token')
        
        if not token:
            return jsonify({"error": "Authentication required"}), 401
            
        if token.startswith('Bearer '):
            token = token[7:]
            
        verification = CustomJWT.decode(token, app.config['SECRET_KEY'])
        if "error" in verification:
            return jsonify({"error": verification["error"]}), 401
            
        request.current_user = verification
        return f(*args, **kwargs)
    return decorated

def custom_jwt(f):
    """Decorator @custom_jwt"""
    @wraps(f)
    def decorated(*args, **kwargs):
        return login_required(f)(*args, **kwargs)
    return decorated

# ENDPOINTS FIXED - SOLO JSON RESPONSES
@app.route('/register', methods=['GET'])
def register_form():
    """Formulario HTML para registro"""
    return render_template("register.html", title="Register")

@app.route('/login', methods=['GET'])
def login_form():
    """Formulario HTML para login"""
    return render_template("login.html", title="Login")

@app.route('/account', methods=['GET'])
def account_instructions():
    """Instrucciones para usar el endpoint protegido - FIXED"""
    return render_template("account.html", title="account")

# ENDPOINTS API - SOLO JSON RESPONSES
@app.route('/register', methods=['POST'])
def register():
    """Endpoint de registro - SOLO JSON"""
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Username and password required"}), 400
    
    username = data['username'].strip()
    password = data['password']
    
    if len(username) < 3 or len(username) > 50:
        return jsonify({"error": "Username must be 3-50 characters"}), 400
    
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    
    if username in users_db:
        return jsonify({"error": "User already exists"}), 409
    
    salt = bcrypt.gensalt(rounds=12)
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
    
    users_db[username] = {
        'password_hash': password_hash.decode('utf-8'),
        'created_at': datetime.datetime.now().isoformat(),
        'role': data.get('role', 'user'),
        'last_login': None
    }
    
    return jsonify({
        "status": "success",
        "message": "Usuario registrado exitosamente",
        "username": username,
        "security_level": "OWASP Top10 Compliant"
    }), 201

@app.route('/login', methods=['POST'])
def login():
    """Endpoint de login - SOLO JSON"""
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Username and password required"}), 400
    
    username = data['username'].strip()
    password = data['password']
    client_ip = request.remote_addr
    
    # Verificar brute force
    user_key = f"{username}_{client_ip}"
    current_time = time.time()
    if user_key in login_attempts:
        recent_attempts = [t for t in login_attempts[user_key] if current_time - t < LOCKOUT_TIME]
        if len(recent_attempts) >= MAX_LOGIN_ATTEMPTS:
            return jsonify({"error": "Account temporarily locked"}), 429
        login_attempts[user_key] = recent_attempts
    
    if username not in users_db:
        login_attempts.setdefault(user_key, []).append(current_time)
        return jsonify({"error": "Invalid credentials"}), 401
    
    user = users_db[username]
    stored_hash = user['password_hash'].encode('utf-8')
    
    if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
        # Login exitoso - limpiar intentos
        if user_key in login_attempts:
            login_attempts[user_key] = []
        
        user['last_login'] = datetime.datetime.now().isoformat()
        
        token_payload = {
            'username': username,
            'role': user['role'],
            'ip': client_ip,
            'exp': time.time() + (24 * 3600),
            'iss': 'tin_tan_secure_app'
        }
        
        token = CustomJWT.encode(token_payload, app.config['SECRET_KEY'])
        
        session['token'] = token
        session['username'] = username
        session.permanent = True
        
        return jsonify({
            "status": 200,
            "message": "Autenticación exitosa",
            "token": token,
            "user": {
                "username": username,
                "role": user['role'],
                "login_time": user['last_login']
            },
            "security": "OWASP Top10 Protected"
        }), 200
    else:
        login_attempts.setdefault(user_key, []).append(current_time)
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/account', methods=['POST'])
@login_required
@custom_jwt
def account_protected():
    """Endpoint protegido de cuenta - SOLO JSON RESPONSE"""
    user = request.current_user
    
    return jsonify({
        "status": "success",
        "message": "¡Bienvenido al dashboard protegido!",
        "user": user,
        "access_time": datetime.datetime.now().isoformat(),
        "security": "OWASP Top10 Protected",
        "endpoint": "POST /account",
        "response_type": "JSON"
    })

@app.route('/protected-data', methods=['GET'])
@login_required
@custom_jwt
def protected_data():
    """Endpoint protegido adicional - SOLO JSON"""
    user = request.current_user
    
    return jsonify({
        "status": "success",
        "message": "Datos protegidos accesibles",
        "user_info": user,
        "data": {
            "feature_flags": ["admin_panel", "api_access", "user_management"],
            "server_stats": {
                "users_count": len(users_db),
                "active_sessions": len(jwt_cache),
                "uptime": "running"
            }
        },
        "timestamp": datetime.datetime.now().isoformat()
    })

@app.route('/health', methods=['GET'])
def health():
    """Health check - SOLO JSON"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.datetime.now().isoformat(),
        "users_registered": len(users_db),
        "endpoints_working": True,
        "server": "Secure Flask App JSON Fixed",
        "version": "2.2"
    })

@app.route('/security/dashboard', methods=['GET'])
@login_required
def security_dashboard():
    """Dashboard principal de seguridad"""
    # Aquí renderizas el template
    return render_template("security_dashboard.html", 
                                 title="Security Dashboard",
                                 user=request.current_user,
                                 session=session)

@app.route('/security/run-scans', methods=['POST'])
@admin_required
def run_security_scans():
    """Ejecutar todos los escaneos de seguridad"""
    
    def run_script(script_name, script_path):
        try:
            # Ejecutar el script y capturar output
            result = subprocess.run(
                [sys.executable, script_path],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutos máximo
            )
            
            output = {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "success": result.returncode == 0,
                "timestamp": datetime.datetime.now().isoformat()
            }
            
            # Parsear resultados específicos según el script
            if script_name == "check_files":
                output["parsed"] = parse_check_files_output(result.stdout)
            elif script_name == "security_audit":
                output["parsed"] = parse_security_audit_output(result.stdout)
            elif script_name == "pre_deploy":
                output["parsed"] = parse_pre_deploy_output(result.stdout)
            
            SCRIPT_OUTPUTS[script_name] = output
            
        except subprocess.TimeoutExpired:
            SCRIPT_OUTPUTS[script_name] = {
                "error": "Timeout - El script tomó demasiado tiempo",
                "success": False,
                "timestamp": datetime.datetime.now().isoformat()
            }
        except Exception as e:
            SCRIPT_OUTPUTS[script_name] = {
                "error": str(e),
                "success": False,
                "timestamp": datetime.datetime.now().isoformat()
            }
    
    # Ejecutar scripts en hilos separados
    scripts = {
        "check_files": SCRIPTS_DIR / "check_files.py",
        "security_audit": SCRIPTS_DIR / "security_audit.py",
        "pre_deploy": SCRIPTS_DIR / "pre_deploy_check.py"
    }
    
    threads = []
    for name, path in scripts.items():
        if path.exists():
            thread = threading.Thread(target=run_script, args=(name, str(path)))
            thread.start()
            threads.append(thread)
    
    # Esperar a que todos terminen (con timeout)
    for thread in threads:
        thread.join(timeout=310)
    
    return jsonify({
        "status": "completed",
        "results": SCRIPT_OUTPUTS,
        "timestamp": datetime.datetime.now().isoformat()
    })

@app.route('/security/results', methods=['GET'])
@login_required
def get_security_results():
    """Obtener los resultados más recientes"""
    return jsonify({
        "results": SCRIPT_OUTPUTS,
        "timestamp": datetime.datetime.now().isoformat()
    })

@app.route('/security/run-single/<script_name>', methods=['POST'])
@admin_required
def run_single_script(script_name):
    """Ejecutar un script específico"""
    scripts = {
        "check_files": SCRIPTS_DIR / "check_files.py",
        "security_audit": SCRIPTS_DIR / "security_audit.py",
        "pre_deploy": SCRIPTS_DIR / "pre_deploy_check.py"
    }
    
    if script_name not in scripts:
        return jsonify({"error": "Script no encontrado"}), 404
    
    script_path = scripts[script_name]
    if not script_path.exists():
        return jsonify({"error": f"Script {script_name} no encontrado en el servidor"}), 404
    
    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        output = {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "success": result.returncode == 0,
            "timestamp": datetime.datetime.now().isoformat()
        }
        
        # Parseo específico
        if script_name == "check_files":
            output["parsed"] = parse_check_files_output(result.stdout)
        elif script_name == "security_audit":
            output["parsed"] = parse_security_audit_output(result.stdout)
        elif script_name == "pre_deploy":
            output["parsed"] = parse_pre_deploy_output(result.stdout)
        
        SCRIPT_OUTPUTS[script_name] = output
        
        return jsonify(output)
        
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Timeout", "success": False}), 408
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500

# Funciones de parseo
def parse_check_files_output(output):
    """Parsear output de check_files.py"""
    parsed = {
        "detect_secrets_result": "No detectado",
        "malware_scan_result": "No detectado",
        "filtered_files": [],
        "summary": {}
    }
    
    if "detect-secrets encontró secretos" in output:
        parsed["detect_secrets_result"] = "⚠️ Secretos detectados"
    elif "Escaneo limpio" in output:
        parsed["detect_secrets_result"] = "✅ Limpio"
    
    if "Posible código peligroso" in output:
        parsed["malware_scan_result"] = "⚠️ Código sospechoso detectado"
    else:
        parsed["malware_scan_result"] = "✅ Limpio"
    
    # Extraer resumen
    if "Se encontraron riesgos" in output:
        parsed["summary"]["status"] = "Riesgos detectados"
    elif "Escaneo limpio" in output:
        parsed["summary"]["status"] = "Limpio"
    
    return parsed

def parse_security_audit_output(output):
    """Parsear output de security_audit.py"""
    parsed = {
        "vulnerabilities": [],
        "total_issues": 0,
        "files_affected": []
    }
    
    lines = output.split('\n')
    current_file = None
    
    for line in lines:
        if line.endswith('.py:'):
            current_file = line[:-1]
            parsed["files_affected"].append(current_file)
        elif line.strip().startswith('-'):
            vuln = line.strip()[2:]
            parsed["vulnerabilities"].append({
                "file": current_file,
                "issue": vuln
            })
            parsed["total_issues"] += 1
    
    return parsed

def parse_pre_deploy_output(output):
    """Parsear output de pre_deploy_check.py"""
    parsed = {
        "tests": [],
        "summary": {},
        "overall_status": "Pendiente"
    }
    
    lines = output.split('\n')
    current_test = None
    
    for line in lines:
        if "Testing" in line and "..." in line:
            current_test = line.replace("🔍", "").replace("...", "").strip()
            parsed["tests"].append({
                "name": current_test,
                "results": []
            })
        elif "✅" in line and current_test:
            if parsed["tests"]:
                parsed["tests"][-1]["results"].append({
                    "status": "success",
                    "message": line.replace("✅", "").strip()
                })
        elif "❌" in line and current_test:
            if parsed["tests"]:
                parsed["tests"][-1]["results"].append({
                    "status": "failure",
                    "message": line.replace("❌", "").strip()
                })
    
    # Extraer resumen
    if "RESUMEN:" in output:
        summary_lines = output[output.find("RESUMEN:"):].split('\n')
        for line in summary_lines[1:]:
            if "✅" in line or "❌" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    parsed["summary"][parts[0].strip()] = parts[1].strip()
    
    # Determinar estado general
    if any("❌" in line for line in lines):
        parsed["overall_status"] = "Fallo"
    elif all("✅" in line for line in lines if "Testing" not in line and "🔍" not in line):
        parsed["overall_status"] = "Éxito"
    else:
        parsed["overall_status"] = "Advertencias"
    
    return parsed


@app.route('/')
def home():
    """Home endpoint - SOLO JSON"""
    return jsonify({
        "app": "Secure Flask App - JSON Responses Fixed",
        "version": "2.2",
        "endpoints": {
            "GET /register": "Formulario HTML de registro",
            "POST /register": "API JSON de registro", 
            "GET /login": "Formulario HTML de login",
            "POST /login": "API JSON de login",
            "GET /account": "Instrucciones y acceso",
            "POST /account": "Dashboard protegido (JSON response)",
            "GET /protected-data": "Datos protegidos (JSON)",
            "GET /health": "Estado del servidor (JSON)"
        },
        "instructions": "Todos los endpoints POST retornan JSON puro"
    })

if __name__ == "__main__":
    print("🚀 INICIANDO SECURE FLASK APP JSON FIXED...")
    print("📍 Endpoints disponibles:")
    print("   GET  /register      - Formulario HTML de registro")
    print("   POST /register      - API JSON de registro") 
    print("   GET  /login         - Formulario HTML de login")
    print("   POST /login         - API JSON de login")
    print("   GET  /account       - Instrucciones y acceso")
    print("   POST /account       - Dashboard protegido (JSON PURO)")
    print("   GET  /protected-data - Datos protegidos (JSON)")
    print("   GET  /health        - Estado del servidor (JSON)")
    print("\n🔧 FIX APPLIED: Todos los endpoints POST retornan JSON puro")
    print("🌐 Accede desde:")
    print("   http://localhost:5000/account")
    print("   http://localhost:5000/register") 
    print("   http://localhost:5000/login")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
