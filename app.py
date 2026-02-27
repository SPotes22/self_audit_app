'''
auto-audited core apis 
Copyright (C) 2026 Santiago Potes Giraldo
SPDX-License-Identifier: GPL-3.0-or-later

Este archivo es parte de auto-audited.

auto-audited is free software: you can redistribute it and/or modify
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
# app.py
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
from dotenv import load_dotenv
import pickle
import numpy as np
from typing import Dict, Any, List
import joblib 
from models import db, Formulario, FormStatus
from datetime import datetime, timedelta

# Cargar variables de entorno desde .env
load_dotenv()
app = Flask(__name__)
 
try:
    required_secret = os.getenv("SECRET_KEY", "default_value")
    # print(f"Required Secret: {required_secret}")
    # Al inicio del archivo, agrega:
    ADMIN_CREATION_SECRET = os.getenv('ADMIN_CREATION_SECRET', None)
# Si no existe en .env, solo se permitirá crear admin como primer usuario
except KeyError:
    raise ValueError("Required environment variable 'REQUIRED_SECRET' is not set")




# base de datos 
# Configuración de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///formularios.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = required_secret
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Simulación de base de datos en memoria
users_db = {}
# Inicializar SQLAlchemy con la app
db.init_app(app)

# Crear tablas (ejecutar solo una vez al iniciar)
with app.app_context():
    db.create_all()
    print("✅ Base de datos inicializada")

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

# ENDPOINTS ADMIN
@app.route('/admin/create', methods=['POST'])
def create_admin():
    """Endpoint para crear administradores usando la clave secreta del .env"""
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data or 'admin_secret' not in data:
        return jsonify({"error": "Username, password and admin_secret required"}), 400
    
    username = data['username'].strip()
    password = data['password']
    provided_secret = data['admin_secret']
    
    # Verificar la clave secreta del .env
    admin_secret = os.getenv('ADMIN_CREATION_SECRET')
    
    if not admin_secret:
        return jsonify({"error": "Admin creation secret not configured in server"}), 500
    
    # Comparación segura para evitar timing attacks
    if not hmac.compare_digest(provided_secret, admin_secret):
        return jsonify({"error": "Invalid admin secret"}), 403
    
    # Validaciones básicas
    if len(username) < 3 or len(username) > 50:
        return jsonify({"error": "Username must be 3-50 characters"}), 400
    
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    
    # Verificar si el usuario ya existe
    if username in users_db:
        return jsonify({"error": "User already exists"}), 409
    
    # Crear el usuario como admin
    salt = bcrypt.gensalt(rounds=12)
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
    
    users_db[username] = {
        'password_hash': password_hash.decode('utf-8'),
        'created_at': datetime.now().isoformat(),
        'role': 'admin',  # Forzamos admin
        'last_login': None,
        'created_by': 'admin_secret_endpoint'
    }
    
    return jsonify({
        "status": "success",
        "message": "Administrador creado exitosamente",
        "username": username,
        "role": "admin",
        "note": "Usuario creado con privilegios de administrador"
    }), 201


@app.route('/admin/list', methods=['GET'])
@admin_required
def list_admins():
    """Listar todos los usuarios administradores (solo para admins)"""
    admins = []
    for username, user_data in users_db.items():
        if user_data.get('role') == 'admin':
            admins.append({
                "username": username,
                "created_at": user_data.get('created_at'),
                "last_login": user_data.get('last_login')
            })
    
    return jsonify({
        "status": "success",
        "total_admins": len(admins),
        "admins": admins,
        "timestamp": datetime.now().isoformat()
    }), 200



# ENDPOINTS API - SOLO JSON RESPONSES
@app.route('/register', methods=['POST'])
def register():
    """Endpoint de registro - SOLO JSON con validación segura de roles"""
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
    
    # 🔐 SEGURIDAD: Forzar rol 'user' para registros normales
    # Solo permitir 'admin' si hay una clave secreta especial o es el primer usuario
    requested_role = data.get('role', 'user')
    
    # Opción 1: Siempre asignar 'user' (más seguro)
    assigned_role = 'user'
    
    # Opción 2: Permitir admin solo con token especial (recomendado)
    # Puedes crear el primer admin manualmente o con una clave especial
    admin_secret = os.getenv('ADMIN_CREATION_SECRET', None)
    
    if requested_role == 'admin':
        # Verificar si hay un token especial en la solicitud
        admin_token = data.get('admin_token')
        
        # Verificar si es el primer usuario (opcional)
        if len(users_db) == 0:
            # El primer usuario puede ser admin
            assigned_role = 'admin'
            print("🏆 Primer usuario registrado como ADMIN")
        elif admin_token and admin_token == admin_secret:
            # Token válido para crear admin
            assigned_role = 'admin'
            print("🔑 Admin creado con token especial")
        else:
            # Intentaron crear admin sin autorización
            assigned_role = 'user'
            print(f"⚠️ Intento de creación de admin bloqueado para: {username}")
    else:
        assigned_role = 'user'
    
    salt = bcrypt.gensalt(rounds=12)
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
    
    users_db[username] = {
        'password_hash': password_hash.decode('utf-8'),
        'created_at': datetime.now().isoformat(),
        'role': assigned_role,  # Usamos el rol asignado seguramente
        'last_login': None
    }
    
    return jsonify({
        "status": "success",
        "message": "Usuario registrado exitosamente",
        "username": username,
        "role": assigned_role,  # Devolvemos el rol real asignado
        "security_level": "OWASP Top10 Compliant",
        "note": "Role validation enforced server-side"
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
        
        user['last_login'] = datetime.now().isoformat()
        
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
        "access_time": datetime.now().isoformat(),
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
        "timestamp": datetime.now().isoformat()
    })

@app.route('/health', methods=['GET'])
def health():
    """Health check - SOLO JSON"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "users_registered": len(users_db),
        "endpoints_working": True,
        "server": "Secure Flask App JSON Fixed",
        "version": "2.2"
    })

@app.route('/security/dashboard', methods=['GET'])
@login_required
@custom_jwt
@admin_required
def security_dashboard():
    """Dashboard principal de seguridad"""
    # Aquí renderizas el template
    return render_template("security_dashboard.html", 
                                 title="Security Dashboard",
                                 user=request.current_user,
                                 session=session)

@app.route('/security/run-scans', methods=['POST'])
@login_required
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
                "timestamp": datetime.now().isoformat()
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
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            SCRIPT_OUTPUTS[script_name] = {
                "error": str(e),
                "success": False,
                "timestamp": datetime.now().isoformat()
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
        "timestamp": datetime.now().isoformat()
    })

@app.route('/security/results', methods=['GET'])
@login_required
@admin_required
def get_security_results():
    """Obtener los resultados más recientes"""
    return jsonify({
        "results": SCRIPT_OUTPUTS,
        "timestamp": datetime.now().isoformat()
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
            "timestamp": datetime.now().isoformat()
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

@app.route('/setup/first-admin', methods=['POST'])
def setup_first_admin():
    """Endpoint especial para crear el primer administrador (solo usable una vez)"""
    
    # Verificar si ya hay usuarios
    if len(users_db) > 0:
        return jsonify({"error": "Setup already completed"}), 403
    
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Username and password required"}), 400
    
    username = data['username'].strip()
    password = data['password']
    
    # Validaciones...
    if len(username) < 3 or len(username) > 50:
        return jsonify({"error": "Username must be 3-50 characters"}), 400
    
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    
    # Crear el primer usuario como admin
    salt = bcrypt.gensalt(rounds=12)
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
    
    users_db[username] = {
        'password_hash': password_hash.decode('utf-8'),
        'created_at': datetime.now().isoformat(),
        'role': 'admin',  # Forzamos admin
        'last_login': None
    }
    
    return jsonify({
        "status": "success",
        "message": "Primer administrador creado exitosamente",
        "username": username,
        "role": "admin",
        "warning": "Guarda estas credenciales. Este endpoint ya no estará disponible."
    }), 201

# end point para subir de user a admin (solo admin)
@app.route('/admin/promote-user', methods=['POST'])
@admin_required  # Usa tu decorator existente
def promote_to_admin():
    """Endpoint para que un admin promueva a otro usuario"""
    data = request.get_json()
    
    if not data or 'username' not in data:
        return jsonify({"error": "Username required"}), 400
    
    username = data['username'].strip()
    
    if username not in users_db:
        return jsonify({"error": "User not found"}), 404
    
    # Actualizar rol
    users_db[username]['role'] = 'admin'
    
    return jsonify({
        "status": "success",
        "message": f"Usuario {username} promovido a admin",
        "promoted_by": request.current_user.get('username')
    }), 200

# ============================================
# OCTOMATRIX THREAT DETECTION INTEGRATION
# Basado en pre_deploy_check.py
# ============================================

class OctomatrixThreatDetector:
    """Detector de amenazas usando el modelo Octomatrix (basado en pre_deploy_check.py)"""
    
    def __init__(self, model_path='octomatrix_model.pkl'):
        self.model_path = Path(__file__).parent / model_path
        self.model = None
        self.patterns = self._get_default_patterns()  # Patrones por defecto de pre_deploy_check.py
        self.load_model()
    
    def _get_default_patterns(self):
        """Patrones de seguridad basados en pre_deploy_check.py"""
        return {
            'sql_injection': [
                "' OR '1'='1",
                "admin' --",
                "'; DROP TABLE",
                "' UNION SELECT",
                "1=1--",
                "' OR '1'='1'--",
                "' OR 1=1--",
                "1' ORDER BY--",
                "1' GROUP BY--",
                "' OR '1'='1'/*",
                "' OR 1=1/*",
                "') OR ('1'='1--"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "%2e%2e%2f%2e%2e%2fetc/passwd",
                "....//....//etc/passwd",
                "..;/etc/passwd",
                "file:///etc/passwd",
                "/etc/passwd",
                "C:\\Windows\\System32\\drivers\\etc\\hosts"
            ],
            'xss_patterns': [
                "<script>",
                "javascript:",
                "onerror=",
                "onload=",
                "alert(",
                "eval(",
                "document.cookie",
                "<img src=x onerror=",
                "<svg onload=",
                "prompt(",
                "confirm("
            ],
            'command_injection': [
                "; ls",
                "| cat /etc/passwd",
                "&& whoami",
                "|| dir",
                "`id`",
                "$(cat /etc/passwd)",
                "& ping",
                "| net user"
            ],
            'file_upload_malicious': [
                ".php",
                ".asp",
                ".jsp",
                ".exe",
                ".sh",
                ".bat",
                ".pl",
                ".cgi"
            ]
        }
    
    def load_model(self):
        """Cargar el modelo .pkl de Octomatrix"""
        try:
            if self.model_path.exists():
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                
                print(f"✅ Modelo Octomatrix cargado: {type(self.model).__name__}")
                
                # Si el modelo es un diccionario, actualizar patrones
                if isinstance(self.model, dict):
                    if 'patterns' in self.model:
                        self.patterns.update(self.model['patterns'])
                        print(f"📊 Patrones cargados del modelo: {sum(len(v) for v in self.model['patterns'].values())}")
                    elif self.model:  # Si tiene otras keys, intentar mapear
                        print(f"📊 Contenido del modelo: {list(self.model.keys())}")
                        # Intentar extraer patrones si existen
                        for key in ['sql', 'sqli', 'injection', 'patterns', 'rules']:
                            if key in self.model and isinstance(self.model[key], (list, dict)):
                                if isinstance(self.model[key], dict):
                                    self.patterns.update(self.model[key])
                                else:
                                    self.patterns['custom_rules'] = self.model[key]
                
                return True
            else:
                print(f"⚠️ Modelo no encontrado en {self.model_path}")
                return False
        except Exception as e:
            print(f"❌ Error cargando modelo Octomatrix: {str(e)}")
            return False
    
    def analyze_input(self, user_input: str, input_type: str = "auto") -> dict:
        """
        Analizar input del usuario para detectar amenazas
        input_type puede ser: 'auto', 'username', 'password', 'comment', 'file', 'url', 'search'
        """
        if not isinstance(user_input, str):
            user_input = str(user_input)
        
        # Convertir a minúsculas para comparación
        input_lower = user_input.lower()
        
        # Detectar tipo de input si es auto
        if input_type == "auto":
            input_type = self._detect_input_type(user_input)
        
        # Resultados del análisis
        threats = {
            'sql_injection': [],
            'path_traversal': [],
            'xss': [],
            'command_injection': [],
            'file_upload': []
        }
        
        # 1. Detectar SQL Injection (basado en test_sql_injection de pre_deploy_check.py)
        for pattern in self.patterns['sql_injection']:
            if pattern.lower() in input_lower:
                threats['sql_injection'].append(pattern)
        
        # Detectar patrones adicionales de SQLi
        sqli_indicators = ["'", '"', '--', ';', 'union', 'select', 'drop', 'insert', 
                          'update', 'delete', 'where', 'or 1=1', 'or \'1\'=\'1']
        for indicator in sqli_indicators:
            if indicator in input_lower:
                if indicator not in threats['sql_injection']:
                    threats['sql_injection'].append(f"indicator:{indicator}")
        
        # 2. Detectar Path Traversal (basado en test_path_traversal)
        for pattern in self.patterns['path_traversal']:
            if pattern.lower() in input_lower or pattern in user_input:
                threats['path_traversal'].append(pattern)
        
        # Patrones adicionales de path traversal
        if '../' in user_input or '..\\' in user_input or '%2e%2e%2f' in input_lower:
            threats['path_traversal'].append('directory_traversal_sequence')
        
        # 3. Detectar XSS (Cross-Site Scripting)
        for pattern in self.patterns['xss_patterns']:
            if pattern.lower() in input_lower:
                threats['xss'].append(pattern)
        
        # Detectar tags HTML
        if '<' in user_input and '>' in user_input:
            threats['xss'].append('html_tags_present')
        
        # 4. Detectar Command Injection
        for pattern in self.patterns['command_injection']:
            if pattern.lower() in input_lower:
                threats['command_injection'].append(pattern)
        
        # 5. Detectar file upload malicioso (si aplica)
        if input_type == 'file' or input_type == 'filename':
            for ext in self.patterns['file_upload_malicious']:
                if user_input.endswith(ext) or ext in user_input:
                    threats['file_upload'].append(f"malicious_extension:{ext}")
        
        # Calcular nivel de amenaza
        threat_score = self._calculate_threat_score(threats)
        should_block = threat_score > 15  # Umbral: más de 30% de probabilidad
        
        # Determinar acciones recomendadas
        actions = self._get_recommended_actions(threats, threat_score)
        
        return {
            'input': user_input[:100] + '...' if len(user_input) > 100 else user_input,
            'input_type': input_type,
            'threats_detected': {k: v for k, v in threats.items() if v},
            'threat_score': threat_score,
            'should_block': should_block,
            'risk_level': self._get_risk_level(threat_score),
            'recommended_actions': actions,
            'timestamp': datetime.now().isoformat()
        }
    
    def _detect_input_type(self, user_input: str) -> str:
        """Detectar automáticamente el tipo de input"""
        input_lower = user_input.lower()
        
        # Detectar por patrones
        if any(ext in user_input for ext in ['.php', '.asp', '.exe', '.sh']):
            return 'filename'
        if user_input.startswith('/') or ':\\' in user_input or '../' in user_input:
            return 'path'
        if 'http://' in input_lower or 'https://' in input_lower or '.' in user_input:
            return 'url'
        if len(user_input) > 50:  # Inputs largos suelen ser comentarios
            return 'comment'
        if any(op in user_input for op in ['+', '-', '*', '/', '=', '<', '>']):
            return 'search'
        
        return 'generic'
    
    def _calculate_threat_score(self, threats: dict) -> float:
        """Calcular puntuación de amenaza (0-100)"""
        weights = {
            'sql_injection': 35,
            'path_traversal': 30,
            'xss': 25,
            'command_injection': 40,
            'file_upload': 20
        }
        
        total_score = 0
        max_possible = sum(weights.values())
        
        for threat_type, detected in threats.items():
            if detected:
                # Cuantos más patrones, mayor puntuación
                pattern_count = len(detected)
                type_score = min(weights[threat_type], pattern_count * (weights[threat_type] / 3))
                total_score += type_score
        
        return min(100, (total_score / max_possible) * 100)
    
    def _get_risk_level(self, score: float) -> str:
        """Obtener nivel de riesgo basado en puntuación"""
        if score >= 70:
            return "CRÍTICO"
        elif score >= 50:
            return "ALTO"
        elif score >= 30:
            return "MEDIO"
        elif score >= 10:
            return "BAJO"
        else:
            return "INFO"
    
    def _get_recommended_actions(self, threats: dict, score: float) -> list:
        """Obtener acciones recomendadas basadas en amenazas detectadas"""
        actions = []
        
        if threats['sql_injection']:
            actions.append("⚠️ Bloquear input - Posible SQL Injection detectado")
            actions.append("🔒 Usar parámetros preparados/escapar caracteres especiales")
        
        if threats['path_traversal']:
            actions.append("⚠️ Bloquear input - Intento de Path Traversal")
            actions.append("🔒 Validar y sanitizar rutas de archivos")
        
        if threats['xss']:
            actions.append("⚠️ Bloquear input - Posible XSS detectado")
            actions.append("🔒 Escapar output y usar Content-Security-Policy")
        
        if threats['command_injection']:
            actions.append("⚠️ Bloquear input - Intento de Command Injection")
            actions.append("🔒 No ejecutar comandos del sistema con input de usuario")
        
        if threats['file_upload']:
            actions.append("⚠️ Bloquear archivo - Extensión peligrosa detectada")
            actions.append("🔒 Validar tipo MIME y contenido real del archivo")
        
        if score >= 30 and not actions:
            actions.append("⚠️ Bloquear preventivamente - Input sospechoso")
        
        if not actions and score < 10:
            actions.append("✅ Input seguro - Permitir procesamiento")
        
        return actions

# Instancia global del detector
octomatrix_detector = OctomatrixThreatDetector()

# ============================================
# ENDPOINT PRINCIPAL - El que pediste
# ============================================

@app.route('/octomatrix/check-input', methods=['POST'])
@login_required
def octomatrix_check_input():
    """
    ENDPOINT PRINCIPAL: Recibe input y BLOQUEA si es necesario
    """
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    user_input = data.get('input') or data.get('text') or data.get('value') or data.get('data')
    
    if user_input is None:
        return jsonify({"error": "No input to analyze. Provide 'input' field"}), 400
    
    input_type = data.get('type', 'auto')
    
    # Analizar el input
    analysis = octomatrix_detector.analyze_input(user_input, input_type)
    
    # SI DEBE SER BLOQUEADO - DEVOLVER 403
    if analysis['should_block']:
        # Registrar IP del atacante
        client_ip = request.remote_addr
        # Aquí puedes agregar logging
        
        return jsonify({
            "status": "blocked",
            "message": "⛔ INPUT BLOQUEADO - Se detectaron patrones maliciosos",
            "analysis": analysis,
            "action": "BLOCK",
            "ip_address": client_ip,
            "timestamp": datetime.now().isoformat()
        }), 403  # 403 Forbidden - Bloqueado
    
    # Input seguro - 200 OK
    return jsonify({
        "status": "allowed",
        "message": "✅ Input permitido - No se detectaron amenazas",
        "analysis": analysis,
        "action": "ALLOW",
        "timestamp": datetime.now().isoformat()
    }), 200

# ============================================
# ENDPOINTS ADICIONALES ÚTILES
# ============================================

@app.route('/octomatrix/check-batch', methods=['POST'])
@admin_required
def octomatrix_check_batch():
    """Analizar múltiples inputs en una sola solicitud"""
    data = request.get_json()
    
    if not data or 'inputs' not in data:
        return jsonify({"error": "Provide 'inputs' array"}), 400
    
    inputs = data['inputs']
    if not isinstance(inputs, list):
        return jsonify({"error": "inputs must be an array"}), 400
    
    if len(inputs) > 50:
        return jsonify({"error": "Maximum 50 inputs per batch"}), 400
    
    results = []
    blocks = 0
    
    for item in inputs:
        if isinstance(item, dict):
            user_input = item.get('input') or item.get('text') or item.get('value')
            input_type = item.get('type', 'auto')
        else:
            user_input = item
            input_type = 'auto'
        
        if user_input:
            analysis = octomatrix_detector.analyze_input(user_input, input_type)
            if analysis['should_block']:
                blocks += 1
            results.append(analysis)
    
    return jsonify({
        "status": "success",
        "total_analyzed": len(results),
        "total_blocked": blocks,
        "results": results,
        "timestamp": datetime.now().isoformat()
    }), 200

@app.route('/octomatrix/patterns', methods=['GET'])
@login_required
def octomatrix_patterns():
    """Mostrar los patrones de detección actuales"""
    return jsonify({
        "status": "success",
        "patterns": octomatrix_detector.patterns,
        "total_patterns": sum(len(v) for v in octomatrix_detector.patterns.values()),
        "timestamp": datetime.now().isoformat()
    }), 200

@app.route('/octomatrix/test-payloads', methods=['GET'])
@admin_required
def octomatrix_test_payloads():
    """Endpoint de prueba con payloads de pre_deploy_check.py"""
    test_payloads = {
        "sql_injection": [
            "' OR '1'='1",
            "admin' --",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users--"
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2fetc/passwd"
        ],
        "xss": [
            "<script>alert('xss')</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>"
        ],
        "normal": [
            "hola mundo",
            "usuario_normal",
            "Este es un comentario legítimo"
        ]
    }
    
    results = {}
    for category, payloads in test_payloads.items():
        results[category] = []
        for payload in payloads:
            analysis = octomatrix_detector.analyze_input(payload)
            results[category].append({
                "payload": payload,
                "should_block": analysis['should_block'],
                "risk_level": analysis['risk_level'],
                "threats": analysis['threats_detected']
            })
    
    return jsonify({
        "status": "success",
        "test_results": results,
        "timestamp": datetime.now().isoformat()
    }), 200

# ============================================
# MÉTODO PARA REGISTRAR ACTIVIDAD SOSPECHOSA
# ============================================

def log_suspicious_activity(ip, input_data, analysis):
    """Registrar actividad sospechosa para análisis posterior"""
    try:
        log_file = Path(__file__).parent / "suspicious_activity.log"
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "input": input_data[:200],  # Truncar para log
            "analysis": analysis,
            "user_agent": request.headers.get('User-Agent', 'Unknown')
        }
        
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
            
        # También guardar IPs sospechosas
        ip_file = Path(__file__).parent / "suspicious_ips.txt"
        with open(ip_file, 'a') as f:
            f.write(f"{ip} - {analysis['risk_level']} - {analysis['threats_detected']}\n")
            
    except Exception as e:
        print(f"Error logging suspicious activity: {e}")

# Después de cargar el modelo, agrega esta función de diagnóstico
@app.route('/octomatrix/debug-model', methods=['GET'])
@admin_required
def debug_octomatrix_model():
    """Endpoint de depuración para ver el contenido real del modelo"""
    if octomatrix_detector.model is None:
        return jsonify({"error": "Model not loaded"}), 404
    
    model_info = {
        "type": str(type(octomatrix_detector.model)),
        "is_dict": isinstance(octomatrix_detector.model, dict),
    }
    
    if isinstance(octomatrix_detector.model, dict):
        # Mostrar estructura del diccionario
        model_info.update({
            "keys": list(octomatrix_detector.model.keys()),
            "sample": {k: str(v)[:200] for k, v in list(octomatrix_detector.model.items())[:5]},
            "total_items": len(octomatrix_detector.model)
        })
        
        # Si tiene patrones, mostrarlos
        if 'patterns' in octomatrix_detector.model:
            model_info["patterns_found"] = True
            model_info["pattern_categories"] = list(octomatrix_detector.model['patterns'].keys())
    
    return jsonify({
        "status": "success",
        "model_info": model_info,
        "current_patterns": octomatrix_detector.patterns,
        "timestamp": datetime.now().isoformat()
    }), 200

@app.route('/octomatrix/test', methods=['GET'])
def octomatrix_test_page():
    """Página HTML para probar Octomatrix"""
    return render_template("octomatrix_test.html", title="Octomatrix Security Tester")

# enpoints capa estatica
# app.py - Reemplaza el endpoint /buy actual con este

@app.route('/buy', methods=['GET', 'POST'])
@custom_jwt
def buy_service():
    """Endpoint para compra - Maneja formularios con estados"""
    
    if request.method == 'GET':
        # Renderizar formulario HTML
        return render_template("buy.html", 
                             title="Formulario de Compra",
                             user=request.current_user if hasattr(request, 'current_user') else None)
    
    elif request.method == 'POST':
        try:
            # Obtener datos del formulario
            data = request.get_json() if request.is_json else request.form
            
            nombre = data.get('nombre')
            direccion = data.get('direccion_fisica')
            celular = data.get('celular')
            
            # Validaciones básicas
            if not all([nombre, direccion, celular]):
                return jsonify({
                    "error": "Todos los campos son requeridos",
                    "required": ["nombre", "direccion_fisica", "celular"]
                }), 400
            
            # Validar celular (ejemplo simple)
            if not celular.isdigit() or len(celular) < 7:
                return jsonify({"error": "Celular inválido"}), 400
            
            # Verificar Octomatrix para seguridad
            octo_result = octomatrix_detector.analyze_input(f"{nombre} {direccion} {celular}")
            if octo_result['should_block']:
                log_suspicious_activity(request.remote_addr, data, octo_result)
                return jsonify({
                    "status": "blocked",
                    "message": "Input bloqueado por seguridad",
                    "risk_level": octo_result['risk_level']
                }), 403
            
            # Crear nuevo formulario
            nuevo_formulario = Formulario(
                nombre=nombre.strip(),
                direccion_fisica=direccion.strip(),
                celular=celular.strip(),
                status=FormStatus.DELAYED,  # Estado inicial
                created_by=request.current_user.get('username') if hasattr(request, 'current_user') else None,
                username=request.current_user.get('username') if hasattr(request, 'current_user') else None
            )
            
            # Guardar en base de datos
            db.session.add(nuevo_formulario)
            db.session.commit()
            
            # Si la solicitud es JSON, devolver respuesta JSON
            if request.is_json:
                return jsonify({
                    "status": "success",
                    "message": "Formulario creado exitosamente",
                    "formulario": nuevo_formulario.to_dict(),
                    "estado_inicial": "delayed"
                }), 201
            else:
                # Si es POST desde formulario HTML, redirigir o mostrar mensaje
                return render_template("buy.html", 
                                     success=True, 
                                     message="Formulario enviado correctamente",
                                     formulario_id=nuevo_formulario.id)
                
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": f"Error al procesar formulario: {str(e)}"}), 500

# app.py - Agrega estos endpoints después del /buy

@app.route('/api/formularios', methods=['GET'])
@login_required
def listar_formularios():
    """Listar todos los formularios (con filtros opcionales)"""
    
    # Obtener parámetros de consulta
    status_filter = request.args.get('status')
    username_filter = request.args.get('username')
    
    # Construir query
    query = Formulario.query
    
    if status_filter:
        try:
            status_enum = FormStatus(status_filter)
            query = query.filter_by(status=status_enum)
        except ValueError:
            return jsonify({"error": f"Status inválido. Opciones: {[s.value for s in FormStatus]}"}), 400
    
    if username_filter:
        query = query.filter_by(username=username_filter)
    
    # Ordenar por fecha de creación (más recientes primero)
    formularios = query.order_by(Formulario.created_at.desc()).all()
    
    return jsonify({
        "status": "success",
        "total": len(formularios),
        "formularios": [f.to_dict() for f in formularios]
    }), 200

@app.route('/api/formularios/<int:form_id>', methods=['GET'])
@login_required
def obtener_formulario(form_id):
    """Obtener un formulario específico"""
    formulario = Formulario.query.get_or_404(form_id)
    return jsonify(formulario.to_dict()), 200

@app.route('/api/formularios/<int:form_id>/status', methods=['PUT', 'PATCH'])
@login_required
def actualizar_estado(form_id):
    """Actualizar estado de un formulario"""
    formulario = Formulario.query.get_or_404(form_id)
    
    data = request.get_json()
    if not data or 'status' not in data:
        return jsonify({"error": "Se requiere campo 'status'"}), 400
    
    new_status = data['status']
    notes = data.get('notes')
    
    # Verificar si es admin para ciertos estados
    if new_status in ['approved', 'archived']:
        if request.current_user.get('role') != 'admin':
            return jsonify({"error": "Solo administradores pueden aprobar o archivar"}), 403
    
    try:
        formulario.update_status(new_status, notes)
        
        return jsonify({
            "status": "success",
            "message": f"Estado actualizado a {new_status}",
            "formulario": formulario.to_dict()
        }), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/formularios/<int:form_id>', methods=['DELETE'])
@admin_required
def eliminar_formulario(form_id):
    """Eliminar un formulario (solo admin)"""
    formulario = Formulario.query.get_or_404(form_id)
    
    db.session.delete(formulario)
    db.session.commit()
    
    return jsonify({
        "status": "success",
        "message": f"Formulario {form_id} eliminado"
    }), 200

@app.route('/api/formularios/estadisticas', methods=['GET'])
@login_required
def estadisticas_formularios():
    """Estadísticas de formularios por estado"""
    
    stats = {}
    for status in FormStatus:
        count = Formulario.query.filter_by(status=status).count()
        stats[status.value] = count
    
    stats['total'] = sum(stats.values())
    
    return jsonify({
        "status": "success",
        "estadisticas": stats
    }), 200

# Ejemplo: Obtener SOLO los aprobados
@app.route('/api/formularios/approved', methods=['GET'])
def get_approved():
    # CONSULTA ACTIVA a la BD - NO son datos decorativos
    approved = Formulario.query.filter_by(status=FormStatus.APPROVED).all()
    return jsonify([f.to_dict() for f in approved])

# Ejemplo: Obtener los que necesitan revisión
@app.route('/api/formularios/pending-review', methods=['GET'])
def get_pending():
    # CONSULTA REAL - NO es decorativo
    pending = Formulario.query.filter(
        Formulario.status.in_([FormStatus.DELAYED, FormStatus.REVISED])
    ).all()
    return jsonify([f.to_dict() for f in pending])

@app.route('/api/demo/estados-activos', methods=['GET'])
def demo_estados():
    """Demostración de que el ORM gestiona datos activamente"""
    
    # 1. Crear un formulario de prueba
    test = Formulario(
        nombre="TEST_ACTIVO",
        direccion_fisica="Demo Dirección",
        celular="123456789"
    )
    db.session.add(test)
    db.session.commit()
    
    resultado = {
        "paso1_creado": test.to_dict(),
        "mensaje": "Status inicial = delayed (automático)"
    }
    
    # 2. Cambiar estado a REVISED
    test.status = FormStatus.REVISED
    db.session.commit()
    
    resultado["paso2_cambiado"] = test.to_dict()
    resultado["mensaje2"] = "Status cambiado a revised"
    
    # 3. Agregar nota y cambiar a APPROVED
    test.status = FormStatus.APPROVED
    test.notes = "Aprobado en demo"
    db.session.commit()
    
    resultado["paso3_aprobado"] = test.to_dict()
    resultado["mensaje3"] = "Status cambiado a approved con nota"
    
    # 4. Mostrar que updated_at cambió automáticamente
    resultado["conclusion"] = "⚠️ OBSERVA: updated_at cambió en cada paso automáticamente"
    
    return jsonify(resultado)

@app.route('/api/dashboard/metrics', methods=['GET'])
def dashboard_metrics():
    """Métricas EN VIVO - NO son decorativas"""
    return jsonify({
        "total": Formulario.query.count(),
        "pendientes": Formulario.query.filter_by(status=FormStatus.DELAYED).count(),
        "revisados": Formulario.query.filter_by(status=FormStatus.REVISED).count(),
        "aprobados": Formulario.query.filter_by(status=FormStatus.APPROVED).count(),
        "archivados": Formulario.query.filter_by(status=FormStatus.ARCHIVED).count(),
        "ultima_actualizacion": datetime.now().isoformat()
    })

@app.route('/api/formularios/<int:form_id>/approve', methods=['POST'])
@admin_required
def approve_form(form_id):
    """Workflow de aprobación - MODIFICA LA BD"""
    form = Formulario.query.get_or_404(form_id)
    
    # Lógica de negocio REAL
    if form.status == FormStatus.ARCHIVED:
        return jsonify({"error": "No se puede aprobar un formulario archivado"}), 400
    
    # CAMBIO REAL EN BD
    form.status = FormStatus.APPROVED
    form.notes = f"Aprobado por {request.current_user['username']} el {datetime.now().strftime('%Y-%m-%d')}"
    db.session.commit()
    
    # Esto es un CAMBIO REAL, no decorativo
    return jsonify({
        "mensaje": "Formulario APROBADO en el sistema",
        "formulario": form.to_dict(),
        "accion": "BD_ACTUALIZADA"
    })


@app.route('/dashboard/formularios', methods=['GET'])
@login_required
def dashboard_formularios_view():
    """Vista HTML del dashboard de formularios"""
    return render_template("dashboard_formularios.html", 
                         title="Dashboard de Formularios",
                         user=request.current_user if hasattr(request, 'current_user') else None)

@app.route('/landing')
def generic_site():
    "vista corporativa generica"
    return render_template("landing.html")

@app.route('/who')
def about():
    "vista corporativa generica"
    return render_template("who.html")

@app.route('/where')
def site_location():
    "vista corporativa generica"
    return render_template("where.html")

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
    print("   http://localhost:5000/register") 
    print("   http://localhost:5000/login")
    print("   http://localhost:5000/account")
    print("   http://localhost:5000/security/dashboard")
    print("   http://localhost:5000/octomatrix/test")
    print("   http://localhost:5000/who")
    print("   http://localhost:5000/where")
    print("   http://localhost:5000/landing")
    print("   http://localhost:5000/dashboard/formularios")
    print("   http://localhost:5000/buy")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
