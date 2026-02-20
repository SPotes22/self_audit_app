# static_serve.py
import os
import mimetypes
from flask import send_from_directory, abort, jsonify
from functools import wraps

STATIC_DIR = "static_files"
ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.jpg', '.png', '.gif', '.html', '.css', '.js'}

def static_file_required(f):
    """Decorator para servir archivos estáticos de solo lectura"""
    @wraps(f)
    def decorated(*args, **kwargs):
        filename = kwargs.get('filename', '')
        
        # Security checks
        if '..' in filename or filename.startswith('/'):
            return jsonify({"error": "Invalid path"}), 400
            
        filepath = os.path.join(STATIC_DIR, filename)
        
        # Check if file exists and is within static directory
        real_path = os.path.realpath(filepath)
        static_real = os.path.realpath(STATIC_DIR)
        
        if not real_path.startswith(static_real):
            return jsonify({"error": "Access denied"}), 403
            
        if not os.path.exists(real_path):
            return jsonify({"error": "File not found"}), 404
            
        # Check file extension
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            return jsonify({"error": "File type not allowed"}), 403
            
        kwargs['filepath'] = real_path
        return f(*args, **kwargs)
    return decorated

def setup_static_routes(app):
    """Configurar rutas estáticas"""
    
    # Create static directory if not exists
    os.makedirs(STATIC_DIR, exist_ok=True)
    
    @app.route('/static/<path:filename>', methods=['GET'])
    @static_file_required
    def serve_static(filename, filepath=None):
        """Servir archivos estáticos de solo lectura"""
        try:
            return send_from_directory(STATIC_DIR, filename)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @app.route('/static-list', methods=['GET'])
    def list_static_files():
        """Listar archivos estáticos disponibles"""
        files = []
        for root, dirs, filenames in os.walk(STATIC_DIR):
            for f in filenames:
                ext = os.path.splitext(f)[1].lower()
                if ext in ALLOWED_EXTENSIONS:
                    rel_path = os.path.relpath(os.path.join(root, f), STATIC_DIR)
                    files.append({
                        'name': f,
                        'path': rel_path.replace('\\', '/'),
                        'size': os.path.getsize(os.path.join(root, f)),
                        'type': mimetypes.guess_type(f)[0] or 'application/octet-stream'
                    })
        
        return jsonify({
            'status': 'success',
            'files': files,
            'total': len(files)
        })
    
    @app.route('/static-info/<path:filename>', methods=['GET'])
    @static_file_required
    def static_file_info(filename, filepath=None):
        """Obtener información de un archivo estático"""
        stat = os.stat(filepath)
        return jsonify({
            'filename': filename,
            'size': stat.st_size,
            'modified': stat.st_mtime,
            'type': mimetypes.guess_type(filename)[0],
            'read_only': True
        })
    
    return app
