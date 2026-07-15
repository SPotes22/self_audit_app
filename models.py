# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import enum

# Crear instancia de SQLAlchemy que será usada en app.py
db = SQLAlchemy()

# Enumeración para los estados del formulario
class FormStatus(enum.Enum):
    DELAYED = "delayed"
    REVISED = "revised"
    APPROVED = "approved"
    ARCHIVED = "archived"

    @classmethod
    def choices(cls):
        return [(choice.value, choice.name.capitalize()) for choice in cls]


class Formulario(db.Model):
    """Modelo ORM para los formularios de compra"""
    __tablename__ = 'formularios'

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    direccion_fisica = db.Column(db.String(200), nullable=False)
    celular = db.Column(db.String(20), nullable=False)
    
    # Estados según tu especificación
    status = db.Column(db.Enum(FormStatus), 
                      default=FormStatus.DELAYED, 
                      nullable=False)
    
    # Metadatos adicionales útiles
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.String(50), nullable=True)
    
    # Notas/observaciones (opcional)
    notes = db.Column(db.Text, nullable=True)
    
    # Relación con usuario que creó el formulario (si tienes users_db)
    username = db.Column(db.String(50), nullable=True)

    def __repr__(self):
        return f'<Formulario {self.nombre} - {self.status.value}>'

    def to_dict(self):
        """Convertir modelo a diccionario para respuestas JSON"""
        return {
            'id': self.id,
            'nombre': self.nombre,
            'direccion_fisica': self.direccion_fisica,
            'celular': self.celular,
            'status': self.status.value,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'notes': self.notes,
            'username': self.username
        }

    def update_status(self, new_status, notes=None):
        """Actualizar estado del formulario"""
        if isinstance(new_status, str):
            try:
                new_status = FormStatus(new_status)
            except ValueError:
                raise ValueError(f"Estado inválido. Debe ser uno de: {[s.value for s in FormStatus]}")
        
        self.status = new_status
        if notes:
            self.notes = notes
        db.session.commit()
