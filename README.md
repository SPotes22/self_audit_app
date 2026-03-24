Aquí tienes un README.md profesional y completo para tu proyecto, basado en toda la información de los documentos que hemos trabajado.

---

#  Sistema de Gestión de Formularios con Seguridad Integrada

[![CI/CD Pipeline](https://github.com/SPotes22/self_audit_app/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/SPotes22/self_audit_app/actions/workflows/security-pipeline.yml)
[![OWASP Top 10](https://img.shields.io/badge/OWASP%20Top%2010-Compliant-brightgreen)](https://owasp.org/Top10/)
[![Code Coverage](https://img.shields.io/badge/coverage-85%25-brightgreen)](https://github.com/SPotes22/self_audit_app)

##  Tabla de Contenidos

- [Descripción General](#descripción-general)
- [Características Principales](#características-principales)
- [Arquitectura](#arquitectura)
- [Requisitos Previos](#requisitos-previos)
- [Instalación y Configuración](#instalación-y-configuración)
- [Ejecución del Proyecto](#ejecución-del-proyecto)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [Seguridad](#seguridad)
- [Pruebas y Auditoría](#pruebas-y-auditoría)
- [Despliegue](#despliegue)
- [Documentación Adicional](#documentación-adicional)
- [Contribución](#contribución)
- [Licencia](#licencia)

---

##  Descripción General

Este proyecto implementa un sistema de gestión de formularios de compra con un enfoque integral en seguridad desde el diseño hasta la operación. La aplicación incorpora controles de seguridad en múltiples capas, incluyendo autenticación robusta, detección de amenazas en tiempo real, logging estructurado y un pipeline de CI/CD con gates de seguridad automatizados.

**Objetivos principales:**
- ✅ Implementar controles de seguridad basados en OWASP Top 10
- ✅ Automatizar la detección de vulnerabilidades en desarrollo y despliegue
- ✅ Establecer capacidades básicas de SOC (Security Operations Center)
- ✅ Proporcionar trazabilidad completa de eventos de seguridad

---

##  Características Principales

### 🔐 Autenticación y Control de Acceso
- **JWT personalizado con PBKDF2-HMAC-SHA256** (100,000 iteraciones) en lugar de librerías estándar
- **Protección anti-fuerza bruta** con bloqueo escalonado por IP/usuario
- **Creación segura de administradores** usando `hmac.compare_digest()` para prevenir timing attacks
- **Roles de usuario:** Anónimo, Operador, Administrador y Auditor

### 🛡️ Detección de Amenazas (Octomatrix)
- Análisis en tiempo real de inputs contra patrones OWASP Top 10
- Modelo híbrido: patrones estáticos + soporte para modelos de Machine Learning (`.pkl`)
- Bloqueo automático de inputs maliciosos (respuesta 403)
- Logging automático para análisis forense

### 📊 Máquina de Estados de Formularios
- Ciclo de vida definido: `DELAYED` → `REVISED` → `APPROVED` → `ARCHIVED`
- Transiciones controladas con validación de roles
- Auditoría implícita de cada cambio de estado

### 📝 Logging y Auditoría
- Logs estructurados en formato JSON
- Dashboard de auditoría en `/security/dashboard`
- Correlación de eventos para detección de patrones anómalos

### 🚀 CI/CD con Gates de Seguridad
- **Linting:** Ruff / Flake8
- **Análisis estático:** Bandit
- **Escaneo de dependencias:** Safety / pip-audit
- **Pruebas de seguridad:** Pytest con casos específicos
- **Cobertura mínima:** 80% para código crítico

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                      Capa Estática (Frontend)                │
│  /buy  │  /who  │  /security/dashboard  │  /octomatrix/test │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Gateway de Aplicación (Flask)               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Autenticación  │  Octomatrix  │  Máquina Estados  │    │
│  │  (JWT + bcrypt) │  (WAF App)   │  (FormStatus)    │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Capa de Persistencia                      │
│  ┌──────────────────┐          ┌──────────────────┐         │
│  │  SQLite (ORM)    │          │  En Memoria      │         │
│  │  • Formularios   │          │  • users_db      │         │
│  │  • Persistente   │          │  • login_attempts│         │
│  └──────────────────┘          └──────────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

**Decisiones de diseño clave:**
1. **JWT personalizado vs librerías estándar:** Control total sobre algoritmo y payload
2. **Almacenamiento híbrido:** SQLite para datos persistentes, memoria para datos volátiles
3. **Octomatrix integrado:** Seguridad en capa de aplicación antes de lógica de negocio

---

## 📋 Requisitos Previos

- **Python:** 3.9 o superior
- **Docker** (opcional, para despliegue)
- **Git** (para clonar el repositorio)
- **Make** (opcional, para usar comandos predefinidos)

---

## 🔧 Instalación y Configuración

### 1. Clonar el repositorio
```bash
git clone https://github.com/SPotes22/self_audit_app.git
cd self_audit_app
```

### 2. Crear y activar entorno virtual
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

### 3. Instalar dependencias
```bash
pip install -r requirements.txt
```

### 4. Configurar variables de entorno
Crea un archivo `.env` basado en `.env.example`:
```bash
cp .env.example .env
```

Edita el archivo con tus valores:
```env
FLASK_APP=app.py
FLASK_ENV=production
SECRET_KEY=tu-clave-secreta-segura-aqui
ADMIN_CREATION_SECRET=secreto-para-crear-admins
OCTOMATRIX_MODEL_PATH=models/octomatrix_model.pkl  # opcional
```

### 5. Inicializar base de datos
```bash
flask shell
>>> from app import db
>>> db.create_all()
>>> exit()
```

---

## 🚀 Ejecución del Proyecto

### Modo Desarrollo
```bash
make run
# o
flask run --debug
```

### Modo Producción (Gunicorn)
```bash
make prod
# o
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Docker
```bash
make docker-build
make docker-run
```

### Verificar que está funcionando
```bash
curl http://localhost:5000/health
# Respuesta esperada: {"status": "ok"}
```

---

## 📁 Estructura del Proyecto

```
.
├── app.py                      # Punto de entrada de la aplicación
├── requirements.txt            # Dependencias del proyecto
├── .env.example                # Ejemplo de variables de entorno
├── Makefile                    # Comandos útiles (run, test, lint)
├── Dockerfile                  # Configuración para contenedor
├── README.md                   # Este archivo
│
├── modules/                    # Módulos principales
│   ├── auth/                   # Autenticación y usuarios
│   │   ├── __init__.py
│   │   ├── models.py           # Modelo de usuario
│   │   ├── decorators.py       # Decoradores de roles
│   │   └── jwt_handler.py      # JWT personalizado con PBKDF2
│   │
│   ├── forms/                  # Gestión de formularios
│   │   ├── __init__.py
│   │   ├── models.py           # Modelo de formulario con Enum
│   │   └── routes.py           # Endpoints CRUD
│   │
│   ├── octomatrix/             # Detección de amenazas
│   │   ├── __init__.py
│   │   ├── detector.py         # Análisis de inputs
│   │   └── patterns.py         # Patrones OWASP
│   │
│   ├── audit/                  # Logging y auditoría
│   │   ├── __init__.py
│   │   ├── logger.py           # Logger estructurado
│   │   └── dashboard.py        # Endpoints de auditoría
│   │
│   └── admin/                  # Funciones administrativas
│       ├── __init__.py
│       └── routes.py           # Creación de admins, tests
│
├── tests/                      # Pruebas
│   ├── test_auth.py
│   ├── test_forms.py
│   ├── test_octomatrix.py
│   └── test_security.py
│
├── docs/                       # Documentación
│   ├── architecture.md         # Documento de arquitectura
│   ├── audit.md               # Plan de auditoría OWASP
│   ├── pipeline.md            # CI/CD y controles
│   └── soc.md                 # Modelo SOC
│
└── .github/
    └── workflows/
        └── security-pipeline.yml  # Pipeline CI/CD
```

---

## 🔒 Seguridad

### Controles Implementados

| Capa | Control | Herramienta/Método |
|------|---------|-------------------|
| **Código** | Linting, Análisis Estático | Ruff, Bandit |
| **Dependencias** | Escaneo de vulnerabilidades | Safety |
| **Autenticación** | Hashing de passwords | bcrypt (12 rounds) |
| **Tokens** | JWT personalizado | PBKDF2-HMAC-SHA256 (100k iteraciones) |
| **Anti-brute force** | Bloqueo por IP/usuario | Implementación propia |
| **Input Validation** | WAF a nivel de app | Octomatrix |
| **Logging** | Trazabilidad de eventos | JSON estructurado |
| **CI/CD** | Gates de seguridad | GitHub Actions |

### Riesgos Aceptados
1. **Pérdida de datos de usuarios en memoria:** Aceptado para desarrollo/demo. En producción se migrará a PostgreSQL.
2. **SQLite en producción:** Aceptado para cargas bajas. Migración futura a PostgreSQL.
3. **Rate limiting básico:** Aceptado para protección inicial. Complementar con Cloudflare en producción.

### Mejoras Futuras Planeadas
- [ ] Migrar `users_db` a base de datos persistente
- [ ] Implementar sistema de refresh tokens
- [ ] Entrenar modelo Octomatrix con datasets de ataques reales
- [ ] Añadir API versionada con OpenAPI/Swagger
- [ ] Implementar MFA (TOTP)
- [ ] Integración con SIEM (Splunk/ELK)

---

## 🧪 Pruebas y Auditoría

### Ejecutar pruebas localmente
```bash
# Todas las pruebas
make test

# Solo pruebas de seguridad
make test-security

# Con cobertura
make coverage
```

### Pre-commit checks
Antes de hacer push, ejecuta:
```bash
make pre-flight
```
Esto ejecuta: linting → análisis estático → escaneo de dependencias → pruebas

### Auditoría OWASP Top 10
Consulta el documento completo en `docs/audit.md`. Resumen:

| ID | Categoría | Estado |
|----|-----------|--------|
| A01 | Pérdida de Control de Acceso | ⚠️ Riesgo |
| A02 | Fallos Criptográficos | ✅ OK |
| A03 | Inyección | ✅ OK |
| A04 | Diseño Inseguro | ✅ OK |
| A05 | Mala Configuración | ⚠️ Riesgo |
| A06 | Componentes Vulnerables | ✅ OK |
| A07 | Fallos de Autenticación | ✅ OK |
| A08 | Integridad de Datos | ✅ OK |
| A09 | Fallos de Monitoreo | ✅ OK |
| A10 | SSRF | ✅ OK |

### Hallazgos Pendientes
1. **Dashboard de auditoría expuesto** (`/security/dashboard` sin autenticación) - Severidad ALTA
2. **Modo debug activado en staging** - Severidad MEDIA

---

## 🚢 Despliegue

### Render / DigitalOcean
```bash
# 1. Configurar variables de entorno en la plataforma
# 2. Conectar repositorio
# 3. Desplegar
```

### Empresarial (con alta disponibilidad)
```yaml
# docker-compose.yml (futuro)
version: '3.8'
services:
  app:
    image: tu-app:latest
    environment:
      - DATABASE_URL=postgresql://...
      - REDIS_URL=redis://...
    deploy:
      replicas: 3
  postgres:
    image: postgres:15
  redis:
    image: redis:7
```

---

## 📚 Documentación Adicional

- [Arquitectura del Sistema](docs/architecture.md) - Decisiones técnicas y vistas lógicas
- [Auditoría de Seguridad OWASP](docs/audit.md) - Checklist y hallazgos
- [Pipeline CI/CD y Controles](docs/pipeline.md) - Gates de seguridad automáticos
- [Modelo SOC](docs/soc.md) - Detección, respuesta y métricas

---

## 🤝 Contribución

1. **Fork** el repositorio
2. **Crea una rama** para tu feature: `git checkout -b feature/nueva-funcionalidad`
3. **Ejecuta los checks locales:** `make pre-flight`
4. **Commit** tus cambios: `git commit -m 'feat: añadir nueva funcionalidad'`
5. **Push** a la rama: `git push origin feature/nueva-funcionalidad`
6. **Abre un Pull Request**

**Reglas importantes:**
- ✅ No saltarse los gates de seguridad
- ✅ Mantener cobertura de código >80% para código crítico
- ✅ Documentar excepciones de seguridad aceptadas
- ✅ Seguir las convenciones de commit (Conventional Commits)

---

## 📄 Licencia

Este proyecto está bajo la licencia MIT. Ver el archivo [LICENSE](LICENSE) para más detalles.

---

## 📧 Contacto y Soporte

- **Issues:** [GitHub Issues](https://github.com/SPotes22/self_audit_app/issues)
- **Seguridad:** reportar vulnerabilidades a `security@tu-dominio.com`
- **Documentación:** [Wiki del proyecto](https://github.com/SPotes22/self_audit_app/wiki)

---

## 🙏 Agradecimientos

- OWASP Foundation por sus guías y estándares
- Equipo de desarrollo por el enfoque en seguridad desde el diseño
- Comunidad open source por las herramientas utilizadas

---

**🔐 Seguridad ante todo. Código seguro, despliegues seguros, operaciones seguras.**
