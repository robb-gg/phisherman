# 🚀 Phisherman - Quick Start Cheat Sheet

## 📋 **Requisitos Rápidos**
```bash
# Verificar que tienes todo instalado
poetry --version
docker --version
docker-compose --version
```

## ⚡ **Startup Rápido (3 comandos)**

### 1️⃣ Levantar Servicios Base
```bash
# Solo BD, Redis y Prometheus (básicos)
docker-compose up -d postgres redis prometheus
```

### 2️⃣ Ejecutar API Local
```bash
# API en puerto 8001 (evita conflictos)
poetry run uvicorn phisherman.api.main:app --host 0.0.0.0 --port 8001 --reload
```

### 3️⃣ Probar que Funciona
```bash
# Health check
curl http://localhost:8001/healthz

# Ver empresas víctimas
curl http://localhost:8001/api/v1/victims/
```

---

## 🔥 **Endpoints Principales**

### 📍 **Health & Status**
```bash
GET http://localhost:8001/healthz                    # Simple health
GET http://localhost:8001/health                     # Detailed health
```

### 📍 **Análisis de URLs**
```bash
# Analizar URL sospechosa con detección de víctimas
curl -X POST http://localhost:8001/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://payp4l-security.evil.com"}'

# Analizar otra URL de prueba
curl -X POST http://localhost:8001/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://app1e-verify.suspicious.com"}'
```

### 📍 **🆕 Sistema de Catalogación de Víctimas**
```bash
# Lista todas las empresas víctimas
curl http://localhost:8001/api/v1/victims/

# Estadísticas globales
curl http://localhost:8001/api/v1/victims/stats

# Detalles de empresa específica (usar ID real)
curl http://localhost:8001/api/v1/victims/{company-id}

# Campañas por empresa
curl http://localhost:8001/api/v1/victims/{company-id}/campaigns

# URLs maliciosas por empresa
curl http://localhost:8001/api/v1/victims/{company-id}/urls

# Tendencias por industria
curl http://localhost:8001/api/v1/victims/industry/banking/trends
curl http://localhost:8001/api/v1/victims/industry/technology/trends
curl http://localhost:8001/api/v1/victims/industry/ecommerce/trends
```

---

## 📊 **Datos de Prueba Cargados**

### 🏢 **Empresas Víctimas (7 total)**
- **PayPal** (Banking): 1,247 URLs, 12 campañas, Risk: 85.0
- **Apple** (Technology): 892 URLs, 8 campañas, Risk: 75.0
- **Microsoft** (Technology): 1,156 URLs, 15 campañas, Risk: 70.0
- **Amazon** (E-commerce): 2,341 URLs, 18 campañas, Risk: 80.0
- **Meta** (Social Media): 1,678 URLs, 22 campañas, Risk: 65.0
- **Coinbase** (Cryptocurrency): 567 URLs, 7 campañas, Risk: 90.0
- **Netflix** (Media): 234 URLs, 3 campañas, Risk: 45.0

### 🚨 **Campañas Activas (3 total)**
- PayPal Invoice Scam 2024 (156 URLs, 89 activas)
- iCloud Storage Phishing (78 URLs, 45 activas)
- Crypto Wallet Takeover (34 URLs, 28 activas)

---

## 🔧 **Comandos de Desarrollo**

### 🛠️ **Setup Inicial (si necesitas)**
```bash
# Instalar dependencias
poetry install

# Generar .env seguro
poetry run python scripts/generate-env.py

# Crear tablas BD
poetry run python -c "
import os
from dotenv import load_dotenv
load_dotenv()
from sqlalchemy import create_engine
from phisherman.datastore.database import Base
from phisherman.datastore import models, victim_models
url = os.getenv('DATABASE_URL', '').replace('+psycopg', '')
engine = create_engine(url)
Base.metadata.create_all(engine)
print('✅ Tablas creadas')
"

# Cargar datos de prueba
poetry run python scripts/seed_victim_data.py
```

### 📝 **Comandos Útiles**
```bash
# Ver logs de servicios
docker-compose logs -f postgres
docker-compose logs -f redis

# Restart servicios
docker-compose restart postgres redis

# Conectar a BD directamente
docker-compose exec postgres psql -U phisherman -d phisherman

# Ver métricas Prometheus
curl http://localhost:9090/metrics
```

---

## 🐛 **Troubleshooting Rápido**

### ❌ **"Port already in use"**
```bash
# Cambiar puertos en .env
API_PORT=8002
POSTGRES_PORT=5434
```

### ❌ **"Connection refused"**
```bash
# Verificar servicios
docker-compose ps
docker-compose up -d postgres redis
```

### ❌ **"Module not found"**
```bash
# Reinstalar dependencias
poetry install
```

---

## 🎯 **URLs de Testing Recomendadas**

```bash
# Phishing de PayPal
{"url": "https://payp4l-security.evil.com"}
{"url": "https://paypal-verify.suspicious.net"}

# Phishing de Apple
{"url": "https://app1e-verify.malicious.org"}
{"url": "https://icloud-storage.fake.com"}

# Phishing de Microsoft
{"url": "https://micr0soft-login.evil.net"}
{"url": "https://outlook-verify.suspicious.com"}

# URL legítima (para comparar)
{"url": "https://github.com/user/repo"}
```

---

## 🚀 **One-Liner Completo**
```bash
# Levantar todo de una vez (si no hay conflictos de puertos)
docker-compose up -d postgres redis prometheus && sleep 5 && poetry run uvicorn phisherman.api.main:app --host 0.0.0.0 --port 8001 --reload
```

**¡Listo! El sistema de catalogación de víctimas está funcionando!** 🎉
