# Microservicio de Feeds - Phisherman

Este microservicio interno se encarga de la gestión centralizada de feeds de threat intelligence, incluyendo integración con PhishTank, OpenPhish, URLhaus y Google Safe Browsing.

## 🏗️ Arquitectura

```
┌─────────────────┐    HTTP    ┌──────────────────┐    Database    ┌──────────────┐
│   API Principal │ ◄────────► │ Microservicio    │ ◄────────────► │  PostgreSQL  │
│   (Puerto 8000) │            │    de Feeds      │                │   Compartida │
└─────────────────┘            │  (Puerto 8001)   │                └──────────────┘
                               └──────────────────┘
                                        │
                                        ▼
                               ┌─────────────────┐
                               │   External APIs  │
                               │ • PhishTank     │
                               │ • OpenPhish     │
                               │ • URLhaus       │
                               │ • Safe Browsing │
                               └─────────────────┘
```

## 🚀 Inicio Rápido

### Con Docker Compose (Recomendado)

```bash
# Iniciar todos los servicios incluyendo feeds
docker-compose up -d

# Ver logs del microservicio de feeds
docker-compose logs -f feeds
```

### Desarrollo Local

```bash
# Script de desarrollo rápido
./start-feeds-dev.sh

# O manualmente:
cd phisherman-feeds
uvicorn main:app --host 0.0.0.0 --port 8001 --reload
```

## 📡 Endpoints

### Consultas de URLs (Uso interno)

```bash
# Consultar una URL específica
POST http://localhost:8001/feeds/v1/lookup
{
    "url": "http://example.com",
    "normalize": true
}

# Consulta masiva (hasta 100 URLs)
POST http://localhost:8001/feeds/v1/bulk-lookup
{
    "urls": ["http://example1.com", "http://example2.com"],
    "normalize": true
}

# Estadísticas de feeds
GET http://localhost:8001/feeds/v1/stats
```

### Gestión de Feeds

```bash
# Estado de todos los feeds
GET http://localhost:8001/feeds/v1/status

# Refresh manual de un feed específico
POST http://localhost:8001/feeds/v1/refresh/phishtank
POST http://localhost:8001/feeds/v1/refresh/openphish
POST http://localhost:8001/feeds/v1/refresh/urlhaus
POST http://localhost:8001/feeds/v1/refresh/safebrowsing

# Refresh de todos los feeds
POST http://localhost:8001/feeds/v1/refresh-all

# Fuentes disponibles
GET http://localhost:8001/feeds/v1/sources
```

### Health Check

```bash
# Health check básico
GET http://localhost:8001/health

# Health check detallado
GET http://localhost:8001/feeds/v1/health
```

## 🔧 Configuración

### Variables de Entorno

```bash
# Configuración básica
FEEDS_ENVIRONMENT=development
FEEDS_DEBUG=true
FEEDS_PORT=8001

# Base de datos (compartida con API principal)
DATABASE_URL=postgresql://user:pass@localhost:5432/phisherman

# Redis (compartido)
REDIS_URL=redis://localhost:6379

# API Keys externas
FEEDS_GOOGLE_SAFEBROWSING_API_KEY=tu_api_key_aqui

# Intervalos de refresh (en minutos)
FEEDS_PHISHTANK_REFRESH_INTERVAL=15
FEEDS_OPENPHISH_REFRESH_INTERVAL=15
FEEDS_URLHAUS_REFRESH_INTERVAL=30
FEEDS_SAFEBROWSING_REFRESH_INTERVAL=60

# Hosts internos permitidos
FEEDS_ALLOWED_INTERNAL_HOSTS=["api", "localhost", "127.0.0.1"]
```

## 🔐 Seguridad

### Acceso Solo Red Interna

El microservicio está diseñado para ser accesible **únicamente** desde la red interna:

- **Desarrollo**: Verifica hosts permitidos en `FEEDS_ALLOWED_INTERNAL_HOSTS`
- **Producción**: Requiere token interno en header `X-Internal-Service-Token`
- **Docker**: Usa network bridge `internal` para aislamiento

### Headers de Autenticación

```bash
# En producción, incluir token interno:
curl -H "X-Internal-Service-Token: tu-secret-key" \
     http://feeds:8001/feeds/v1/lookup
```

## 📊 Fuentes de Datos

| Fuente | Tipo | Intervalo | Confianza | Descripción |
|--------|------|-----------|-----------|-------------|
| **PhishTank** | Phishing | 15 min | 90% | URLs de phishing verificadas por comunidad |
| **OpenPhish** | Phishing | 15 min | 85% | Detección automatizada de phishing |
| **URLhaus** | Malware | 30 min | 90% | URLs que distribuyen malware |
| **Safe Browsing** | Mixto | 60 min | 95% | API de Google para amenazas web |

## 🔗 Integración con API Principal

### FeedsAnalyzer

El analyzer `feeds` se integra automáticamente en el motor de análisis:

```python
# En phisherman/analyzers/engine.py
self.enabled_analyzers = [
    "feeds",  # 🆕 Nueva integración
    "dns_resolver",
    "rdap_whois",
    # ... otros analyzers
]
```

### Cliente HTTP Interno

```python
from phisherman.services.feeds_client import feeds_client

# Consultar URL
result = await feeds_client.lookup_url("http://example.com")
print(result["is_threat"])  # True/False

# Verificar estado
status = await feeds_client.get_feeds_status()
print(status["total_active_feeds"])
```

## 🐳 Docker

### Dockerfile del Microservicio

```dockerfile
FROM python:3.11-slim
# Comparte dependencias con API principal
COPY pyproject.toml poetry.lock ./
RUN poetry install --no-dev
COPY phisherman-feeds/ ./phisherman-feeds/
COPY phisherman/ ./phisherman/  # Base compartida
EXPOSE 8001
CMD ["uvicorn", "phisherman-feeds.main:app", "--host", "0.0.0.0", "--port", "8001"]
```

### Configuración en docker-compose.yml

```yaml
feeds:
  build:
    context: .
    dockerfile: phisherman-feeds/Dockerfile
  ports:
    - "8001:8001"
  depends_on:
    - postgres
    - redis
  networks:
    - internal  # Red interna
  environment:
    - DATABASE_URL=postgresql://user:pass@postgres:5432/db
    - FEEDS_GOOGLE_SAFEBROWSING_API_KEY=${GOOGLE_SAFEBROWSING_API_KEY}
```

## 🧪 Testing

```bash
# Test de conectividad básica
curl http://localhost:8001/health

# Test de lookup (requiere URL interna)
curl -X POST http://localhost:8001/feeds/v1/lookup \
     -H "Content-Type: application/json" \
     -H "Host: localhost" \
     -d '{"url": "http://phishing-example.com"}'

# Test desde API principal
curl http://localhost:8000/api/v1/admin/feeds/health
```

## 📈 Monitoreo

### Métricas Disponibles

- **Health checks**: `/health` y `/feeds/v1/health`
- **Estadísticas**: `/feeds/v1/stats`
- **Estado de feeds**: `/feeds/v1/status`
- **Headers de timing**: `X-Process-Time`

### Logs

```bash
# Ver logs en desarrollo
docker-compose logs -f feeds

# Filtrar por nivel
docker-compose logs feeds | grep ERROR
```

## 🚨 Troubleshooting

### Problemas Comunes

1. **"Access denied - internal services only"**
   ```bash
   # Verificar host header o configurar token interno
   curl -H "Host: localhost" http://localhost:8001/feeds/v1/health
   ```

2. **"Feeds service unavailable"**
   ```bash
   # Verificar que el servicio esté corriendo
   docker-compose ps feeds
   curl http://localhost:8001/health
   ```

3. **Imports fallidos**
   ```bash
   # Verificar PYTHONPATH
   export PYTHONPATH="${PWD}:${PYTHONPATH}"
   cd phisherman-feeds && python -c "import phisherman.datastore.models"
   ```

### Base de datos

```bash
# Verificar conectividad a PostgreSQL
docker-compose exec feeds python -c "
from phisherman.datastore.database import AsyncSessionLocal
import asyncio
async def test():
    async with AsyncSessionLocal() as db:
        result = await db.execute('SELECT 1')
        print('DB OK:', result.scalar())
asyncio.run(test())
"
```

## 🔄 Refresh de Datos

### Automático (Celery)

Los feeds se actualizan automáticamente según los intervalos configurados usando las tareas Celery existentes.

### Manual

```bash
# Desde API principal
curl -X POST http://localhost:8000/api/v1/admin/feeds/refresh/phishtank

# Directamente al microservicio (red interna)
curl -X POST http://feeds:8001/feeds/v1/refresh/phishtank
```

---

## 💡 Siguientes Pasos

1. **API Keys**: Configura `GOOGLE_SAFEBROWSING_API_KEY` para funcionalidad completa
2. **Monitoreo**: Integra con Prometheus/Grafana usando métricas de FastAPI
3. **Caching**: Considera Redis para cache de lookups frecuentes
4. **Rate Limiting**: Implementa límites por IP/servicio
5. **Autoscaling**: Configura réplicas en producción
