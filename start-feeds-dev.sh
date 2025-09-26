#!/bin/bash

# Script para desarrollo del microservicio de feeds

echo "🔧 Iniciando microservicio de feeds en modo desarrollo..."

# Verificar que existe el archivo .env
if [ ! -f .env ]; then
    echo "⚠️  Archivo .env no encontrado. Creando uno básico..."
    cat > .env << EOF
# Database
DATABASE_URL=postgresql://phisherman:password@localhost:5432/phisherman

# Redis
REDIS_URL=redis://localhost:6379

# Environment
ENVIRONMENT=development

# API Keys (opcional para desarrollo)
FEEDS_GOOGLE_SAFEBROWSING_API_KEY=

# Feeds configuration
FEEDS_PORT=8001
EOF
    echo "✅ Archivo .env creado. Configura las variables necesarias."
fi

# Configurar PYTHONPATH
export PYTHONPATH="${PWD}:${PYTHONPATH}"

# Arrancar microservicio
echo "🚀 Iniciando feeds service en puerto 8001..."
cd phisherman-feeds
uvicorn main:app --host 0.0.0.0 --port 8001 --reload
