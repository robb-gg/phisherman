#!/bin/bash

# Script para iniciar backend y frontend en modo desarrollo

echo "🐟 Iniciando Phisherman en modo desarrollo..."

# Función para limpiar procesos al salir
cleanup() {
    echo "Deteniendo servicios..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
    exit
}

trap cleanup SIGINT SIGTERM

# Verificar que existe el directorio del backend
if [ ! -d "phisherman" ]; then
    echo "❌ No se encuentra el directorio del backend 'phisherman'"
    exit 1
fi

# Verificar que existe el directorio del frontend
if [ ! -d "phisherman-frontend" ]; then
    echo "❌ No se encuentra el directorio del frontend 'phisherman-frontend'"
    exit 1
fi

# Iniciar backend FastAPI
echo "🚀 Iniciando backend en localhost:8000..."
poetry run uvicorn phisherman.api.main:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

# Esperar un poco para que el backend se inicie
sleep 3

# Iniciar frontend Next.js
echo "🌐 Iniciando frontend en localhost:3000..."
cd phisherman-frontend
npm run dev &
FRONTEND_PID=$!
cd ..

echo "✅ Servicios iniciados:"
echo "   Backend:  http://localhost:8000"
echo "   Frontend: http://localhost:3000"
echo "   API Docs: http://localhost:8000/docs"
echo ""
echo "Presiona Ctrl+C para detener ambos servicios"

# Esperar a que se detengan los procesos
wait
