# Phisherman Frontend

Frontend web para el sistema de análisis de URLs Phisherman, construido con Next.js 14, TypeScript y Tailwind CSS.

## 🚀 Características

- **Interfaz Google-style**: Input centrado con transición suave
- **Análisis en tiempo real**: Integración directa con la API FastAPI
- **Resultados detallados**: Vista completa de todos los analizadores
- **Responsive**: Diseño optimizado para móviles y desktop
- **TypeScript**: Tipado fuerte para mejor desarrollo

## 🛠️ Stack Tecnológico

- **Next.js 14** - Framework React con App Router
- **TypeScript** - Tipado estático
- **Tailwind CSS** - Estilos utility-first
- **React Hooks** - Estado local y efectos

## 🏃‍♂️ Cómo usar

### 1. Instalar dependencias
```bash
npm install
```

### 2. Iniciar el servidor backend
Asegúrate de que la API FastAPI esté corriendo en `http://localhost:8000`

### 3. Iniciar el frontend
```bash
npm run dev
```

La aplicación estará disponible en `http://localhost:3000`

## 🔧 Configuración

El frontend está configurado para hacer proxy de las requests de `/api/v1/*` hacia `http://localhost:8000/api/v1/*` usando Next.js rewrites.

## 📁 Estructura

```
src/
├── app/                 # App Router de Next.js
├── components/          # Componentes React
│   ├── SearchForm.tsx   # Formulario de búsqueda
│   └── SearchResults.tsx # Resultados del análisis
├── hooks/              # Custom hooks
│   └── useAnalyze.ts   # Hook para la API
└── types/              # Tipos TypeScript
    └── api.ts          # Tipos de la API
```

## 🎯 Funcionalidades

- Input de URL con validación en tiempo real
- Botón de análisis con estado de carga
- Resultados con código de colores por peligrosidad
- Vista expandible de evidencia por analizador
- Métricas de tiempo y confianza
- Ejemplos de URLs para pruebas rápidas
