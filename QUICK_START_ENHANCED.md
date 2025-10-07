# 🚀 Quick Start - Enhanced Analyzers

## ✅ Migración Completada

Los componentes clave de **Antifraude** han sido migrados exitosamente a **Phisherman**:

- ✅ **EnhancedSaaSDetector** - Detección inteligente de SaaS con datos de PhishTank
- ✅ **WebContentAnalyzer** - Análisis profundo de contenido, SSL y headers
- ✅ **35+ Tests** - Suite completa de validación
- ✅ **Documentación** - Guía de migración completa

---

## 🧪 Probar Rápidamente

### Opción 1: Script de Prueba Rápido (Recomendado)

```bash
cd /Users/vreyes/SideProyect/phisherman

# Ejecutar suite completa de URLs de prueba
poetry run python test_quick_urls.py

# Probar URL específica
poetry run python test_quick_urls.py "https://suspicious-site.weebly.com"
```

**Salida esperada:**
```
🎣 PHISHERMAN - Enhanced Analyzer Test Suite
================================================================================

🚀 Initializing analysis engine...
✅ Loaded 9 analyzers
✅ Enhanced SaaS Detector loaded
✅ Web Content Analyzer loaded

📊 Testing: SUSPICIOUS - Paypal on Weebly
🔗 URL: https://paypal-verify.weebly.com
--------------------------------------------------------------------------------

🔍 Analyzer Results (9 analyzers):

  ⭐ saas_detector_enhanced:
     • Risk Score: 25.2/100
     • Confidence: 0.90
     • Labels: saas_hosting, provider_weebly, type_website_builder
     • Provider: Weebly
     • Service Type: website_builder
     • Risk Modifier: 1.2
     • Abuse Freq: 3432

  ⭐ web_content_analyzer:
     • Risk Score: 45.0/100
     • Confidence: 0.90
     • Labels: suspicious_keywords, brand_impersonation_keywords, has_forms

📈 Final Scoring:
   • Score: 68.50/100
   • Confidence: 0.87
   • Risk Level: MEDIUM
   • ⚠️  CAUTION: Medium risk - Verify carefully
```

---

### Opción 2: Tests de Pytest

```bash
# Ejecutar suite completa de tests
poetry run pytest tests/test_enhanced_analyzers.py -v

# Ejecutar solo tests del SaaSDetector
poetry run pytest tests/test_enhanced_analyzers.py::TestEnhancedSaaSDetector -v

# Ejecutar solo tests de integración
poetry run pytest tests/test_enhanced_analyzers.py::TestIntegration -v

# Con cobertura
poetry run pytest tests/test_enhanced_analyzers.py --cov=phisherman.analyzers --cov-report=html
```

---

### Opción 3: Python Interactivo

```python
import asyncio
from phisherman.analyzers.engine import AnalysisEngine
from phisherman.scorer.linear_scorer import LinearScorer

async def test_url(url):
    engine = AnalysisEngine()
    scorer = LinearScorer()

    # Analizar
    results = await engine.analyze(url)
    scoring = scorer.calculate_score(results)

    # Mostrar resultados
    print(f"\nURL: {url}")
    print(f"Risk Score: {scoring.final_score:.2f}/100")
    print(f"Risk Level: {scoring.details['risk_level']}")

    # Ver analyzer específico
    for r in results:
        if r.analyzer_name == 'saas_detector_enhanced':
            print(f"\nSaaS Detection:")
            print(f"  Is SaaS: {r.evidence.get('is_saas')}")
            print(f"  Provider: {r.evidence.get('provider')}")
            print(f"  Risk: {r.risk_score:.1f}")

# Ejecutar
asyncio.run(test_url("https://suspicious.firebaseapp.com"))
```

---

## 📊 URLs de Prueba Incluidas

El script `test_quick_urls.py` incluye URLs de prueba organizadas por riesgo:

### ✅ Sitios Legítimos (Bajo Riesgo)
- `https://www.google.com`
- `https://github.com`
- `https://www.amazon.com`

### 🟡 SaaS Plataformas (Riesgo Variable)
- `https://test.firebaseapp.com` - Firebase (neutral risk)
- `https://example.pages.dev` - Cloudflare Pages
- `https://suspicious.weebly.com` - Weebly (high abuse)

### 🔴 Servicios de Alto Riesgo
- `https://bit.ly` - URL shortener (muy alto riesgo)
- `https://qrco.de` - QR generator (alto riesgo)

### ⚠️ Patrones Sospechosos
- `https://paypal-verify.weebly.com` - Brand impersonation
- `https://amazon-login.firebaseapp.com` - Brand on SaaS
- `https://apple-id-verify.web.app` - Credential theft pattern

---

## 🔍 Qué Esperar

### Detección de SaaS Mejorada

**Antes (Phisherman original):**
```python
# Detectaba ~10 plataformas básicas
# Risk scoring genérico
```

**Ahora (Con Antifraude):**
```python
# Detecta 63 plataformas SaaS
# Risk modifiers inteligentes basados en datos reales
# Detección de subdomain abuse
# Análisis de frecuencia de abuso de PhishTank

Ejemplo:
"firebaseapp.com" → Risk modifier: 0.8 (alto uso legítimo)
"weebly.com" → Risk modifier: 1.2 (alto ratio de abuso)
"bit.ly" → Risk modifier: 1.5 (oculta destino - muy alto riesgo)
```

### Análisis de Contenido Web

**Nuevo:** Detección profunda de:
- ✅ 18 keywords de phishing ("verify your account", "suspended account", etc.)
- ✅ 24 marcas populares para detectar impersonación
- ✅ Formularios con campos de password (credential theft)
- ✅ Certificados SSL (auto-firmados, issuers sospechosos)
- ✅ Security headers (HSTS, CSP, X-Frame-Options)
- ✅ Cadenas de redirects (técnica de evasión)

---

## 📈 Resultados Esperados

### Ejemplo: Firebase Legítimo

```
URL: https://my-app.firebaseapp.com
Risk Score: 18.50/100
Risk Level: low
✅ Appears legitimate (low risk SaaS hosting)
```

### Ejemplo: Phishing en Weebly

```
URL: https://paypal-secure-login.weebly.com
Risk Score: 72.30/100
Risk Level: high
⚠️  WARNING: HIGH RISK
  - SaaS with high abuse frequency
  - Brand impersonation keywords detected
  - Subdomain abuse pattern
  - Password input fields detected
```

### Ejemplo: URL Shortener

```
URL: https://bit.ly/suspicious123
Risk Score: 85.40/100
Risk Level: high
⚠️  WARNING: VERY HIGH RISK
  - URL shortener hides destination
  - Cannot verify final URL
  - High abuse service type
```

---

## 🐛 Troubleshooting

### Problema: "Module not found"

```bash
# Asegúrate de estar en el directorio correcto
cd /Users/vreyes/SideProyect/phisherman

# Reinstalar dependencias
poetry install

# Verificar que los módulos existen
ls phisherman/analyzers/saas_detector_enhanced.py
ls phisherman/analyzers/web_content_analyzer.py
```

### Problema: Tests fallan por timeout

```bash
# Algunos tests hacen requests HTTP reales
# Si hay problemas de red, es normal que algunos fallen
# Los tests de unidad (SaaS detection) NO deberían fallar

# Ejecutar solo tests que no requieren red
poetry run pytest tests/test_enhanced_analyzers.py::TestSaaSDetectionLogic -v
```

### Problema: "No linter errors" pero no funciona

```bash
# Verificar imports
poetry run python -c "from phisherman.analyzers.saas_detector_enhanced import EnhancedSaaSDetector; print('OK')"

# Verificar engine
poetry run python -c "from phisherman.analyzers.engine import AnalysisEngine; e = AnalysisEngine(); print([a.name for a in e.analyzers])"
```

---

## 📚 Documentación Completa

- **Guía de Migración:** `MIGRATION_FROM_ANTIFRAUDE.md`
- **Tests:** `tests/test_enhanced_analyzers.py`
- **README Principal:** `README.md`

---

## ✅ Checklist de Validación

Ejecuta estos comandos para validar que todo funciona:

```bash
# 1. Verificar que los analyzers se cargan
poetry run python -c "
from phisherman.analyzers.engine import AnalysisEngine
e = AnalysisEngine()
names = [a.name for a in e.analyzers]
assert 'saas_detector_enhanced' in names
assert 'web_content_analyzer' in names
print('✅ Analyzers loaded correctly')
"

# 2. Ejecutar tests básicos
poetry run pytest tests/test_enhanced_analyzers.py::TestSaaSDetectionLogic -v

# 3. Probar análisis real
poetry run python test_quick_urls.py "https://github.io"

# 4. Ver cobertura
poetry run pytest tests/test_enhanced_analyzers.py --cov=phisherman.analyzers
```

Si todos pasan: **🎉 ¡Migración exitosa!**

---

## 🎯 Próximos Pasos

1. **Ajustar pesos** en `configs/weights.yaml` según tus necesidades
2. **Añadir más URLs** de prueba en `test_quick_urls.py`
3. **Integrar con base de datos** para persistir análisis
4. **Conectar con VictimAnalyzer** para catalogación automática
5. **Crear dashboard** para visualizar resultados

---

**¿Necesitas ayuda?** Revisa `MIGRATION_FROM_ANTIFRAUDE.md` para detalles técnicos completos.
