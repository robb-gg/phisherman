# 🗄️ Esquema de Base de Datos - Phisherman

## 📊 **Resumen General**

- **PostgreSQL 16.10** (8.34 MB)
- **9 tablas principales** + 1 sistema (alembic)
- **3 conexiones activas**
- **17 registros totales** (mayormente en `verdicts`)

---

## 📋 **Tablas Principales**

### 🌐 **UrlScan** - `url_scans`
> **Tabla central** - Almacena todos los análisis de URLs realizados

**Campos clave:**
- `id` (UUID, PK)
- `url`, `normalized_url`, `domain`
- `is_malicious`, `risk_score`, `confidence`
- `labels` (JSON), `evidence` (JSON)
- `analyzer_results` (JSON) - Resultados de todos los analyzers
- `client_ip`, `user_agent`

**Relaciones:**
- → `VictimUrl` (1:N) - URLs clasificadas como impersonando empresas

---

### ⚠️ **Indicator** - `indicators`
> **Threat Intelligence** - Indicadores de amenazas de feeds externos

**Campos clave:**
- `indicator_type` (url, domain, ip, hash)
- `indicator_value` (la URL/dominio/IP)
- `threat_type` (phishing, malware, spam)
- `severity` (low, medium, high, critical)
- `source` (phishtank, openphish, urlhaus, safebrowsing)
- `metadata` (JSON) - Datos adicionales del feed

**Sin relaciones directas** - Se consulta por matching

---

### 📡 **FeedEntry** - `feed_entries`
> **Raw Data** - Entradas sin procesar de feeds externos

**Campos clave:**
- `feed_name`, `feed_url`
- `raw_data` (JSON) - Datos originales del feed
- `processed` (boolean), `checksum` (para deduplicación)

**Flujo:** `FeedEntry` → procesamiento → `Indicator`

---

### 🏢 **VictimCompany** - `victim_companies`
> **Empresas objetivo** - Compañías impersonadas por phishing

**Campos clave:**
- `name`, `normalized_name`, `brand_names[]`
- `industry` (enum: banking, ecommerce, etc.)
- `official_domains[]`, `official_tlds[]`
- `total_phishing_urls`, `active_campaigns`
- `brand_keywords[]`, `common_misspellings[]`

**Relaciones:**
- → `PhishingCampaign` (1:N)
- → `VictimUrl` (1:N)
- → `BrandPattern` (1:N)

---

### 🎯 **PhishingCampaign** - `phishing_campaigns`
> **Campañas organizadas** - Ataques coordinados contra empresas

**Campos clave:**
- `name`, `campaign_hash` (único)
- `victim_company_id` (FK) → `VictimCompany`
- `status` (active, monitoring, declining, inactive)
- `attack_vector`, `complexity_level`
- `total_urls`, `active_urls`, `domains_count`
- `infrastructure_fingerprint` (JSON)

**Relaciones:**
- ← `VictimCompany` (N:1)
- → `VictimUrl` (1:N)

---

### 🔗 **VictimUrl** - `victim_urls`
> **Junction Table** - Conecta URLs con empresas víctimas

**Campos clave:**
- `url_scan_id` (FK) → `UrlScan`
- `victim_company_id` (FK) → `VictimCompany`
- `campaign_id` (FK, optional) → `PhishingCampaign`
- `impersonation_type`, `similarity_score`
- `auto_classified`, `human_verified`

**Relaciones centrales:**
- ← `UrlScan` (N:1)
- ← `VictimCompany` (N:1)
- ← `PhishingCampaign` (N:1, opcional)

---

### 💾 **Verdict** - `verdicts`
> **Cache** - Resultados almacenados para evitar re-análisis

**Campos clave:**
- `url_hash` (único), `normalized_url`
- `is_malicious`, `risk_score`, `confidence`
- `expires_at`, `hit_count`

**Sin relaciones** - Cache independiente

---

### 🎨 **BrandPattern** - `brand_patterns`
> **Patrones de detección** - Reglas para clasificar automáticamente

**Campos clave:**
- `victim_company_id` (FK) → `VictimCompany`
- `pattern_type`, `pattern_value`, `pattern_regex`
- `confidence`, `false_positive_rate`
- `matches_count`, `true_positives`

---

## 🔄 **Flujo de Datos Principal**

```
1. 📱 REQUEST → API
2. 🌐 URL → UrlScan (análisis)
3. 📡 External Feeds → FeedEntry → Indicator
4. 🤖 URL + Patterns → VictimUrl (clasificación)
5. 📊 VictimUrl → PhishingCampaign (agrupación)
6. 💾 Resultado → Verdict (cache)
```

---

## 🔗 **Relaciones Críticas**

### **Clasificación de Víctimas:**
```sql
UrlScan → VictimUrl ← VictimCompany
                ↓
        PhishingCampaign
```

### **Threat Intelligence:**
```sql
FeedEntry → Indicator (sin FK, matching por valor)
```

### **Detección Automática:**
```sql
VictimCompany → BrandPattern → Auto-clasificación
```

---

## 📈 **Índices Importantes**

### **Performance crítico:**
- `url_scans.normalized_url` - Búsquedas rápidas
- `indicators.indicator_value` - Matching de amenazas
- `indicators.source` - Filtros por feed
- `victim_urls.url_scan_id` - Joins frecuentes

### **Análisis temporal:**
- `url_scans.created_at` - Tendencias
- `indicators.first_seen` - Nuevas amenazas
- `verdicts.expires_at` - Limpieza de cache

---

## 🛠️ **Scripts de Monitoreo**

### **Inspección completa:**
```bash
poetry run python inspect-database.py
```

### **Monitor diario:**
```bash
poetry run python db-monitor.py
```

### **Queries útiles:**
```sql
-- URLs más analizadas
SELECT normalized_url, COUNT(*) as scans
FROM url_scans
GROUP BY normalized_url
ORDER BY scans DESC LIMIT 10;

-- Top empresas objetivo
SELECT vc.name, COUNT(vu.id) as phishing_urls
FROM victim_companies vc
LEFT JOIN victim_urls vu ON vc.id = vu.victim_company_id
GROUP BY vc.name
ORDER BY phishing_urls DESC;

-- Indicadores por fuente
SELECT source, threat_type, COUNT(*)
FROM indicators
GROUP BY source, threat_type;

-- Cache hit rate
SELECT
    AVG(hit_count) as avg_hits,
    COUNT(*) as total_verdicts,
    COUNT(*) FILTER (WHERE hit_count > 1) as reused
FROM verdicts;
```

---

## 🔧 **Comandos de Mantenimiento**

### **Limpieza de cache expirado:**
```sql
DELETE FROM verdicts WHERE expires_at < NOW();
```

### **Estadísticas de tablas:**
```sql
SELECT
    schemaname,
    tablename,
    n_tup_ins as inserts,
    n_tup_upd as updates,
    n_tup_del as deletes
FROM pg_stat_user_tables;
```

### **Tamaño de tablas:**
```sql
SELECT
    tablename,
    pg_size_pretty(pg_total_relation_size(tablename)) as size
FROM pg_tables
WHERE schemaname = 'public';
```

---

## ⚡ **Optimizaciones Recomendadas**

1. **Particionado por fecha** para `url_scans` (cuando > 1M registros)
2. **Archivado automático** de `verdicts` expirados
3. **Índice compuesto** en `(victim_company_id, created_at)` para `victim_urls`
4. **Vacuum y analyze** regulares para mantener estadísticas actualizadas

---

*Actualizado: 2025-09-20*
