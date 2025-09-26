# 🗄️ Diagrama de Base de Datos - DBML

## 📊 **Cómo usar el esquema visual**

### 1. **Abrir dbdiagram.io**
Ve a [https://dbdiagram.io/d](https://dbdiagram.io/d)

### 2. **Importar el esquema**
- Click en "Import" o "+"
- Selecciona "Import from DBML"
- Copia y pega el contenido de `phisherman-schema.dbml`
- O sube el archivo directamente

### 3. **Explorar el diagrama**
El diagrama mostrará automáticamente:
- ✅ **9 tablas principales** con todos sus campos
- ✅ **Relaciones visuales** (líneas conectoras)
- ✅ **Tipos de datos** y constraints
- ✅ **Índices importantes** documentados
- ✅ **Notas explicativas** en cada tabla

---

## 🔗 **Relaciones principales que verás**

```
victim_companies → phishing_campaigns (1:N)
victim_companies → victim_urls (1:N)
victim_companies → brand_patterns (1:N)

url_scans → victim_urls (1:N)

phishing_campaigns → victim_urls (1:N)
```

---

## 📈 **Beneficios del diagrama visual**

- **🎯 Comprensión rápida**: Ve todas las relaciones de un vistazo
- **📋 Documentación**: Notas explicativas en cada tabla/campo
- **🔍 Navegación**: Click en tablas para ver detalles
- **📤 Exportación**: Puedes exportar como PNG, PDF, etc.
- **👥 Colaboración**: Comparte el link del diagrama con el equipo

---

## 💡 **Colores sugeridos para organizar**

Una vez importado, puedes colorear las tablas por función:

- 🟦 **Azul**: Análisis principal (`url_scans`, `verdicts`)
- 🟧 **Naranja**: Threat Intelligence (`indicators`, `feed_entries`)
- 🟩 **Verde**: Clasificación víctimas (`victim_companies`, `victim_urls`)
- 🟪 **Morado**: Campañas (`phishing_campaigns`, `brand_patterns`)
- ⚪ **Gris**: Sistema (`alembic_version`)

---

## 🔄 **Mantener actualizado**

Cuando modifiques la base de datos:

1. Actualiza `phisherman-schema.dbml`
2. Re-importa en dbdiagram.io
3. El diagrama se actualizará automáticamente

---

## 📱 **Enlaces útiles**

- **Herramienta**: [dbdiagram.io](https://dbdiagram.io/d)
- **DBML Docs**: [DBML Language](https://www.dbml.org/docs/)
- **Sintaxis**: [DBML Reference](https://www.dbml.org/docs/reference)

---

*El archivo `phisherman-schema.dbml` contiene todo el esquema listo para importar* ✨
