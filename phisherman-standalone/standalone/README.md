# Instalar dependencias
pip install -r requirements-standalone.txt

# Inicializar base de datos
python phisherman-feeds-standalone.py init

# Refresh manual de todos los feeds
python phisherman-feeds-standalone.py refresh

# Refresh de un feed específico
python phisherman-feeds-standalone.py refresh --feed phishtank

# Ver estadísticas
python phisherman-feeds-standalone.py stats

# Ejecutar en modo daemon (cada 15 minutos)
python phisherman-feeds-standalone.py daemon --interval 15

# Migrar datos a PostgreSQL cuando esté listo
python migrate_to_postgresql.py --sqlite feeds_data.db --postgres "postgresql+psycopg://user:pass@localhost/phisherman"
