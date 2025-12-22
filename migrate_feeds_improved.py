#!/usr/bin/env python3
"""
Migración mejorada de SQLite a PostgreSQL con verificación y estadísticas.
"""

import asyncio
import json
import sqlite3
import sys
from datetime import datetime
from uuid import UUID

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from phisherman.datastore.database import Base
from phisherman.datastore.models import FeedEntry, Indicator


async def verify_and_migrate(sqlite_path: str, postgres_url: str):
    """Migrar y verificar datos de SQLite a PostgreSQL."""
    
    print("=" * 80)
    print("🔄 MIGRACIÓN SQLite → PostgreSQL")
    print("=" * 80)
    
    # Conectar a SQLite
    print(f"\n📂 Conectando a SQLite: {sqlite_path}")
    sqlite_conn = sqlite3.connect(sqlite_path)
    sqlite_conn.row_factory = sqlite3.Row
    
    # Contar registros en SQLite
    cursor = sqlite_conn.execute("SELECT COUNT(*) FROM feed_entries")
    sqlite_feed_count = cursor.fetchone()[0]
    
    cursor = sqlite_conn.execute("SELECT COUNT(*) FROM indicators")
    sqlite_indicator_count = cursor.fetchone()[0]
    
    print(f"  ✓ Feed entries en SQLite: {sqlite_feed_count}")
    print(f"  ✓ Indicators en SQLite:   {sqlite_indicator_count}")
    
    # Conectar a PostgreSQL
    print(f"\n🐘 Conectando a PostgreSQL...")
    engine = create_async_engine(postgres_url, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    # Crear tablas si no existen
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Contar registros actuales en PostgreSQL
    async with async_session() as session:
        result = await session.execute(select(func.count(FeedEntry.id)))
        pg_feed_count = result.scalar()
        
        result = await session.execute(select(func.count(Indicator.id)))
        pg_indicator_count = result.scalar()
    
    print(f"  ✓ Feed entries en PostgreSQL (antes): {pg_feed_count}")
    print(f"  ✓ Indicators en PostgreSQL (antes):   {pg_indicator_count}")
    
    # Migrar FeedEntries
    print(f"\n📦 Migrando Feed Entries...")
    cursor = sqlite_conn.execute("SELECT * FROM feed_entries")
    
    migrated_feeds = 0
    skipped_feeds = 0
    
    async with async_session() as session:
        for row in cursor:
            row_dict = dict(row)
            
            # Verificar si ya existe
            stmt = select(FeedEntry).where(FeedEntry.checksum == row_dict["checksum"])
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()
            
            if existing:
                skipped_feeds += 1
                continue
            
            # Crear nuevo FeedEntry
            try:
                feed_entry = FeedEntry(
                    id=UUID(row_dict["id"]),
                    feed_name=row_dict["feed_name"],
                    feed_url=row_dict["feed_url"],
                    raw_data=json.loads(row_dict["raw_data"]) if row_dict["raw_data"] else {},
                    parsed_data=json.loads(row_dict["parsed_data"]) if row_dict["parsed_data"] else {},
                    processed=bool(row_dict["processed"]),
                    processing_error=row_dict["processing_error"],
                    external_id=row_dict["external_id"],
                    checksum=row_dict["checksum"],
                    feed_timestamp=datetime.fromisoformat(row_dict["feed_timestamp"]) if row_dict["feed_timestamp"] else None,
                    created_at=datetime.fromisoformat(row_dict["created_at"]),
                    updated_at=datetime.fromisoformat(row_dict["updated_at"]),
                )
                
                session.add(feed_entry)
                migrated_feeds += 1
                
                if migrated_feeds % 1000 == 0:
                    print(f"  ⏳ Migrados {migrated_feeds} feed entries...")
                    await session.commit()
                    
            except Exception as e:
                print(f"  ❌ Error en feed entry {row_dict.get('id')}: {e}")
                continue
        
        await session.commit()
    
    print(f"  ✓ Migrados: {migrated_feeds}")
    print(f"  ⊘ Duplicados omitidos: {skipped_feeds}")
    
    # Migrar Indicators
    print(f"\n🎯 Migrando Indicators...")
    cursor = sqlite_conn.execute("SELECT * FROM indicators")
    
    migrated_indicators = 0
    skipped_indicators = 0
    error_indicators = 0
    too_long_indicators = 0
    
    async with async_session() as session:
        for row in cursor:
            row_dict = dict(row)
            
            # Verificar longitud de la URL (max 2083 caracteres)
            indicator_value = row_dict["indicator_value"]
            if len(indicator_value) > 2083:
                too_long_indicators += 1
                if too_long_indicators <= 5:  # Solo mostrar los primeros 5
                    print(f"  ⚠️  URL demasiado larga ({len(indicator_value)} chars), omitiendo...")
                continue
            
            # Verificar si ya existe
            stmt = select(Indicator).where(
                (Indicator.indicator_value == indicator_value) &
                (Indicator.source == row_dict["source"])
            )
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()
            
            if existing:
                skipped_indicators += 1
                continue
            
            # Crear nuevo Indicator
            try:
                indicator = Indicator(
                    id=UUID(row_dict["id"]),
                    indicator_type=row_dict["indicator_type"],
                    indicator_value=indicator_value,
                    threat_type=row_dict["threat_type"],
                    severity=row_dict["severity"],
                    confidence=float(row_dict["confidence"]),
                    source=row_dict["source"],
                    source_url=row_dict["source_url"],
                    tags=json.loads(row_dict["tags"]) if row_dict["tags"] else [],
                    extra_data=json.loads(row_dict["metadata"]) if row_dict["metadata"] else {},
                    first_seen=datetime.fromisoformat(row_dict["first_seen"]),
                    last_seen=datetime.fromisoformat(row_dict["last_seen"]),
                    expires_at=datetime.fromisoformat(row_dict["expires_at"]) if row_dict["expires_at"] else None,
                    is_active=bool(row_dict["is_active"]),
                    created_at=datetime.fromisoformat(row_dict["created_at"]),
                    updated_at=datetime.fromisoformat(row_dict["updated_at"]),
                )
                
                session.add(indicator)
                migrated_indicators += 1
                
                if migrated_indicators % 1000 == 0:
                    print(f"  ⏳ Migrados {migrated_indicators} indicators...")
                    await session.commit()
                    
            except Exception as e:
                error_indicators += 1
                if error_indicators <= 5:  # Solo mostrar los primeros 5 errores
                    print(f"  ❌ Error en indicator {row_dict.get('id')}: {e}")
                continue
        
        await session.commit()
    
    print(f"  ✓ Migrados: {migrated_indicators}")
    print(f"  ⊘ Duplicados omitidos: {skipped_indicators}")
    if too_long_indicators > 0:
        print(f"  ⚠️  URLs demasiado largas (>2083 chars): {too_long_indicators}")
    if error_indicators > 0:
        print(f"  ❌ Errores: {error_indicators}")
    
    # Verificación final
    print(f"\n✅ Verificando migración...")
    async with async_session() as session:
        result = await session.execute(select(func.count(FeedEntry.id)))
        final_feed_count = result.scalar()
        
        result = await session.execute(select(func.count(Indicator.id)))
        final_indicator_count = result.scalar()
    
    print(f"  📊 Feed entries finales:  {final_feed_count} (antes: {pg_feed_count})")
    print(f"  📊 Indicators finales:    {final_indicator_count} (antes: {pg_indicator_count})")
    
    # Resumen por fuente
    print(f"\n📈 Resumen por fuente:")
    async with async_session() as session:
        result = await session.execute(
            select(Indicator.source, func.count(Indicator.id))
            .group_by(Indicator.source)
        )
        sources = result.all()
        
        for source, count in sources:
            print(f"  • {source}: {count} indicators")
    
    print("\n" + "=" * 80)
    print("✨ Migración completada!")
    print("=" * 80)
    
    sqlite_conn.close()
    await engine.dispose()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Migración mejorada SQLite → PostgreSQL")
    parser.add_argument(
        "--sqlite",
        default="phisherman-standalone/ feeds_data.db",
        help="Ruta a la base de datos SQLite"
    )
    parser.add_argument(
        "--postgres",
        default="postgresql+psycopg://phisherman:password@localhost:5432/phisherman",
        help="URL de conexión a PostgreSQL"
    )
    
    args = parser.parse_args()
    
    try:
        asyncio.run(verify_and_migrate(args.sqlite, args.postgres))
    except KeyboardInterrupt:
        print("\n\n⚠️  Migración interrumpida por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error fatal: {e}")
        sys.exit(1)
