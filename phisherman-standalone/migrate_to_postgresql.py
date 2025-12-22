#!/usr/bin/env python3
"""
Script para migrar datos del SQLite standalone al PostgreSQL del proyecto principal
"""

import asyncio
import json
import os
import sqlite3

# Importar modelos del proyecto principal
import sys
import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

sys.path.append(os.path.join(os.path.dirname(__file__), "../"))

from phisherman.datastore.database import Base  # noqa: E402
from phisherman.datastore.models import FeedEntry, Indicator  # noqa: E402


async def migrate_data(sqlite_path: str, postgres_url: str):
    """Migrar datos de SQLite a PostgreSQL."""

    # Conectar a PostgreSQL
    engine = create_async_engine(postgres_url)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Crear tablas si no existen
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Conectar a SQLite
    sqlite_conn = sqlite3.connect(sqlite_path)
    sqlite_conn.row_factory = sqlite3.Row

    try:
        # Migrar feed_entries
        print("Migrating feed entries...")
        cursor = sqlite_conn.execute("SELECT * FROM feed_entries")

        async with async_session() as session:
            for row in cursor:
                # Convertir row a dict
                row_dict = dict(row)

                # Verificar si ya existe
                stmt = select(FeedEntry).where(
                    FeedEntry.checksum == row_dict["checksum"]
                )
                result = await session.execute(stmt)
                existing = result.scalar_one_or_none()

                if existing:
                    continue

                # Crear nuevo FeedEntry
                feed_entry = FeedEntry(
                    id=uuid.UUID(row_dict["id"]),
                    feed_name=row_dict["feed_name"],
                    feed_url=row_dict["feed_url"],
                    raw_data=json.loads(row_dict["raw_data"])
                    if row_dict["raw_data"]
                    else {},
                    parsed_data=json.loads(row_dict["parsed_data"])
                    if row_dict["parsed_data"]
                    else {},
                    processed=bool(row_dict["processed"]),
                    processing_error=row_dict["processing_error"],
                    external_id=row_dict["external_id"],
                    checksum=row_dict["checksum"],
                    feed_timestamp=datetime.fromisoformat(row_dict["feed_timestamp"])
                    if row_dict["feed_timestamp"]
                    else None,
                    created_at=datetime.fromisoformat(row_dict["created_at"]),
                    updated_at=datetime.fromisoformat(row_dict["updated_at"]),
                )

                session.add(feed_entry)

            await session.commit()

        # Migrar indicators
        print("Migrating indicators...")
        cursor = sqlite_conn.execute("SELECT * FROM indicators")

        async with async_session() as session:
            for row in cursor:
                row_dict = dict(row)

                # Verificar si ya existe
                stmt = select(Indicator).where(
                    (Indicator.indicator_value == row_dict["indicator_value"])
                    & (Indicator.source == row_dict["source"])
                )
                result = await session.execute(stmt)
                existing = result.scalar_one_or_none()

                if existing:
                    continue

                # Crear nuevo Indicator
                indicator = Indicator(
                    id=uuid.UUID(row_dict["id"]),
                    indicator_type=row_dict["indicator_type"],
                    indicator_value=row_dict["indicator_value"],
                    threat_type=row_dict["threat_type"],
                    severity=row_dict["severity"],
                    confidence=row_dict["confidence"],
                    source=row_dict["source"],
                    source_url=row_dict["source_url"],
                    tags=json.loads(row_dict["tags"]) if row_dict["tags"] else [],
                    extra_data=json.loads(row_dict["metadata"])
                    if row_dict["metadata"]
                    else {},
                    first_seen=datetime.fromisoformat(row_dict["first_seen"]),
                    last_seen=datetime.fromisoformat(row_dict["last_seen"]),
                    expires_at=datetime.fromisoformat(row_dict["expires_at"])
                    if row_dict["expires_at"]
                    else None,
                    is_active=bool(row_dict["is_active"]),
                    created_at=datetime.fromisoformat(row_dict["created_at"]),
                    updated_at=datetime.fromisoformat(row_dict["updated_at"]),
                )

                session.add(indicator)

            await session.commit()

        print("Migration completed successfully!")

    finally:
        sqlite_conn.close()
        await engine.dispose()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Migrate SQLite data to PostgreSQL")
    parser.add_argument("--sqlite", required=True, help="Path to SQLite database")
    parser.add_argument("--postgres", required=True, help="PostgreSQL connection URL")

    args = parser.parse_args()

    asyncio.run(migrate_data(args.sqlite, args.postgres))
