#!/usr/bin/env python3
"""
Script simple para monitorear la base de datos de Phisherman diariamente.
"""

import asyncio
from datetime import datetime

from sqlalchemy import text

from phisherman.datastore.database import AsyncSessionLocal


async def quick_status():
    """Status rápido de la base de datos."""
    async with AsyncSessionLocal() as db:
        print(f"🔍 DB Monitor - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)

        # Tablas principales con conteos
        tables = [
            ("url_scans", "🌐 URLs analizadas"),
            ("indicators", "⚠️  Indicadores de amenazas"),
            ("feed_entries", "📡 Entradas de feeds"),
            ("victim_companies", "🏢 Empresas víctimas"),
            ("phishing_campaigns", "🎯 Campañas de phishing"),
            ("victim_urls", "🔗 URLs clasificadas"),
            ("verdicts", "💾 Verdicts cachados"),
        ]

        for table, desc in tables:
            result = await db.execute(text(f"SELECT COUNT(*) FROM {table}"))
            count = result.scalar()
            print(f"{desc:<25} {count:>8}")

        print("-" * 50)

        # Actividad reciente (último día)
        result = await db.execute(
            text(
                """
            SELECT COUNT(*) FROM url_scans
            WHERE created_at >= NOW() - INTERVAL '24 hours'
        """
            )
        )
        recent_scans = result.scalar()

        result = await db.execute(
            text(
                """
            SELECT COUNT(*) FROM indicators
            WHERE created_at >= NOW() - INTERVAL '24 hours'
        """
            )
        )
        recent_indicators = result.scalar()

        print("📈 Actividad últimas 24h:")
        print(f"   Nuevos scans: {recent_scans}")
        print(f"   Nuevos indicadores: {recent_indicators}")

        # Top fuentes de indicators
        result = await db.execute(
            text(
                """
            SELECT source, COUNT(*) as count
            FROM indicators
            GROUP BY source
            ORDER BY count DESC
            LIMIT 5
        """
            )
        )

        print("\n📊 Top fuentes de amenazas:")
        for row in result:
            print(f"   {row.source}: {row.count}")


if __name__ == "__main__":
    asyncio.run(quick_status())
