#!/usr/bin/env python3
"""
Script para extraer URLs de phishing de la base de datos de Phisherman.
"""

import asyncio
import json
from datetime import datetime

from sqlalchemy import text

from phisherman.datastore.database import AsyncSessionLocal


async def extract_phishing_urls():
    """Extraer URLs de phishing de la base de datos."""
    async with AsyncSessionLocal() as db:
        results = {
            "extracted_at": datetime.now().isoformat(),
            "total_urls": 0,
            "sources": {},
        }

        # 1. URLs de Indicators (feeds externos)
        print("🔍 Extrayendo URLs de Indicators (feeds externos)...")
        indicator_query = text(
            """
            SELECT
                indicator_value as url,
                threat_type,
                severity,
                source,
                confidence,
                first_seen,
                last_seen
            FROM indicators
            WHERE indicator_type = 'url'
                AND threat_type = 'phishing'
            ORDER BY last_seen DESC
            LIMIT 50
        """
        )

        result = await db.execute(indicator_query)
        indicator_urls = []
        for row in result:
            url_data = {
                "url": row.url,
                "threat_type": row.threat_type,
                "severity": row.severity,
                "source": row.source,
                "confidence": float(row.confidence) if row.confidence else None,
                "first_seen": row.first_seen.isoformat() if row.first_seen else None,
                "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            }
            indicator_urls.append(url_data)

        results["sources"]["indicators"] = indicator_urls
        print(f"  ✓ Encontradas {len(indicator_urls)} URLs de feeds externos")

        # 2. URLs de UrlScans (URLs maliciosas analizadas)
        print("🔍 Extrayendo URLs de URL Scans (análisis internos)...")
        urlscan_query = text(
            """
            SELECT
                normalized_url as url,
                domain,
                risk_score,
                confidence,
                labels,
                created_at
            FROM url_scans
            WHERE is_malicious = true
            ORDER BY created_at DESC
            LIMIT 50
        """
        )

        result = await db.execute(urlscan_query)
        urlscan_urls = []
        for row in result:
            url_data = {
                "url": row.url,
                "domain": row.domain,
                "risk_score": float(row.risk_score) if row.risk_score else None,
                "confidence": float(row.confidence) if row.confidence else None,
                "labels": row.labels if row.labels else [],
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            urlscan_urls.append(url_data)

        results["sources"]["url_scans"] = urlscan_urls
        print(f"  ✓ Encontradas {len(urlscan_urls)} URLs de análisis internos")

        # 3. Contar totales
        total_count = await db.execute(
            text(
                "SELECT COUNT(*) FROM indicators WHERE indicator_type = 'url' AND threat_type = 'phishing'"
            )
        )
        total_indicators = total_count.scalar()

        total_scans = await db.execute(
            text("SELECT COUNT(*) FROM url_scans WHERE is_malicious = true")
        )
        total_urlscans = total_scans.scalar()

        results["total_urls"] = len(indicator_urls) + len(urlscan_urls)
        results["total_in_db"] = {
            "indicators": total_indicators,
            "url_scans": total_urlscans,
        }

        return results


async def main():
    """Función principal."""
    print("🎣 EXTRAYENDO URLs DE PHISHING DE LA BASE DE DATOS")
    print("=" * 60)

    try:
        results = await extract_phishing_urls()

        # Guardar en JSON
        output_file = "phishing_urls_extracted.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print("\n✅ Extracción completada!")
        print(f"📊 Total URLs extraídas: {results['total_urls']}")
        print(
            f"   - De feeds externos (indicators): {len(results['sources']['indicators'])}"
        )
        print(
            f"   - De análisis internos (url_scans): {len(results['sources']['url_scans'])}"
        )
        print(f"\n💾 Guardado en: {output_file}")

        # Mostrar algunas URLs de ejemplo
        print("\n📋 EJEMPLOS DE URLs EXTRAÍDAS:")
        print("-" * 60)

        all_urls = (
            results["sources"]["indicators"][:5] + results["sources"]["url_scans"][:5]
        )

        for i, url_data in enumerate(all_urls[:10], 1):
            source = "Feed Externo" if "source" in url_data else "Análisis Interno"
            print(f"\n{i}. {url_data['url']}")
            print(f"   Fuente: {source}")
            if "source" in url_data:
                print(f"   Feed: {url_data['source']}")
                print(f"   Severidad: {url_data['severity']}")
            if "risk_score" in url_data and url_data["risk_score"]:
                print(f"   Risk Score: {url_data['risk_score']:.2f}")

        # Crear archivo simple con solo las URLs (para copiar/pegar fácilmente)
        simple_urls_file = "phishing_urls_simple.txt"
        with open(simple_urls_file, "w") as f:
            for url_data in results["sources"]["indicators"]:
                f.write(f"{url_data['url']}\n")
            for url_data in results["sources"]["url_scans"]:
                f.write(f"{url_data['url']}\n")

        print(f"\n📝 También guardado en formato simple: {simple_urls_file}")
        print("   (Una URL por línea, listo para copiar/pegar)")

    except Exception as e:
        print(f"\n❌ Error durante la extracción: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
