#!/usr/bin/env python3
"""
Script de prueba para verificar la integración del microservicio de feeds.
"""

import asyncio
from datetime import datetime

import httpx

# URLs de prueba
FEEDS_SERVICE_URL = "http://localhost:8001"
API_SERVICE_URL = "http://localhost:8000"

# URLs conocidas para pruebas (usar con precaución)
TEST_URLS = [
    "https://www.google.com",  # URL limpia
    "http://example.com",  # URL limpia
    # Agrega URLs de phishing conocidas para testing real
]


async def test_feeds_health():
    """Test básico de conectividad."""
    print("🏥 Verificando salud del microservicio de feeds...")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{FEEDS_SERVICE_URL}/health")
            print(f"✅ Feeds service health: {response.status_code}")
            print(f"   Response: {response.json()}")
            return response.status_code == 200
    except Exception as e:
        print(f"❌ Error conectando a feeds service: {e}")
        return False


async def test_feeds_lookup():
    """Test de lookup de URL."""
    print("\n🔍 Probando lookup de URLs...")

    try:
        async with httpx.AsyncClient() as client:
            for url in TEST_URLS:
                print(f"\n   Consultando: {url}")

                response = await client.post(
                    f"{FEEDS_SERVICE_URL}/feeds/v1/lookup",
                    json={"url": url, "normalize": True},
                    headers={"Host": "localhost"},
                )

                if response.status_code == 200:
                    result = response.json()
                    is_threat = result.get("is_threat", False)
                    matches = result.get("total_matches", 0)

                    status = "🚨 THREAT" if is_threat else "✅ CLEAN"
                    print(f"   {status} - {matches} matches")

                    if is_threat:
                        for match in result.get("matches", []):
                            print(
                                f"     - {match['source']}: {match['threat_type']} ({match['confidence']})"
                            )
                else:
                    print(f"   ❌ Error: {response.status_code}")

    except Exception as e:
        print(f"❌ Error en lookup: {e}")


async def test_feeds_stats():
    """Test de estadísticas."""
    print("\n📊 Obteniendo estadísticas...")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{FEEDS_SERVICE_URL}/feeds/v1/stats", headers={"Host": "localhost"}
            )

            if response.status_code == 200:
                stats = response.json()
                print(f"✅ Total indicadores: {stats.get('total_indicators', 0)}")

                print("   Por fuente:")
                for source, count in stats.get("by_source", {}).items():
                    print(f"     - {source}: {count}")

                print("   Por tipo:")
                for threat_type, count in stats.get("by_threat_type", {}).items():
                    print(f"     - {threat_type}: {count}")
            else:
                print(f"❌ Error obteniendo stats: {response.status_code}")

    except Exception as e:
        print(f"❌ Error en stats: {e}")


async def test_feeds_status():
    """Test de estado de feeds."""
    print("\n⚙️  Verificando estado de feeds...")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{FEEDS_SERVICE_URL}/feeds/v1/status", headers={"Host": "localhost"}
            )

            if response.status_code == 200:
                status = response.json()
                total_feeds = len(status.get("feeds", []))
                active_feeds = status.get("total_active_feeds", 0)

                print(f"✅ Feeds: {active_feeds}/{total_feeds} activos")

                for feed in status.get("feeds", []):
                    name = feed["name"]
                    status_str = feed["status"]
                    entries = feed["total_entries"]

                    status_icon = "✅" if status_str == "active" else "❌"
                    print(f"   {status_icon} {name}: {entries} entradas ({status_str})")
            else:
                print(f"❌ Error obteniendo status: {response.status_code}")

    except Exception as e:
        print(f"❌ Error en status: {e}")


async def test_api_integration():
    """Test de integración con API principal."""
    print("\n🔗 Probando integración con API principal...")

    try:
        async with httpx.AsyncClient() as client:
            # Health check de feeds desde API principal
            response = await client.get(f"{API_SERVICE_URL}/api/v1/admin/feeds/health")

            if response.status_code == 200:
                result = response.json()
                is_healthy = result.get("feeds_service_healthy", False)

                if is_healthy:
                    print("✅ API principal puede conectar con feeds service")
                else:
                    print("❌ API principal no puede conectar con feeds service")
                    print(f"   Error: {result.get('error', 'Unknown')}")
            else:
                print(f"❌ Error desde API principal: {response.status_code}")

    except Exception as e:
        print(f"❌ Error probando integración: {e}")


async def test_analyzer_integration():
    """Test del analyzer de feeds integrado."""
    print("\n🧩 Probando analyzer de feeds integrado...")

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            for url in TEST_URLS[:2]:  # Solo probar con 2 URLs
                print(f"\n   Analizando: {url}")

                response = await client.post(
                    f"{API_SERVICE_URL}/api/v1/analyze", json={"url": url}
                )

                if response.status_code == 200:
                    result = response.json()

                    # Buscar resultado del analyzer de feeds
                    feeds_analyzer = None
                    for analyzer in result.get("analyzer_results", []):
                        if analyzer.get("analyzer_name") == "feeds":
                            feeds_analyzer = analyzer
                            break

                    if feeds_analyzer:
                        risk_score = feeds_analyzer.get("risk_score", 0)
                        confidence = feeds_analyzer.get("confidence", 0)
                        labels = feeds_analyzer.get("labels", [])

                        print("   ✅ Feeds analyzer ejecutado")
                        print(f"      Risk score: {risk_score:.3f}")
                        print(f"      Confidence: {confidence:.3f}")
                        print(f"      Labels: {labels}")
                    else:
                        print("   ⚠️  Feeds analyzer no encontrado en resultados")
                else:
                    print(f"   ❌ Error en análisis: {response.status_code}")

    except Exception as e:
        print(f"❌ Error en analyzer integration: {e}")


async def main():
    """Ejecutar todas las pruebas."""
    print("🧪 Test de Integración - Microservicio de Feeds")
    print("=" * 50)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Feeds Service: {FEEDS_SERVICE_URL}")
    print(f"API Service: {API_SERVICE_URL}")

    # Ejecutar pruebas
    feeds_healthy = await test_feeds_health()

    if feeds_healthy:
        await test_feeds_stats()
        await test_feeds_status()
        await test_feeds_lookup()
        await test_api_integration()
        await test_analyzer_integration()
    else:
        print("\n❌ Feeds service no está disponible. Verifica que esté corriendo:")
        print("   docker-compose up feeds")
        print("   o")
        print("   ./start-feeds-dev.sh")

    print("\n✅ Tests completados!")


if __name__ == "__main__":
    asyncio.run(main())
