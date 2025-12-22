#!/usr/bin/env python3
"""
Phisherman Feeds Standalone - Recolector independiente de threat intelligence
Versión corregida con URLs actualizadas y mejor manejo de errores
"""

import argparse
import asyncio
import csv
import hashlib
import io
import json
import logging
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiosqlite
import httpx

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,  # Volver a INFO
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("feeds.log"), logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# Silenciar logs de httpx para evitar spam
logging.getLogger("httpx").setLevel(logging.WARNING)


class Config:
    """Configuración del sistema de feeds."""

    def __init__(self, config_file: str | None = None):
        self.database_path = "feeds_data.db"
        self.user_agent = "phishtank/vreyes"  # ✅ User-Agent correcto para PhishTank
        self.http_timeout = 120

        # URLs actualizadas - PhishTank CSV funciona, JSON tiene problemas
        self.feed_urls = {
            "phishtank": "https://data.phishtank.com/data/online-valid.csv",  # ✅ CSV funciona correctamente
            "openphish": "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",  # Nueva URL
            "urlhaus": "https://urlhaus.abuse.ch/downloads/json/",
        }

        # PhishTank API key para acceso sin rate limiting
        self.phishtank_api_key = ""

        # Intervalos de refresh en minutos
        self.phishtank_interval = 15
        self.openphish_interval = 15
        self.urlhaus_interval = 30

        # APIs opcionales
        self.virustotal_api_key = ""
        self.google_safebrowsing_key = ""

        if config_file and Path(config_file).exists():
            self._load_config(config_file)

    def _load_config(self, config_file: str):
        """Cargar configuración desde archivo JSON."""
        try:
            with open(config_file) as f:
                config = json.load(f)

            for key, value in config.items():
                if hasattr(self, key):
                    setattr(self, key, value)
        except Exception as e:
            logger.warning(f"Error loading config file: {e}")


class FeedsDatabase:
    """Manejo de la base de datos SQLite para los feeds."""

    def __init__(self, db_path: str):
        self.db_path = db_path

    async def init_database(self):
        """Inicializar esquema de la base de datos."""
        async with aiosqlite.connect(self.db_path) as db:
            # Tabla para entradas crudas de feeds
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS feed_entries (
                    id TEXT PRIMARY KEY,
                    feed_name TEXT NOT NULL,
                    feed_url TEXT NOT NULL,
                    raw_data TEXT NOT NULL,
                    parsed_data TEXT,
                    processed BOOLEAN DEFAULT FALSE,
                    processing_error TEXT,
                    external_id TEXT,
                    checksum TEXT NOT NULL UNIQUE,
                    feed_timestamp TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Tabla para indicadores procesados
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS indicators (
                    id TEXT PRIMARY KEY,
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    source TEXT NOT NULL,
                    source_url TEXT,
                    tags TEXT,
                    metadata TEXT,
                    first_seen TIMESTAMP NOT NULL,
                    last_seen TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Tabla de estadísticas
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS feed_stats (
                    feed_name TEXT PRIMARY KEY,
                    total_entries INTEGER DEFAULT 0,
                    last_refresh TIMESTAMP,
                    last_error TEXT,
                    consecutive_errors INTEGER DEFAULT 0
                )
            """
            )

            # Índices para performance
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_feed_entries_feed_name ON feed_entries(feed_name)"
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_feed_entries_checksum ON feed_entries(checksum)"
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(indicator_value)"
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_indicators_source ON indicators(source)"
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(indicator_type)"
            )

            await db.commit()
            logger.info("Database initialized successfully")

    async def entry_exists(self, checksum: str) -> bool:
        """Verificar si una entrada ya existe."""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                "SELECT 1 FROM feed_entries WHERE checksum = ?", (checksum,)
            )
            result = await cursor.fetchone()
            return result is not None

    async def save_feed_entry(self, entry_data: dict[str, Any]) -> str:
        """Guardar una entrada de feed."""
        entry_id = str(uuid.uuid4())

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO feed_entries
                (id, feed_name, feed_url, raw_data, checksum, external_id, feed_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    entry_id,
                    entry_data["feed_name"],
                    entry_data["feed_url"],
                    json.dumps(entry_data["raw_data"]),
                    entry_data["checksum"],
                    entry_data.get("external_id"),
                    datetime.now(UTC).isoformat(),
                ),
            )
            await db.commit()

        return entry_id

    async def save_indicator(self, indicator_data: dict[str, Any]) -> str:
        """Guardar un indicador de amenaza."""
        indicator_id = str(uuid.uuid4())

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO indicators
                (id, indicator_type, indicator_value, threat_type, severity,
                 confidence, source, source_url, tags, metadata, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    indicator_id,
                    indicator_data["indicator_type"],
                    indicator_data["indicator_value"].lower(),
                    indicator_data["threat_type"],
                    indicator_data["severity"],
                    indicator_data["confidence"],
                    indicator_data["source"],
                    indicator_data["source_url"],
                    json.dumps(indicator_data.get("tags", [])),
                    json.dumps(indicator_data.get("metadata", {})),
                    datetime.now(UTC).isoformat(),
                    datetime.now(UTC).isoformat(),
                ),
            )
            await db.commit()

        return indicator_id

    async def update_feed_stats(
        self, feed_name: str, entries_count: int, error: str = None
    ):
        """Actualizar estadísticas del feed."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO feed_stats
                (feed_name, total_entries, last_refresh, last_error, consecutive_errors)
                VALUES (?,
                       COALESCE((SELECT total_entries FROM feed_stats WHERE feed_name = ?), 0) + ?,
                       ?, ?,
                       CASE WHEN ? IS NULL THEN 0
                            ELSE COALESCE((SELECT consecutive_errors FROM feed_stats WHERE feed_name = ?), 0) + 1
                       END)
            """,
                (
                    feed_name,
                    feed_name,
                    entries_count,
                    datetime.now(UTC).isoformat(),
                    error,
                    error,
                    feed_name,
                ),
            )
            await db.commit()

    async def get_stats(self) -> dict[str, Any]:
        """Obtener estadísticas generales."""
        async with aiosqlite.connect(self.db_path) as db:
            # Estadísticas por feed
            cursor = await db.execute("SELECT * FROM feed_stats")
            feeds_data = await cursor.fetchall()
            feeds = []
            if feeds_data:
                columns = [description[0] for description in cursor.description]
                feeds = [dict(zip(columns, feed, strict=False)) for feed in feeds_data]

            # Total de indicadores
            cursor = await db.execute(
                "SELECT COUNT(*) FROM indicators WHERE is_active = TRUE"
            )
            total_indicators = (await cursor.fetchone())[0]

            # Indicadores por tipo
            cursor = await db.execute(
                """
                SELECT threat_type, COUNT(*)
                FROM indicators WHERE is_active = TRUE
                GROUP BY threat_type
            """
            )
            by_threat_type_data = await cursor.fetchall()
            by_threat_type = dict(by_threat_type_data) if by_threat_type_data else {}

            return {
                "feeds": feeds,
                "total_indicators": total_indicators,
                "by_threat_type": by_threat_type,
                "database_size_mb": Path(self.db_path).stat().st_size / 1024 / 1024
                if Path(self.db_path).exists()
                else 0,
            }


class FeedProcessor:
    """Procesador principal de feeds con soporte completo para PhishTank API."""

    def __init__(self, config: Config, database: FeedsDatabase):
        self.config = config
        self.db = database
        self.session = None

    async def __aenter__(self):
        self.session = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.http_timeout),
            headers={"User-Agent": self.config.user_agent},
            follow_redirects=True,  # ✅ IMPORTANTE: Seguir redirects automáticamente
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.aclose()

    async def refresh_phishtank(self) -> dict[str, Any]:
        """Procesar feed de PhishTank (CSV format con API key optimizada)."""
        feed_name = "phishtank"

        # ✅ Usar API key si está disponible para mejor rendimiento
        if self.config.phishtank_api_key:
            # Usar formato comprimido con API key (más eficiente)
            feed_url = f"https://data.phishtank.com/data/{self.config.phishtank_api_key}/online-valid.csv.bz2"
            logger.info(f"Refreshing {feed_name} feed with API key (compressed)...")
        else:
            # Fallback al público sin API key
            feed_url = self.config.feed_urls["phishtank"]
            logger.info(f"Refreshing {feed_name} feed (public access)...")

        try:
            # ✅ Verificar si hay actualizaciones con HEAD request (si hay API key)
            if self.config.phishtank_api_key:
                head_response = await self.session.head(feed_url)
                etag = head_response.headers.get("etag", "")
                logger.debug(f"PhishTank ETag: {etag}")

            response = await self.session.get(feed_url)
            response.raise_for_status()

            # ✅ Manejar contenido comprimido si es necesario
            if feed_url.endswith(".bz2"):
                import bz2

                csv_content = bz2.decompress(response.content).decode("utf-8").strip()
            else:
                csv_content = response.text.strip()

            csv_reader = csv.DictReader(io.StringIO(csv_content))
            entries_processed = 0

            for row in csv_reader:
                # ✅ Validar datos del CSV
                url = row.get("url", "").strip()
                phish_id = row.get("phish_id", "").strip()

                if not url or not phish_id:
                    continue

                # Solo procesar URLs verificadas y en línea
                if (
                    row.get("verified", "").lower() != "yes"
                    or row.get("online", "").lower() != "yes"
                ):
                    continue

                # Crear checksum para deduplicación
                entry_str = f"{feed_name}:{url}"
                checksum = hashlib.sha256(entry_str.encode()).hexdigest()

                if await self.db.entry_exists(checksum):
                    continue

                # ✅ Mejorar extracción del target según documentación
                target_raw = row.get("target", "")
                target_clean = target_raw.replace(
                    '"', ""
                ).strip()  # Limpiar comillas y espacios

                # Convertir row CSV a formato dict para compatibilidad
                entry_data = {
                    "phish_id": phish_id,
                    "url": url,
                    "phish_detail_url": row.get("phish_detail_url", ""),
                    "submission_time": row.get(
                        "submission_time", ""
                    ),  # ISO 8601 format
                    "verified": row.get("verified", ""),  # Always "yes" in these files
                    "verification_time": row.get(
                        "verification_time", ""
                    ),  # ISO 8601 format
                    "online": row.get("online", ""),  # Always "yes" in these files
                    "target": target_clean,  # Company/brand being impersonated
                }

                # Guardar entrada del feed
                await self.db.save_feed_entry(
                    {
                        "feed_name": feed_name,
                        "feed_url": feed_url,
                        "raw_data": entry_data,
                        "checksum": checksum,
                        "external_id": phish_id,
                    }
                )

                # ✅ Crear indicador con metadatos completos según documentación
                indicator_tags = ["phishing", "phishtank", "verified", "online"]
                if target_clean:
                    indicator_tags.append(
                        f"target_{target_clean.lower().replace(' ', '_')}"
                    )

                await self.db.save_indicator(
                    {
                        "indicator_type": "url",
                        "indicator_value": url,
                        "threat_type": "phishing",
                        "severity": "high",
                        "confidence": 0.95,  # High confidence - verified by PhishTank community
                        "source": feed_name,
                        "source_url": feed_url,
                        "tags": indicator_tags,
                        "metadata": {
                            "phish_id": int(phish_id)
                            if phish_id.isdigit()
                            else phish_id,  # Always positive integer per docs
                            "submission_time": row.get(
                                "submission_time", ""
                            ),  # ISO 8601 format
                            "verification_time": row.get(
                                "verification_time", ""
                            ),  # ISO 8601 format
                            "target_company": target_clean,  # Company/brand being impersonated
                            "phish_detail_url": row.get(
                                "phish_detail_url", ""
                            ),  # PhishTank detail page
                            "community_verified": True,  # Always true in these files
                            "currently_online": True,  # Always true in these files
                        },
                    }
                )

                entries_processed += 1

            await self.db.update_feed_stats(feed_name, entries_processed)

            logger.info(f"PhishTank refresh completed: {entries_processed} new entries")
            return {"status": "success", "entries_processed": entries_processed}

        except Exception as e:
            logger.error(f"PhishTank refresh failed: {e}")
            await self.db.update_feed_stats(feed_name, 0, str(e))
            return {"status": "error", "error": str(e)}

    async def refresh_openphish(self) -> dict[str, Any]:
        """Procesar feed de OpenPhish."""
        feed_name = "openphish"
        feed_url = self.config.feed_urls["openphish"]  # ✅ URL actualizada

        try:
            logger.info(f"Refreshing {feed_name} feed...")

            response = await self.session.get(feed_url)
            response.raise_for_status()

            urls = response.text.strip().split("\n")
            entries_processed = 0

            for url in urls:
                url = url.strip()
                if not url or url.startswith("#"):
                    continue

                entry_str = f"{feed_name}:{url}"
                checksum = hashlib.sha256(entry_str.encode()).hexdigest()

                if await self.db.entry_exists(checksum):
                    continue

                await self.db.save_feed_entry(
                    {
                        "feed_name": feed_name,
                        "feed_url": feed_url,
                        "raw_data": {"url": url},
                        "checksum": checksum,
                    }
                )

                await self.db.save_indicator(
                    {
                        "indicator_type": "url",
                        "indicator_value": url,
                        "threat_type": "phishing",
                        "severity": "high",
                        "confidence": 0.85,
                        "source": feed_name,
                        "source_url": feed_url,
                        "tags": ["phishing", "openphish"],
                        "metadata": {"url": url},
                    }
                )

                entries_processed += 1

            await self.db.update_feed_stats(feed_name, entries_processed)

            logger.info(f"OpenPhish refresh completed: {entries_processed} new entries")
            return {"status": "success", "entries_processed": entries_processed}

        except Exception as e:
            logger.error(f"OpenPhish refresh failed: {e}")
            await self.db.update_feed_stats(feed_name, 0, str(e))
            return {"status": "error", "error": str(e)}

    async def refresh_urlhaus(self) -> dict[str, Any]:
        """Procesar feed de URLhaus."""
        feed_name = "urlhaus"
        feed_url = self.config.feed_urls["urlhaus"]

        try:
            logger.info(f"Refreshing {feed_name} feed...")

            response = await self.session.get(feed_url)
            response.raise_for_status()

            # ✅ URLhaus devuelve un ZIP que contiene el JSON
            import zipfile
            from io import BytesIO

            with zipfile.ZipFile(BytesIO(response.content)) as zf:
                # El archivo JSON está dentro del ZIP
                json_filename = zf.namelist()[0]  # Usualmente "urlhaus_full.json"
                logger.info(f"Extracting {json_filename} from ZIP...")
                with zf.open(json_filename) as f:
                    json_content = f.read().decode('utf-8')

            # ✅ El JSON es un objeto con IDs como keys y arrays de URLs como values
            data = json.loads(json_content)
            
            entries_processed = 0
            duplicates = 0
            no_url = 0
            invalid_entries = 0

            # Iterar sobre cada ID y sus URLs asociadas
            for url_id, url_entries in data.items():
                # Cada value puede ser un array de objetos o un objeto único
                if not isinstance(url_entries, list):
                    url_entries = [url_entries]
                
                for entry in url_entries:
                    if not isinstance(entry, dict):
                        invalid_entries += 1
                        continue

                    url = entry.get("url", "").strip()
                    if not url:
                        no_url += 1
                        continue

                    # Usar el ID del JSON como external_id
                    entry_str = f"{feed_name}:{url_id}:{url}"
                    checksum = hashlib.sha256(entry_str.encode()).hexdigest()

                    if await self.db.entry_exists(checksum):
                        duplicates += 1
                        continue

                    # Agregar el ID al entry para referencia
                    entry["id"] = url_id

                    await self.db.save_feed_entry(
                        {
                            "feed_name": feed_name,
                            "feed_url": feed_url,
                            "raw_data": entry,
                            "checksum": checksum,
                            "external_id": url_id,
                        }
                    )

                    threat_tags = entry.get("tags", [])
                    if isinstance(threat_tags, str):
                        threat_tags = [threat_tags]
                    elif not isinstance(threat_tags, list):
                        threat_tags = []

                    await self.db.save_indicator(
                        {
                            "indicator_type": "url",
                            "indicator_value": url,
                            "threat_type": "malware",
                            "severity": "high",
                            "confidence": 0.9,
                            "source": feed_name,
                            "source_url": feed_url,
                            "tags": ["malware", "urlhaus"] + threat_tags,
                            "metadata": {
                                "urlhaus_id": url_id,
                                "dateadded": entry.get("dateadded"),
                                "url_status": entry.get("url_status"),
                                "threat": entry.get("threat"),
                                "tags": threat_tags,
                            },
                        }
                    )

                    entries_processed += 1

            await self.db.update_feed_stats(feed_name, entries_processed)

            logger.info(
                f"URLhaus refresh completed: {entries_processed} new entries "
                f"(duplicates: {duplicates}, invalid: {invalid_entries}, no_url: {no_url})"
            )
            return {
                "status": "success",
                "entries_processed": entries_processed,
                "duplicates": duplicates,
                "invalid_entries": invalid_entries,
                "no_url": no_url,
            }

        except Exception as e:
            logger.error(f"URLhaus refresh failed: {e}")
            await self.db.update_feed_stats(feed_name, 0, str(e))
            return {"status": "error", "error": str(e)}

    async def check_url_phishtank(self, url: str) -> dict[str, Any]:
        """Verificar una URL específica usando PhishTank URL Lookup API."""
        if not self.config.phishtank_api_key:
            return {
                "status": "error",
                "error": "PhishTank API key required for URL lookup",
            }

        try:
            # Endpoint oficial para verificación de URLs (HTTPS según documentación)
            api_url = "https://checkurl.phishtank.com/checkurl/"

            # Preparar datos del request (form-encoded según documentación)
            import urllib.parse

            data = {
                "url": urllib.parse.quote(
                    url, safe=""
                ),  # URL encoded como requiere la doc
                "format": "json",
                "app_key": self.config.phishtank_api_key,
            }

            # Usar form data en lugar de JSON
            response = await self.session.post(api_url, data=data)
            response.raise_for_status()

            # Debug: mostrar contenido de la respuesta
            logger.debug(f"PhishTank API response status: {response.status_code}")
            logger.debug(f"PhishTank API response headers: {dict(response.headers)}")
            logger.debug(f"PhishTank API response content: {response.text[:500]}...")

            if not response.text.strip():
                return {"status": "error", "error": "Empty response from PhishTank API"}

            try:
                result = response.json()
            except json.JSONDecodeError as e:
                logger.error(
                    f"Invalid JSON response from PhishTank: {response.text[:200]}"
                )
                return {"status": "error", "error": f"Invalid JSON response: {str(e)}"}

            # Extraer información del resultado
            if result.get("results"):
                url_info = result["results"]
                is_phish = url_info.get("in_database", False)

                logger.info(
                    f"PhishTank URL check: {url} -> {'PHISH' if is_phish else 'SAFE'}"
                )

                return {
                    "status": "success",
                    "url": url,
                    "is_phishing": is_phish,
                    "in_database": is_phish,
                    "phish_id": url_info.get("phish_id"),
                    "verified": url_info.get("verified"),
                    "verified_at": url_info.get("verified_at"),
                    "phish_detail_page": url_info.get("phish_detail_page"),
                    "submitted_at": url_info.get("submitted_at"),
                    "valid": url_info.get("valid"),
                }
            else:
                return {
                    "status": "success",
                    "url": url,
                    "is_phishing": False,
                    "in_database": False,
                }

        except Exception as e:
            logger.error(f"PhishTank URL lookup failed: {e}")
            return {"status": "error", "error": str(e)}


async def refresh_all_feeds(config: Config, database: FeedsDatabase) -> dict[str, Any]:
    """Actualizar todos los feeds."""
    async with FeedProcessor(config, database) as processor:
        feeds = {
            "phishtank": processor.refresh_phishtank,
            "openphish": processor.refresh_openphish,
            "urlhaus": processor.refresh_urlhaus,
        }

        results = {}

        # Ejecutar feeds en paralelo
        tasks = []
        for feed_name, refresh_func in feeds.items():
            task = asyncio.create_task(refresh_func(), name=f"refresh_{feed_name}")
            tasks.append((feed_name, task))

        for feed_name, task in tasks:
            try:
                result = await task
                results[feed_name] = result
            except Exception as e:
                results[feed_name] = {"status": "error", "error": str(e)}

        success_count = sum(1 for r in results.values() if r.get("status") == "success")

        return {
            "status": "completed",
            "feeds": results,
            "successful_feeds": success_count,
            "total_feeds": len(feeds),
            "completed_at": datetime.now(UTC).isoformat(),
        }


async def main():
    """Función principal del script."""
    parser = argparse.ArgumentParser(description="Phisherman Feeds Standalone")
    parser.add_argument(
        "command",
        choices=["refresh", "stats", "init", "daemon", "check-url"],
        help="Comando a ejecutar",
    )
    parser.add_argument("--config", help="Archivo de configuración JSON")
    parser.add_argument(
        "--database", default="feeds_data.db", help="Ruta de la base de datos SQLite"
    )
    parser.add_argument(
        "--feed", help="Nombre específico del feed (para comando refresh)"
    )
    parser.add_argument("--url", help="URL a verificar (para comando check-url)")
    parser.add_argument(
        "--interval", type=int, default=15, help="Intervalo en minutos para modo daemon"
    )

    args = parser.parse_args()

    # Cargar configuración
    config = Config(args.config)
    config.database_path = args.database

    # Inicializar base de datos
    database = FeedsDatabase(config.database_path)

    if args.command == "init":
        await database.init_database()
        print(f"Database initialized: {config.database_path}")

    elif args.command == "refresh":
        await database.init_database()

        if args.feed:
            # Refrescar feed específico
            async with FeedProcessor(config, database) as processor:
                if args.feed == "phishtank":
                    result = await processor.refresh_phishtank()
                elif args.feed == "openphish":
                    result = await processor.refresh_openphish()
                elif args.feed == "urlhaus":
                    result = await processor.refresh_urlhaus()
                else:
                    print(f"Unknown feed: {args.feed}")
                    return

                print(json.dumps(result, indent=2))
        else:
            # Refrescar todos los feeds
            result = await refresh_all_feeds(config, database)
            print(json.dumps(result, indent=2))

    elif args.command == "stats":
        stats = await database.get_stats()
        print(json.dumps(stats, indent=2, default=str))

    elif args.command == "check-url":
        if not args.url:
            print("Error: --url parameter is required for check-url command")
            return

        async with FeedProcessor(config, database) as processor:
            result = await processor.check_url_phishtank(args.url)
            print(json.dumps(result, indent=2))

    elif args.command == "daemon":
        await database.init_database()

        logger.info(f"Starting daemon mode with {args.interval} minute intervals")

        while True:
            try:
                logger.info("Starting scheduled feed refresh...")
                result = await refresh_all_feeds(config, database)
                logger.info(
                    f"Scheduled refresh completed: {result['successful_feeds']}/{result['total_feeds']} successful"
                )

                # Esperar hasta el próximo ciclo
                await asyncio.sleep(args.interval * 60)

            except KeyboardInterrupt:
                logger.info("Daemon stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in daemon loop: {e}")
                await asyncio.sleep(60)  # Esperar 1 minuto antes de reintentar


if __name__ == "__main__":
    asyncio.run(main())
