#!/usr/bin/env python3
"""
Script para migrar datos de vehículos desde SQLite a Elasticsearch
Optimizado para manejar 3GB de datos de manera eficiente
"""

import argparse
import sqlite3
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any

try:
    from elasticsearch import Elasticsearch, helpers
    from elasticsearch.exceptions import ConnectionError
except ImportError:
    print("❌ Error: Instala elasticsearch-python:")
    print("pip install elasticsearch")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("⚠️  Recomendado: Instala tqdm para barra de progreso:")
    print("pip install tqdm")
    tqdm = None


@dataclass
class MigrationConfig:
    """Configuración para la migración"""

    db_path: str = "/Users/vreyes/SideProyect/phisherman/wallapop_data.db"
    es_host: str = "http://localhost:9200"
    index_name: str = "vehicles"
    batch_size: int = 1000
    max_retries: int = 3
    request_timeout: int = 60


class VehicleMigrator:
    def __init__(self, config: MigrationConfig):
        self.config = config
        self.es = None
        self.setup_elasticsearch()

    def setup_elasticsearch(self):
        """Configura la conexión a Elasticsearch"""
        print(f"🔌 Conectando a Elasticsearch en {self.config.es_host}")

        self.es = Elasticsearch(
            [self.config.es_host],
            request_timeout=self.config.request_timeout,
            max_retries=self.config.max_retries,
            retry_on_timeout=True,
        )

        try:
            info = self.es.info()
            print(f"✅ Conectado a Elasticsearch {info['version']['number']}")
        except ConnectionError:
            print(f"❌ No se puede conectar a Elasticsearch en {self.config.es_host}")
            print("   Asegúrate de que Elasticsearch esté ejecutándose:")
            print("   docker-compose -f docker-compose.elk.yml up elasticsearch")
            sys.exit(1)

    def get_database_info(self) -> dict[str, Any]:
        """Obtiene información sobre la base de datos SQLite"""
        try:
            conn = sqlite3.connect(self.config.db_path)
            cursor = conn.cursor()

            # Obtener tablas
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]

            info = {"tables": {}}

            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]

                    cursor.execute(f"PRAGMA table_info({table})")
                    columns = [
                        {"name": col[1], "type": col[2]} for col in cursor.fetchall()
                    ]

                    info["tables"][table] = {"count": count, "columns": columns}
                except sqlite3.Error as e:
                    print(f"⚠️  Error al inspeccionar tabla {table}: {e}")

            conn.close()
            return info

        except sqlite3.Error as e:
            print(f"❌ Error al conectar a SQLite: {e}")
            if "malformed" in str(e).lower():
                print(
                    "💡 La base de datos parece estar corrupta. Intentando recuperación..."
                )
                return self.attempt_recovery()
            sys.exit(1)

    def attempt_recovery(self) -> dict[str, Any]:
        """Intenta recuperar datos de una base de datos corrupta"""
        try:
            print("🔧 Intentando recuperar datos...")
            conn = sqlite3.connect(self.config.db_path)
            conn.execute("PRAGMA integrity_check")

            # Intenta obtener al menos las tablas principales
            cursor = conn.cursor()
            cursor.execute(".tables")
            tables = cursor.fetchall()
            print(f"📋 Tablas encontradas: {tables}")

            return {"tables": {"recovered": {"count": 0, "columns": []}}}
        except Exception:
            print("❌ No se pudo recuperar la base de datos")
            return {"tables": {}}

    def create_index_mapping(self):
        """Crea el índice con mapping optimizado para vehículos"""
        mapping = {
            "mappings": {
                "properties": {
                    "id": {"type": "keyword"},
                    "title": {
                        "type": "text",
                        "analyzer": "spanish",
                        "fields": {"keyword": {"type": "keyword"}},
                    },
                    "description": {"type": "text", "analyzer": "spanish"},
                    "price": {"type": "float"},
                    "currency": {"type": "keyword"},
                    "brand": {"type": "keyword"},
                    "model": {
                        "type": "text",
                        "fields": {"keyword": {"type": "keyword"}},
                    },
                    "year": {"type": "integer"},
                    "kilometers": {"type": "integer"},
                    "fuel_type": {"type": "keyword"},
                    "transmission": {"type": "keyword"},
                    "body_type": {"type": "keyword"},
                    "color": {"type": "keyword"},
                    "doors": {"type": "integer"},
                    "power": {"type": "integer"},
                    "location": {
                        "type": "object",
                        "properties": {
                            "city": {"type": "keyword"},
                            "province": {"type": "keyword"},
                            "coordinates": {"type": "geo_point"},
                        },
                    },
                    "seller": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "keyword"},
                            "name": {"type": "keyword"},
                            "type": {"type": "keyword"},
                        },
                    },
                    "images": {"type": "keyword"},
                    "url": {"type": "keyword"},
                    "scraped_at": {"type": "date"},
                    "created_at": {"type": "date"},
                    "updated_at": {"type": "date"},
                }
            },
            "settings": {
                "index": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "refresh_interval": "30s",
                },
                "analysis": {
                    "analyzer": {
                        "spanish": {"type": "standard", "stopwords": "_spanish_"}
                    }
                },
            },
        }

        if self.es.indices.exists(index=self.config.index_name):
            print(f"⚠️  El índice {self.config.index_name} ya existe. Eliminándolo...")
            self.es.indices.delete(index=self.config.index_name)

        print(f"🔧 Creando índice {self.config.index_name} con mapping optimizado...")
        self.es.indices.create(index=self.config.index_name, body=mapping)
        print("✅ Índice creado exitosamente")

    def get_data_from_sqlite(
        self, table_name: str, limit: int = None
    ) -> Iterator[dict[str, Any]]:
        """Generador que lee datos de SQLite de manera eficiente"""
        conn = sqlite3.connect(self.config.db_path)
        conn.row_factory = sqlite3.Row  # Para acceso por nombre de columna
        cursor = conn.cursor()

        try:
            query = f"SELECT * FROM {table_name}"
            if limit:
                query += f" LIMIT {limit}"

            cursor.execute(query)

            while True:
                rows = cursor.fetchmany(self.config.batch_size)
                if not rows:
                    break

                for row in rows:
                    yield dict(row)

        except sqlite3.Error as e:
            print(f"❌ Error leyendo de SQLite: {e}")
        finally:
            conn.close()

    def normalize_vehicle_data(self, row: dict[str, Any]) -> dict[str, Any]:
        """Normaliza y limpia los datos del vehículo"""
        doc = {}

        # Mapeo de campos comunes
        field_mapping = {
            "id": "id",
            "title": "title",
            "titulo": "title",
            "name": "title",
            "description": "description",
            "descripcion": "description",
            "price": "price",
            "precio": "price",
            "brand": "brand",
            "marca": "brand",
            "model": "model",
            "modelo": "model",
            "year": "year",
            "año": "year",
            "anio": "year",
            "km": "kilometers",
            "kilometers": "kilometers",
            "kilometros": "kilometers",
            "fuel": "fuel_type",
            "combustible": "fuel_type",
            "transmission": "transmission",
            "transmision": "transmission",
            "color": "color",
            "doors": "doors",
            "puertas": "doors",
            "power": "power",
            "potencia": "power",
            "city": "location.city",
            "ciudad": "location.city",
            "province": "location.province",
            "provincia": "location.province",
            "url": "url",
            "link": "url",
        }

        # Aplicar mapeo
        for sql_field, es_field in field_mapping.items():
            if sql_field in row and row[sql_field] is not None:
                if "." in es_field:
                    parts = es_field.split(".")
                    if parts[0] not in doc:
                        doc[parts[0]] = {}
                    doc[parts[0]][parts[1]] = row[sql_field]
                else:
                    doc[es_field] = row[sql_field]

        # Procesar campos especiales
        if "price" in doc:
            try:
                # Limpiar precio (remover €, comas, etc.)
                price_str = (
                    str(doc["price"]).replace("€", "").replace(",", "").replace(".", "")
                )
                doc["price"] = float(price_str) if price_str.isdigit() else None
            except Exception:
                doc["price"] = None

        # Agregar timestamp
        doc["scraped_at"] = datetime.now().isoformat()

        return doc

    def bulk_index_data(
        self, documents: Iterator[dict[str, Any]], total_count: int = None
    ):
        """Indexa documentos en lotes usando bulk API"""

        def doc_generator():
            for doc in documents:
                normalized_doc = self.normalize_vehicle_data(doc)
                yield {
                    "_index": self.config.index_name,
                    "_id": normalized_doc.get("id", None),
                    "_source": normalized_doc,
                }

        print(f"📤 Indexando datos en lotes de {self.config.batch_size}...")

        progress_bar = None
        if tqdm and total_count:
            progress_bar = tqdm(total=total_count, desc="Indexando")

        success_count = 0
        error_count = 0

        try:
            for success, info in helpers.parallel_bulk(
                self.es,
                doc_generator(),
                chunk_size=self.config.batch_size,
                thread_count=4,
                max_chunk_bytes=10 * 1024 * 1024,  # 10MB por chunk
            ):
                if success:
                    success_count += 1
                else:
                    error_count += 1
                    print(f"❌ Error indexando: {info}")

                if progress_bar:
                    progress_bar.update(1)

        except Exception as e:
            print(f"❌ Error durante indexación: {e}")

        finally:
            if progress_bar:
                progress_bar.close()

        print(f"✅ Indexación completada: {success_count} éxitos, {error_count} errores")

    def migrate(self, table_name: str = None, limit: int = None):
        """Ejecuta la migración completa"""
        print("🚀 Iniciando migración de vehículos a Elasticsearch...")
        start_time = time.time()

        # Obtener información de la DB
        db_info = self.get_database_info()
        print(f"📊 Base de datos analizada: {len(db_info['tables'])} tablas encontradas")

        for table, info in db_info["tables"].items():
            print(f"   - {table}: {info['count']} registros")

        # Crear índice
        self.create_index_mapping()

        # Determinar tabla a migrar
        if not table_name:
            # Buscar tabla principal de vehículos
            vehicle_tables = [
                t
                for t in db_info["tables"].keys()
                if any(
                    keyword in t.lower()
                    for keyword in ["vehicle", "car", "auto", "coche", "listing", "ad"]
                )
            ]

            if vehicle_tables:
                table_name = vehicle_tables[0]
            else:
                table_name = list(db_info["tables"].keys())[0]

            print(f"🎯 Tabla seleccionada automáticamente: {table_name}")

        if table_name not in db_info["tables"]:
            print(f"❌ Tabla '{table_name}' no encontrada")
            return

        total_count = db_info["tables"][table_name]["count"]
        if limit:
            total_count = min(total_count, limit)

        print(f"📋 Migrando {total_count} registros de la tabla '{table_name}'...")

        # Migrar datos
        documents = self.get_data_from_sqlite(table_name, limit)
        self.bulk_index_data(documents, total_count)

        # Estadísticas finales
        elapsed_time = time.time() - start_time

        # Verificar índice
        self.es.indices.refresh(index=self.config.index_name)
        final_count = self.es.count(index=self.config.index_name)["count"]

        print("\n✅ Migración completada!")
        print(f"   ⏱️  Tiempo: {elapsed_time:.2f} segundos")
        print(f"   📊 Documentos indexados: {final_count}")
        print("   🔗 Kibana: http://localhost:5601")
        print(f"   🔍 Elasticsearch: {self.config.es_host}/{self.config.index_name}")


def main():
    parser = argparse.ArgumentParser(
        description="Migrar datos de vehículos de SQLite a Elasticsearch"
    )
    parser.add_argument(
        "--db-path",
        default="/Users/vreyes/SideProyect/phisherman/wallapop_data.db",
        help="Ruta a la base de datos SQLite",
    )
    parser.add_argument(
        "--es-host", default="http://localhost:9200", help="Host de Elasticsearch"
    )
    parser.add_argument(
        "--index", default="vehicles", help="Nombre del índice en Elasticsearch"
    )
    parser.add_argument("--table", help="Tabla específica a migrar")
    parser.add_argument(
        "--limit", type=int, help="Limitar número de registros (para testing)"
    )
    parser.add_argument(
        "--batch-size", type=int, default=1000, help="Tamaño de lote para indexación"
    )

    args = parser.parse_args()

    config = MigrationConfig(
        db_path=args.db_path,
        es_host=args.es_host,
        index_name=args.index,
        batch_size=args.batch_size,
    )

    migrator = VehicleMigrator(config)
    migrator.migrate(table_name=args.table, limit=args.limit)


if __name__ == "__main__":
    main()
