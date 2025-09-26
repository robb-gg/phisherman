#!/usr/bin/env python3
"""
Script para inspeccionar y visualizar las relaciones de la base de datos de Phisherman.
"""

import asyncio
import json
from datetime import datetime
from typing import Any

from sqlalchemy import text

from phisherman.datastore.database import AsyncSessionLocal


# Colores para output
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    END = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def print_header(text: str):
    """Imprimir header con color."""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text.center(60)}{Colors.END}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.END}")


def print_section(text: str):
    """Imprimir sección con color."""
    print(f"\n{Colors.BLUE}{Colors.BOLD}{text}{Colors.END}")
    print(f"{Colors.BLUE}{'-'*len(text)}{Colors.END}")


async def get_database_info():
    """Obtener información general de la base de datos."""
    async with AsyncSessionLocal() as db:
        # Información de la base de datos
        result = await db.execute(text("SELECT version()"))
        db_version = result.scalar()

        # Tamaño de la base de datos
        result = await db.execute(
            text(
                """
            SELECT pg_size_pretty(pg_database_size(current_database())) as size
        """
            )
        )
        db_size = result.scalar()

        # Número de conexiones
        result = await db.execute(
            text(
                """
            SELECT count(*) from pg_stat_activity
            WHERE datname = current_database()
        """
            )
        )
        connections = result.scalar()

        return {
            "version": db_version,
            "size": db_size,
            "connections": connections,
            "current_time": datetime.now().isoformat(),
        }


async def get_tables_info():
    """Obtener información de todas las tablas."""
    async with AsyncSessionLocal() as db:
        # Lista de tablas
        result = await db.execute(
            text(
                """
            SELECT
                schemaname,
                tablename,
                tableowner,
                hasindexes,
                hasrules,
                hastriggers
            FROM pg_tables
            WHERE schemaname = 'public'
            ORDER BY tablename
        """
            )
        )

        tables = []
        for row in result:
            table_name = row.tablename

            # Obtener número de filas
            count_result = await db.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
            row_count = count_result.scalar()

            # Obtener tamaño de la tabla
            size_result = await db.execute(
                text(
                    f"""
                SELECT pg_size_pretty(pg_total_relation_size('{table_name}')) as size
            """
                )
            )
            table_size = size_result.scalar()

            tables.append(
                {
                    "name": table_name,
                    "schema": row.schemaname,
                    "owner": row.tableowner,
                    "has_indexes": row.hasindexes,
                    "has_rules": row.hasrules,
                    "has_triggers": row.hastriggers,
                    "row_count": row_count,
                    "size": table_size,
                }
            )

        return tables


async def get_table_columns(table_name: str):
    """Obtener información de columnas de una tabla."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text(
                f"""
            SELECT
                column_name,
                data_type,
                is_nullable,
                column_default,
                character_maximum_length,
                numeric_precision,
                numeric_scale
            FROM information_schema.columns
            WHERE table_name = '{table_name}'
            ORDER BY ordinal_position
        """
            )
        )

        columns = []
        for row in result:
            columns.append(
                {
                    "name": row.column_name,
                    "type": row.data_type,
                    "nullable": row.is_nullable == "YES",
                    "default": row.column_default,
                    "max_length": row.character_maximum_length,
                    "precision": row.numeric_precision,
                    "scale": row.numeric_scale,
                }
            )

        return columns


async def get_foreign_keys():
    """Obtener todas las foreign keys y sus relaciones."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text(
                """
            SELECT
                tc.table_name as from_table,
                kcu.column_name as from_column,
                ccu.table_name AS to_table,
                ccu.column_name AS to_column,
                tc.constraint_name
            FROM information_schema.table_constraints AS tc
            JOIN information_schema.key_column_usage AS kcu
                ON tc.constraint_name = kcu.constraint_name
                AND tc.table_schema = kcu.table_schema
            JOIN information_schema.constraint_column_usage AS ccu
                ON ccu.constraint_name = tc.constraint_name
                AND ccu.table_schema = tc.table_schema
            WHERE tc.constraint_type = 'FOREIGN KEY'
            ORDER BY tc.table_name, kcu.column_name
        """
            )
        )

        foreign_keys = []
        for row in result:
            foreign_keys.append(
                {
                    "from_table": row.from_table,
                    "from_column": row.from_column,
                    "to_table": row.to_table,
                    "to_column": row.to_column,
                    "constraint_name": row.constraint_name,
                }
            )

        return foreign_keys


async def get_indexes():
    """Obtener información de índices."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text(
                """
            SELECT
                schemaname,
                tablename,
                indexname,
                indexdef
            FROM pg_indexes
            WHERE schemaname = 'public'
            ORDER BY tablename, indexname
        """
            )
        )

        indexes = []
        for row in result:
            indexes.append(
                {
                    "schema": row.schemaname,
                    "table": row.tablename,
                    "name": row.indexname,
                    "definition": row.indexdef,
                }
            )

        return indexes


async def get_sample_data(table_name: str, limit: int = 3):
    """Obtener datos de ejemplo de una tabla."""
    async with AsyncSessionLocal() as db:
        try:
            result = await db.execute(text(f"SELECT * FROM {table_name} LIMIT {limit}"))
            rows = result.fetchall()
            columns = result.keys()

            sample_data = []
            for row in rows:
                row_dict = {}
                for i, col in enumerate(columns):
                    value = row[i]
                    # Convertir tipos no serializables
                    if hasattr(value, "isoformat"):
                        value = value.isoformat()
                    elif isinstance(value, list | dict):
                        value = json.dumps(value, default=str)
                    row_dict[col] = str(value) if value is not None else None
                sample_data.append(row_dict)

            return sample_data
        except Exception as e:
            return [{"error": str(e)}]


def print_database_info(info: dict[str, Any]):
    """Imprimir información general de la base de datos."""
    print_header("INFORMACIÓN GENERAL DE LA BASE DE DATOS")
    print(f"{Colors.CYAN}Versión PostgreSQL:{Colors.END} {info['version']}")
    print(f"{Colors.CYAN}Tamaño total:{Colors.END} {info['size']}")
    print(f"{Colors.CYAN}Conexiones activas:{Colors.END} {info['connections']}")
    print(f"{Colors.CYAN}Consultado el:{Colors.END} {info['current_time']}")


def print_tables_overview(tables: list[dict[str, Any]]):
    """Imprimir resumen de tablas."""
    print_header("RESUMEN DE TABLAS")

    print(f"{'Tabla':<25} {'Filas':<10} {'Tamaño':<12} {'Índices':<8} {'Triggers':<8}")
    print("─" * 70)

    total_rows = 0
    for table in tables:
        name = table["name"]
        rows = table["row_count"]
        size = table["size"]
        indexes = "✓" if table["has_indexes"] else "✗"
        triggers = "✓" if table["has_triggers"] else "✗"

        color = Colors.GREEN if rows > 0 else Colors.WARNING
        print(
            f"{color}{name:<25}{Colors.END} {rows:<10} {size:<12} {indexes:<8} {triggers:<8}"
        )
        total_rows += rows

    print("─" * 70)
    print(f"{Colors.BOLD}Total de filas en todas las tablas: {total_rows}{Colors.END}")


def print_table_structure(table_name: str, columns: list[dict[str, Any]]):
    """Imprimir estructura de una tabla."""
    print_section(f"📋 ESTRUCTURA DE {table_name.upper()}")

    print(f"{'Campo':<25} {'Tipo':<20} {'Nulo':<6} {'Default':<15}")
    print("─" * 70)

    for col in columns:
        name = col["name"]
        data_type = col["type"]
        if col["max_length"]:
            data_type += f"({col['max_length']})"
        nullable = "✓" if col["nullable"] else "✗"
        default = str(col["default"])[:14] if col["default"] else "-"

        # Colorear campos importantes
        color = ""
        if name == "id":
            color = Colors.BLUE
        elif name.endswith("_id"):
            color = Colors.CYAN
        elif name in ["created_at", "updated_at"]:
            color = Colors.GREEN

        print(
            f"{color}{name:<25}{Colors.END} {data_type:<20} {nullable:<6} {default:<15}"
        )


def print_relationships(foreign_keys: list[dict[str, Any]]):
    """Imprimir relaciones entre tablas."""
    print_header("RELACIONES ENTRE TABLAS (FOREIGN KEYS)")

    if not foreign_keys:
        print(f"{Colors.WARNING}No se encontraron foreign keys{Colors.END}")
        return

    # Agrupar por tabla origen
    relationships_by_table = {}
    for fk in foreign_keys:
        from_table = fk["from_table"]
        if from_table not in relationships_by_table:
            relationships_by_table[from_table] = []
        relationships_by_table[from_table].append(fk)

    for from_table, relationships in relationships_by_table.items():
        print(f"\n{Colors.BOLD}{from_table.upper()}{Colors.END}")
        for rel in relationships:
            print(
                f"  {Colors.CYAN}{rel['from_column']}{Colors.END} → {Colors.GREEN}{rel['to_table']}.{rel['to_column']}{Colors.END}"
            )


def print_indexes_summary(indexes: list[dict[str, Any]]):
    """Imprimir resumen de índices."""
    print_header("ÍNDICES DE BASE DE DATOS")

    indexes_by_table = {}
    for idx in indexes:
        table = idx["table"]
        if table not in indexes_by_table:
            indexes_by_table[table] = []
        indexes_by_table[table].append(idx)

    for table, table_indexes in indexes_by_table.items():
        print(
            f"\n{Colors.BOLD}{table.upper()}{Colors.END} ({len(table_indexes)} índices)"
        )
        for idx in table_indexes:
            index_type = "🔑 PK" if "pkey" in idx["name"] else "📍 IDX"
            print(f"  {index_type} {idx['name']}")


def print_sample_data(table_name: str, data: list[dict[str, Any]]):
    """Imprimir datos de ejemplo."""
    if not data:
        print(f"{Colors.WARNING}    Tabla vacía - sin datos{Colors.END}")
        return
    elif len(data) == 1 and "error" in data[0]:
        print(
            f"{Colors.WARNING}    Sin datos o error: {data[0].get('error', 'Tabla vacía')}{Colors.END}"
        )
        return

    print(f"\n  {Colors.GREEN}📄 Datos de ejemplo:{Colors.END}")
    for i, row in enumerate(data, 1):
        print(f"    Registro {i}:")
        for key, value in row.items():
            if len(str(value)) > 50:
                value = str(value)[:47] + "..."
            print(f"      {key}: {value}")
        print()


def create_database_diagram():
    """Crear un diagrama textual de las relaciones."""
    print_header("DIAGRAMA DE RELACIONES DE DATOS")

    diagram = """
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   UrlScan       │    │  VictimCompany  │    │ PhishingCampaign│
│                 │    │                 │    │                 │
│ • id (PK)       │    │ • id (PK)       │    │ • id (PK)       │
│ • url           │    │ • name          │    │ • name          │
│ • normalized_url│    │ • industry      │    │ • victim_co_id ─┼─┐
│ • domain        │    │ • official_doms │    │ • status        │ │
│ • is_malicious  │    │ • risk_score    │    │ • attack_vector │ │
│ • risk_score    │    │                 │    │                 │ │
│ • labels        │    └─────────────────┘    └─────────────────┘ │
│ • evidence      │                                               │
└─────────┬───────┘                                               │
          │                                                       │
          │    ┌─────────────────┐    ┌─────────────────┐         │
          └────┤   VictimUrl     │    │   Indicator     │         │
               │                 │    │                 │         │
               │ • id (PK)       │    │ • id (PK)       │         │
               │ • url_scan_id ──┼────┘ • indicator_type│         │
               │ • victim_co_id ─┼──────┐• indicator_val │         │
               │ • campaign_id ──┼──────┼┐• threat_type   │         │
               │ • similarity    │      ││• severity      │         │
               │ • deception     │      ││• source        │         │
               └─────────────────┘      ││• confidence    │         │
                                        │└─────────────────┘         │
                                        │                            │
                                        └────────────────────────────┘

┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   FeedEntry     │    │   BrandPattern  │    │    Verdict      │
│                 │    │                 │    │                 │
│ • id (PK)       │    │ • id (PK)       │    │ • id (PK)       │
│ • feed_name     │    │ • victim_co_id ─┼────┤ • url_hash      │
│ • feed_url      │    │ • pattern_type  │    │ • normalized_url│
│ • raw_data      │    │ • pattern_value │    │ • is_malicious  │
│ • processed     │    │ • confidence    │    │ • risk_score    │
│ • checksum      │    │ • matches_count │    │ • expires_at    │
└─────────────────┘    └─────────────────┘    └─────────────────┘

FLUJO DE DATOS:
1. URLs → UrlScan (análisis principal)
2. External Feeds → FeedEntry → Indicator (threat intelligence)
3. UrlScan + Classifier → VictimUrl (clasificación por víctima)
4. VictimUrl → PhishingCampaign (agrupación de campañas)
5. Análisis repetidos → Verdict (cache de resultados)
    """

    print(diagram)


async def main():
    """Función principal."""
    print(f"{Colors.BOLD}🔍 INSPECTOR DE BASE DE DATOS PHISHERMAN{Colors.END}")
    print(f"Timestamp: {datetime.now().isoformat()}")

    try:
        # Información general
        db_info = await get_database_info()
        print_database_info(db_info)

        # Información de tablas
        tables = await get_tables_info()
        print_tables_overview(tables)

        # Relaciones
        foreign_keys = await get_foreign_keys()
        print_relationships(foreign_keys)

        # Estructura detallada de tablas principales
        main_tables = [
            "url_scans",
            "indicators",
            "victim_companies",
            "phishing_campaigns",
            "victim_urls",
        ]

        print_header("ESTRUCTURA DETALLADA DE TABLAS PRINCIPALES")

        for table_name in main_tables:
            if any(t["name"] == table_name for t in tables):
                columns = await get_table_columns(table_name)
                print_table_structure(table_name, columns)

                # Datos de ejemplo
                sample_data = await get_sample_data(table_name)
                print_sample_data(table_name, sample_data)

        # Índices
        indexes = await get_indexes()
        print_indexes_summary(indexes)

        # Diagrama de relaciones
        create_database_diagram()

        print(
            f"\n{Colors.GREEN}{Colors.BOLD}✅ Inspección completada exitosamente{Colors.END}"
        )

    except Exception as e:
        print(f"\n{Colors.FAIL}❌ Error durante la inspección: {e}{Colors.END}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
