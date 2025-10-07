#!/usr/bin/env python3
"""
Script para configurar automáticamente dashboards de Kibana para análisis de vehículos
"""

import json
import sys
import time

import requests


class KibanaSetup:
    def __init__(
        self, kibana_url: str = "http://localhost:5601", es_index: str = "vehicles"
    ):
        self.kibana_url = kibana_url.rstrip("/")
        self.es_index = es_index
        self.session = requests.Session()
        self.headers = {"Content-Type": "application/json", "kbn-xsrf": "true"}

    def wait_for_kibana(self, max_attempts: int = 30) -> bool:
        """Espera a que Kibana esté disponible"""
        print("⏳ Esperando a que Kibana esté disponible...")

        for attempt in range(max_attempts):
            try:
                response = self.session.get(f"{self.kibana_url}/api/status")
                if response.status_code == 200:
                    print("✅ Kibana está disponible")
                    return True
            except requests.exceptions.ConnectionError:
                pass

            time.sleep(2)
            print(f"   Intento {attempt + 1}/{max_attempts}")

        print("❌ Kibana no está disponible después de esperar")
        return False

    def create_index_pattern(self) -> bool:
        """Crea el index pattern para los vehículos"""
        print(f"🔧 Creando index pattern para {self.es_index}...")

        index_pattern = {
            "attributes": {"title": f"{self.es_index}*", "timeFieldName": "scraped_at"}
        }

        try:
            response = self.session.post(
                f"{self.kibana_url}/api/saved_objects/index-pattern/{self.es_index}-pattern",
                headers=self.headers,
                data=json.dumps(index_pattern),
            )

            if response.status_code in [200, 409]:  # 409 = ya existe
                print("✅ Index pattern creado/actualizado")
                return True
            else:
                print(
                    f"❌ Error creando index pattern: {response.status_code} - {response.text}"
                )
                return False
        except Exception as e:
            print(f"❌ Error: {e}")
            return False

    def create_visualizations(self) -> list[str]:
        """Crea visualizaciones básicas para análisis de vehículos"""
        print("📊 Creando visualizaciones...")

        visualizations = [
            {
                "id": "vehicles-price-histogram",
                "title": "Distribución de Precios",
                "type": "histogram",
                "config": {
                    "type": "histogram",
                    "params": {
                        "grid": {"categoryLines": False, "style": {"color": "#eee"}},
                        "categoryAxes": [
                            {
                                "id": "CategoryAxis-1",
                                "type": "category",
                                "position": "bottom",
                                "show": True,
                                "style": {},
                                "scale": {"type": "linear"},
                                "labels": {"show": True, "truncate": 100},
                                "title": {},
                            }
                        ],
                        "valueAxes": [
                            {
                                "id": "ValueAxis-1",
                                "name": "LeftAxis-1",
                                "type": "value",
                                "position": "left",
                                "show": True,
                                "style": {},
                                "scale": {"type": "linear", "mode": "normal"},
                                "labels": {
                                    "show": True,
                                    "rotate": 0,
                                    "filter": False,
                                    "truncate": 100,
                                },
                                "title": {"text": "Count"},
                            }
                        ],
                        "seriesParams": [
                            {
                                "show": True,
                                "type": "histogram",
                                "mode": "stacked",
                                "data": {"label": "Count", "id": "1"},
                                "valueAxis": "ValueAxis-1",
                                "drawLinesBetweenPoints": True,
                                "showCircles": True,
                            }
                        ],
                        "addTooltip": True,
                        "addLegend": True,
                        "legendPosition": "right",
                        "times": [],
                        "addTimeMarker": False,
                    },
                    "aggs": [
                        {
                            "id": "1",
                            "enabled": True,
                            "type": "count",
                            "schema": "metric",
                            "params": {},
                        },
                        {
                            "id": "2",
                            "enabled": True,
                            "type": "histogram",
                            "schema": "segment",
                            "params": {
                                "field": "price",
                                "interval": 5000,
                                "extended_bounds": {},
                            },
                        },
                    ],
                },
            },
            {
                "id": "vehicles-by-brand",
                "title": "Vehículos por Marca",
                "type": "pie",
                "config": {
                    "type": "pie",
                    "params": {
                        "addTooltip": True,
                        "addLegend": True,
                        "legendPosition": "right",
                        "isDonut": True,
                    },
                    "aggs": [
                        {
                            "id": "1",
                            "enabled": True,
                            "type": "count",
                            "schema": "metric",
                            "params": {},
                        },
                        {
                            "id": "2",
                            "enabled": True,
                            "type": "terms",
                            "schema": "segment",
                            "params": {
                                "field": "brand",
                                "size": 20,
                                "order": "desc",
                                "orderBy": "1",
                            },
                        },
                    ],
                },
            },
            {
                "id": "vehicles-by-year",
                "title": "Vehículos por Año",
                "type": "line",
                "config": {
                    "type": "line",
                    "params": {
                        "grid": {"categoryLines": False, "style": {"color": "#eee"}},
                        "categoryAxes": [
                            {
                                "id": "CategoryAxis-1",
                                "type": "category",
                                "position": "bottom",
                                "show": True,
                                "style": {},
                                "scale": {"type": "linear"},
                                "labels": {"show": True, "truncate": 100},
                                "title": {},
                            }
                        ],
                        "valueAxes": [
                            {
                                "id": "ValueAxis-1",
                                "name": "LeftAxis-1",
                                "type": "value",
                                "position": "left",
                                "show": True,
                                "style": {},
                                "scale": {"type": "linear", "mode": "normal"},
                                "labels": {
                                    "show": True,
                                    "rotate": 0,
                                    "filter": False,
                                    "truncate": 100,
                                },
                                "title": {"text": "Count"},
                            }
                        ],
                        "seriesParams": [
                            {
                                "show": True,
                                "type": "line",
                                "mode": "normal",
                                "data": {"label": "Count", "id": "1"},
                                "valueAxis": "ValueAxis-1",
                                "drawLinesBetweenPoints": True,
                                "showCircles": True,
                            }
                        ],
                        "addTooltip": True,
                        "addLegend": True,
                        "legendPosition": "right",
                        "times": [],
                        "addTimeMarker": False,
                    },
                    "aggs": [
                        {
                            "id": "1",
                            "enabled": True,
                            "type": "count",
                            "schema": "metric",
                            "params": {},
                        },
                        {
                            "id": "2",
                            "enabled": True,
                            "type": "histogram",
                            "schema": "segment",
                            "params": {
                                "field": "year",
                                "interval": 1,
                                "extended_bounds": {},
                            },
                        },
                    ],
                },
            },
            {
                "id": "vehicles-location-map",
                "title": "Distribución Geográfica",
                "type": "tile_map",
                "config": {
                    "type": "tile_map",
                    "params": {
                        "mapType": "Scaled Circle Markers",
                        "isDesaturated": True,
                        "addTooltip": True,
                        "heatClusterSize": 1.5,
                        "legendPosition": "bottomright",
                        "mapZoom": 6,
                        "mapCenter": [40.4168, -3.7038],  # España
                    },
                    "aggs": [
                        {
                            "id": "1",
                            "enabled": True,
                            "type": "count",
                            "schema": "metric",
                            "params": {},
                        },
                        {
                            "id": "2",
                            "enabled": True,
                            "type": "geohash_grid",
                            "schema": "segment",
                            "params": {
                                "field": "location.coordinates",
                                "autoPrecision": True,
                                "precision": 2,
                            },
                        },
                    ],
                },
            },
        ]

        created_viz_ids = []

        for viz in visualizations:
            try:
                saved_object = {
                    "attributes": {
                        "title": viz["title"],
                        "visState": json.dumps(
                            {
                                "title": viz["title"],
                                "type": viz["type"],
                                "params": viz["config"]["params"],
                                "aggs": viz["config"]["aggs"],
                            }
                        ),
                        "uiStateJSON": "{}",
                        "description": "",
                        "version": 1,
                        "kibanaSavedObjectMeta": {
                            "searchSourceJSON": json.dumps(
                                {
                                    "index": f"{self.es_index}-pattern",
                                    "query": {"match_all": {}},
                                    "filter": [],
                                }
                            )
                        },
                    }
                }

                response = self.session.post(
                    f"{self.kibana_url}/api/saved_objects/visualization/{viz['id']}",
                    headers=self.headers,
                    data=json.dumps(saved_object),
                )

                if response.status_code in [200, 409]:
                    print(f"✅ Visualización creada: {viz['title']}")
                    created_viz_ids.append(viz["id"])
                else:
                    print(f"⚠️  Error creando {viz['title']}: {response.status_code}")

            except Exception as e:
                print(f"❌ Error creando visualización {viz['title']}: {e}")

        return created_viz_ids

    def create_dashboard(self, viz_ids: list[str]) -> bool:
        """Crea un dashboard con todas las visualizaciones"""
        print("📈 Creando dashboard principal...")

        # Layout de paneles en el dashboard
        panels = []
        panel_configs = [
            {"id": "vehicles-price-histogram", "x": 0, "y": 0, "w": 24, "h": 15},
            {"id": "vehicles-by-brand", "x": 24, "y": 0, "w": 24, "h": 15},
            {"id": "vehicles-by-year", "x": 0, "y": 15, "w": 24, "h": 15},
            {"id": "vehicles-location-map", "x": 24, "y": 15, "w": 24, "h": 15},
        ]

        for i, config in enumerate(panel_configs):
            if config["id"] in viz_ids:
                panels.append(
                    {
                        "gridData": {
                            "x": config["x"],
                            "y": config["y"],
                            "w": config["w"],
                            "h": config["h"],
                            "i": str(i + 1),
                        },
                        "id": config["id"],
                        "panelIndex": str(i + 1),
                        "type": "visualization",
                        "version": "7.0.0",
                    }
                )

        dashboard = {
            "attributes": {
                "title": "Análisis de Vehículos - Dashboard Principal",
                "hits": 0,
                "description": "Dashboard para análisis completo de vehículos scrapeados",
                "panelsJSON": json.dumps(panels),
                "optionsJSON": json.dumps(
                    {"darkTheme": False, "hidePanelTitles": False, "useMargins": True}
                ),
                "uiStateJSON": "{}",
                "version": 1,
                "timeRestore": False,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps(
                        {"query": {"match_all": {}}, "filter": []}
                    )
                },
            }
        }

        try:
            response = self.session.post(
                f"{self.kibana_url}/api/saved_objects/dashboard/vehicles-main-dashboard",
                headers=self.headers,
                data=json.dumps(dashboard),
            )

            if response.status_code in [200, 409]:
                print("✅ Dashboard principal creado")
                print(
                    f"🔗 Accede al dashboard: {self.kibana_url}/app/kibana#/dashboard/vehicles-main-dashboard"
                )
                return True
            else:
                print(
                    f"❌ Error creando dashboard: {response.status_code} - {response.text}"
                )
                return False

        except Exception as e:
            print(f"❌ Error: {e}")
            return False

    def setup_all(self) -> bool:
        """Configura todo automáticamente"""
        if not self.wait_for_kibana():
            return False

        # Crear index pattern
        if not self.create_index_pattern():
            return False

        # Crear visualizaciones
        viz_ids = self.create_visualizations()
        if not viz_ids:
            print("❌ No se pudieron crear visualizaciones")
            return False

        # Crear dashboard
        if not self.create_dashboard(viz_ids):
            return False

        print("\n🎉 ¡Configuración de Kibana completada!")
        print(
            f"📊 Dashboard: {self.kibana_url}/app/kibana#/dashboard/vehicles-main-dashboard"
        )
        print(f"🔍 Discover: {self.kibana_url}/app/kibana#/discover")

        return True


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Configurar dashboards de Kibana para vehículos"
    )
    parser.add_argument(
        "--kibana-url", default="http://localhost:5601", help="URL de Kibana"
    )
    parser.add_argument(
        "--index", default="vehicles", help="Nombre del índice en Elasticsearch"
    )

    args = parser.parse_args()

    setup = KibanaSetup(kibana_url=args.kibana_url, es_index=args.index)
    success = setup.setup_all()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
