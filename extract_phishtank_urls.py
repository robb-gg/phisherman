#!/usr/bin/env python3
"""
Script para extraer URLs de phishing del archivo verified_online_phistank.json
"""

import json
import sys


def extract_urls(
    input_file="verified_online_phistank.json",
    output_file="phishing_test_urls.txt",
    limit=50,
):
    """Extraer URLs de phishing del JSON de PhishTank."""

    print(f"🎣 Extrayendo URLs de {input_file}...")

    urls_extracted = []
    urls_with_metadata = []

    try:
        # Leer y parsear el JSON
        print("📖 Leyendo archivo...")
        with open(input_file) as f:
            data = json.load(f)

        print(f"✓ Encontradas {len(data)} entradas de phishing")

        # Extraer URLs (limitadas)
        for i, entry in enumerate(data[:limit]):
            url = entry.get("url", "")
            if url:
                urls_extracted.append(url)

                # Guardar con metadata para referencia
                urls_with_metadata.append(
                    {
                        "url": url,
                        "phish_id": entry.get("phish_id"),
                        "target": entry.get("target"),
                        "verified": entry.get("verified"),
                        "online": entry.get("online"),
                        "submission_time": entry.get("submission_time"),
                    }
                )

        # Guardar URLs simples
        with open(output_file, "w") as f:
            for url in urls_extracted:
                f.write(f"{url}\n")

        print(f"✅ Guardadas {len(urls_extracted)} URLs en {output_file}")

        # Guardar con metadata en JSON
        json_output = output_file.replace(".txt", "_metadata.json")
        with open(json_output, "w") as f:
            json.dump(
                {
                    "total_extracted": len(urls_extracted),
                    "extraction_date": "now",
                    "urls": urls_with_metadata,
                },
                f,
                indent=2,
            )

        print(f"📊 Metadata guardada en {json_output}")

        # Mostrar algunos ejemplos
        print("\n📋 Primeras 10 URLs extraídas:")
        print("-" * 80)
        for i, url_data in enumerate(urls_with_metadata[:10], 1):
            print(f"\n{i}. {url_data['url']}")
            print(f"   Target: {url_data['target']}")
            print(f"   Verified: {url_data['verified']}")
            print(f"   Online: {url_data['online']}")

        return urls_extracted

    except FileNotFoundError:
        print(f"❌ Error: No se encontró el archivo {input_file}")
        return []
    except json.JSONDecodeError as e:
        print(f"❌ Error al parsear JSON: {e}")
        return []
    except Exception as e:
        print(f"❌ Error inesperado: {e}")
        return []


if __name__ == "__main__":
    # Permitir customizar el límite desde línea de comandos
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 50

    print("=" * 80)
    print("🎣 EXTRACTOR DE URLs DE PHISHING - PhishTank")
    print("=" * 80)
    print()

    urls = extract_urls(limit=limit)

    if urls:
        print("\n✅ ¡Listo! Ahora puedes probar estas URLs en tu frontend.")
        print("   Archivo: phishing_test_urls.txt")
    else:
        print("\n⚠️  No se pudieron extraer URLs.")

    print()
    print("=" * 80)
