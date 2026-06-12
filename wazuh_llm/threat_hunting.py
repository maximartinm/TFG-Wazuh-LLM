#!/usr/bin/env python3
"""
threat_hunting.py — Fase 3 del TFG
Módulo de Threat Hunting mediante consultas en Lenguaje Natural.

El analista escribe una pregunta en español, el LLM la interpreta y genera
una query DSL de OpenSearch, que el middleware ejecuta contra el Indexer
y muestra los resultados en formato legible.

Ejemplos de consultas:
  - "Muestra intentos de fuerza bruta SSH de las últimas 12 horas"
  - "¿Hay escaladas de privilegios con sudo en el agente Ubuntu?"
  - "Lista los 5 ataques más críticos de hoy"
"""
import os
import json
import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

INDEXER_URL  = os.getenv('WZ_INDEXER_URL')
INDEXER_USER = os.getenv('WZ_INDEXER_USER')
INDEXER_PASS = os.getenv('WZ_INDEXER_PASS')


# =====================================================================
# PASO 1 — TRADUCCIÓN NL → DSL CON EL LLM
# =====================================================================

# Prompt de sistema para que el LLM actúe como traductor NL → OpenSearch DSL
PROMPT_NL_A_DSL = """Eres un experto en OpenSearch y Wazuh. Tu única tarea es convertir preguntas en lenguaje natural a queries DSL de OpenSearch.

ESQUEMA DE ÍNDICE WAZUH (campos disponibles):
- timestamp: fecha/hora del evento (formato ISO 8601)
- rule.level: severidad (entero 1-15, siendo 15 el más crítico)
- rule.id: ID de la regla Wazuh (string)
- rule.description: descripción del evento
- rule.mitre.id: técnica MITRE ATT&CK (ej: "T1110")
- rule.mitre.tactic: táctica MITRE (ej: "Credential Access")
- agent.name: nombre del agente/endpoint
- agent.id: ID del agente
- data.srcip: IP origen del ataque
- data.dstip: IP destino
- data.srcuser / data.dstuser: usuarios involucrados
- full_log: log crudo completo del sistema operativo

REGLAS OBLIGATORIAS:
1. Responde SOLO con JSON válido, sin texto adicional, sin explicaciones, sin bloques de código markdown.
2. El JSON debe ser una query DSL de OpenSearch con estructura {"size": N, "query": {...}, "sort": [...]}
3. Para rangos de tiempo, usa "now-Xh" para horas, "now-Xd" para días. El campo de tiempo es "timestamp".
4. Si la pregunta menciona "hoy" usa: "gt": "now/d"  
5. Si menciona "últimas 12 horas" usa: "gt": "now-12h"
6. Limita los resultados a 10 por defecto salvo que se especifique otro número.
7. Ordena siempre por timestamp descendente.

EJEMPLOS:
Pregunta: "intentos de fuerza bruta SSH de las últimas 2 horas"
Respuesta: {"size": 10, "sort": [{"timestamp": {"order": "desc"}}], "query": {"bool": {"must": [{"match": {"rule.description": "ssh"}}, {"range": {"timestamp": {"gt": "now-2h"}}}, {"range": {"rule.level": {"gte": 5}}}]}}}

Pregunta: "escaladas de privilegios sudo hoy"  
Respuesta: {"size": 10, "sort": [{"timestamp": {"order": "desc"}}], "query": {"bool": {"must": [{"match": {"rule.description": "sudo"}}, {"range": {"timestamp": {"gt": "now/d"}}}]}}}

Ahora convierte esta pregunta:
{consulta_usuario}"""


def nl_a_query_dsl(consulta: str, ollama_url: str, modelo: str) -> dict | None:
    """
    Usa el LLM para traducir una consulta en lenguaje natural a DSL de OpenSearch.

    Args:
        consulta:    Pregunta del analista en texto libre.
        ollama_url:  URL del servidor Ollama.
        modelo:      Nombre del modelo a usar.

    Returns:
        Dict con la query DSL, o None si la traducción falla.
    """
    prompt = PROMPT_NL_A_DSL.replace("{consulta_usuario}", consulta)

    try:
        payload = {"model": modelo, "prompt": prompt, "stream": False}
        response = requests.post(ollama_url, json=payload, timeout=60)
        raw = response.json().get("response", "").strip()

        # Limpiar posibles bloques markdown que el modelo incluya a veces
        raw = raw.replace("```json", "").replace("```", "").strip()

        query_dsl = json.loads(raw)
        return query_dsl

    except json.JSONDecodeError:
        print(f"[-] El LLM no devolvió JSON válido. Respuesta recibida:\n{raw[:300]}")
        return None
    except Exception as e:
        print(f"[-] Error traduciendo consulta: {e}")
        return None


# =====================================================================
# PASO 2 — EJECUCIÓN DE LA QUERY EN OPENSEARCH
# =====================================================================

def ejecutar_query(query_dsl: dict) -> list[dict]:
    """
    Ejecuta la query DSL contra el Indexer de Wazuh y devuelve los resultados.

    Returns:
        Lista de dicts con los _source de cada alerta encontrada.
    """
    try:
        response = requests.post(
            INDEXER_URL,
            auth=(INDEXER_USER, INDEXER_PASS),
            json=query_dsl,
            verify=False,
            timeout=15
        )
        if response.status_code == 200:
            hits = response.json().get('hits', {}).get('hits', [])
            return [h['_source'] for h in hits]
        else:
            print(f"[-] Error ejecutando query. Status: {response.status_code}")
            print(f"    Respuesta: {response.text[:200]}")
            return []
    except Exception as e:
        print(f"[-] Error de conexión con el Indexer: {e}")
        return []


# =====================================================================
# PASO 3 — FORMATEO DE RESULTADOS
# =====================================================================

def formatear_resultados(alertas: list[dict], consulta_original: str) -> str:
    """
    Convierte la lista de alertas en un resumen legible para el analista.
    No enviamos TODO al LLM para evitar context overflow en modelos locales.
    """
    if not alertas:
        return f"[~] No se encontraron eventos para: '{consulta_original}'"

    lineas = [
        f"\n{'='*70}",
        f"  RESULTADOS para: '{consulta_original}'",
        f"  {len(alertas)} evento(s) encontrado(s)",
        f"{'='*70}"
    ]

    for i, alerta in enumerate(alertas, start=1):
        ts          = alerta.get("timestamp", "N/A")
        nivel       = alerta.get("rule", {}).get("level", "?")
        descripcion = alerta.get("rule", {}).get("description", "Sin descripción")
        agente      = alerta.get("agent", {}).get("name", "Desconocido")
        src_ip      = alerta.get("data", {}).get("srcip", "-")
        mitre_ids   = alerta.get("rule", {}).get("mitre", {}).get("id", [])
        mitre_str   = ", ".join(mitre_ids) if isinstance(mitre_ids, list) else str(mitre_ids)

        lineas.append(f"\n  [{i}] {ts}")
        lineas.append(f"      Agente  : {agente}")
        lineas.append(f"      Nivel   : {nivel}  |  Descripción: {descripcion}")
        lineas.append(f"      Origen  : {src_ip}")
        if mitre_str and mitre_str != "[]":
            lineas.append(f"      MITRE   : {mitre_str}")

    lineas.append(f"\n{'='*70}")
    return "\n".join(lineas)


# =====================================================================
# BUCLE INTERACTIVO PRINCIPAL
# =====================================================================

def iniciar_modo_hunting():
    """
    Bucle de threat hunting en lenguaje natural.
    Integra los tres pasos: NL → DSL → Ejecución → Resultados.
    """
    ollama_url = os.getenv("WZ_OLLAMA_URL")
    modelo     = os.getenv("WZ_MODELO", "llama3.2")

    print("\n" + "="*70)
    print("  THREAT HUNTING — Modo Consultas en Lenguaje Natural")
    print("  Wazuh Indexer + LLM Local (Ollama)")
    print("="*70)
    print("\nEjemplos de consultas:")
    print("  → 'intentos de brute force SSH de las últimas 6 horas'")
    print("  → 'escaladas de privilegios con sudo hoy'")
    print("  → 'alertas críticas nivel 10 o superior esta semana'")
    print("  → 'actividad de Mimikatz en agentes Windows'")
    print("\nEscribe 'salir' para terminar.\n")

    historial = []  # Para futuras mejoras: contexto conversacional

    while True:
        try:
            consulta = input("🔍 [HUNTING] > ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[~] Sesión de Threat Hunting finalizada.")
            break

        if not consulta:
            continue
        if consulta.lower() in ('salir', 'exit', 'quit', 'q'):
            print("[~] Saliendo del modo Threat Hunting.")
            break

        # Comandos especiales
        if consulta.lower() == 'historial':
            if historial:
                print("\nConsultas anteriores:")
                for i, h in enumerate(historial, 1):
                    print(f"  {i}. {h}")
            else:
                print("[~] Sin historial todavía.")
            continue

        print(f"[~] Traduciendo consulta al lenguaje de OpenSearch...")

        # Paso 1: NL → DSL
        query_dsl = nl_a_query_dsl(consulta, ollama_url, modelo)
        if not query_dsl:
            print("[-] No se pudo generar una query válida. Intenta reformular la pregunta.")
            continue

        # Mostrar la query generada (útil para el TFG: demuestra la traducción)
        print(f"[~] Query DSL generada:")
        print(f"    {json.dumps(query_dsl, ensure_ascii=False)}")

        # Paso 2: Ejecutar query
        print("[~] Consultando el Indexer de Wazuh...")
        resultados = ejecutar_query(query_dsl)

        # Paso 3: Mostrar resultados
        salida = formatear_resultados(resultados, consulta)
        print(salida)

        historial.append(consulta)


if __name__ == "__main__":
    iniciar_modo_hunting()