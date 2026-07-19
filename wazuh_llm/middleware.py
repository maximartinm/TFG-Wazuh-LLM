#!/usr/bin/env python3
"""
Middleware principal del TFG: Wazuh + LLM
Orquestador que conecta el ecosistema Wazuh con un LLM (Ollama, Gemini o Groq)
para enriquecer alertas de seguridad con análisis MITRE ATT&CK.
"""
import os
import sys
import time
import argparse
import pathlib
import requests
import urllib3
from dotenv import load_dotenv

# =====================================================================
# CONFIGURACIÓN INICIAL
# =====================================================================

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Carga .env desde el directorio raíz del paquete (Codigo/) independientemente
# del directorio desde el que se ejecute el comando wazuh-ia
_env_path = pathlib.Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_env_path)

# --- Plano de Gestión (API Manager - Puerto 55000) ---
API_URL   = os.getenv('WZ_API_URL')
API_USER  = os.getenv('WZ_API_USER')
API_PASS  = os.getenv('WZ_API_PASS')

# --- Plano de Datos (Indexer / OpenSearch - Puerto 9200) ---
INDEXER_URL  = os.getenv('WZ_INDEXER_URL')
INDEXER_USER = os.getenv('WZ_INDEXER_USER')
INDEXER_PASS = os.getenv('WZ_INDEXER_PASS')

# IPs protegidas: el guardrail NUNCA las dejará bloquear
LISTA_BLANCA_IPS = [
    "127.0.0.1", "::1", "0.0.0.0",
    os.getenv('WZ_MANAGER_IP', '127.0.0.1')
]

# Modelo por defecto para cada proveedor
MODELOS_DEFAULT = {
    "ollama": os.getenv("WZ_MODELO", "llama3.2"),
    "gemini": "gemini-2.0-flash",
    "groq":   "llama-3.3-70b-versatile",
}


# =====================================================================
# GUARDRAIL DE SEGURIDAD
# =====================================================================

def validar_respuesta_ia(texto_respuesta: str) -> str:
    """
    Analiza solo la sección de respuesta activa del informe para detectar
    si la IA sugiere bloquear IPs críticas. Evita falsos positivos causados
    por IPs que aparecen en el full_log pero no en las recomendaciones.
    """
    # Buscamos la sección de Respuesta Activa en el informe del LLM
    seccion_respuesta = texto_respuesta
    marcadores = ["PLAN DE RESPUESTA", "RESPUESTA ACTIVA", "TRIAJE", "iptables", "firewall-cmd"]
    for marcador in marcadores:
        idx = texto_respuesta.upper().find(marcador.upper())
        if idx != -1:
            # Recortamos desde el marcador para analizar solo la sección relevante
            seccion_respuesta = texto_respuesta[idx:]
            break

    # Analizamos la sección de Respuesta Activa para detectar sugerencias de bloqueo de IPs protegidas
    riesgos = []
    palabras_bloqueo = ['iptables', 'firewall-cmd', 'ufw deny', 'ufw block', 'bloquear', '-j DROP', '-j REJECT']
    for ip in LISTA_BLANCA_IPS:
        if ip in seccion_respuesta:
            if any(cmd in seccion_respuesta.lower() for cmd in palabras_bloqueo):
                riesgos.append(ip)

    # Si se detectan riesgos, añadimos un aviso al final del informe y marcamos la sección como inválida
    if riesgos:
        aviso = (
            f"\n{'='*70}\n"
            f"[!] GUARDRAIL ACTIVADO: La IA sugirió bloquear IPs protegidas: {riesgos}\n"
            f"[!] Esas sugerencias han sido marcadas como INVÁLIDAS. No ejecutar.\n"
            f"{'='*70}"
        )
        return texto_respuesta + aviso

    return texto_respuesta


# =====================================================================
# CONEXIÓN CON WAZUH — PLANO DE GESTIÓN
# =====================================================================

def obtener_token() -> str | None:
    """
    Autenticación JWT en la API de Wazuh (puerto 55000).
    Devuelve el token o None si falla.
    """
    url = f"{API_URL}/security/user/authenticate"
    try:
        r = requests.get(url, auth=(API_USER, API_PASS), verify=False, timeout=10)
        if r.status_code == 200:
            return r.json().get('data', {}).get('token')
        print(f"[!] Login fallido en API de Gestión. Status: {r.status_code}")
        return None
    except requests.exceptions.ConnectionError:
        print(f"[-] No se puede conectar a la API de Gestión ({API_URL}). Comprueba que esté levantado y accesible.")
        return None
    except Exception as e:
        print(f"[-] Error inesperado en login: {e}")
        return None


# =====================================================================
# CONEXIÓN CON WAZUH — PLANO DE DATOS
# =====================================================================

def obtener_alertas_del_indexer(n_alertas: int = 5, nivel_minimo: int = 5) -> list:
    """
    Devuelve una lista de N alertas del Indexer con nivel >= nivel_minimo,
    ordenadas por timestamp descendente.
    """
    query = {
        "size": n_alertas,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"range": {"rule.level": {"gte": nivel_minimo}}}
    }
    try:
        response = requests.post(
            INDEXER_URL,
            auth=(INDEXER_USER, INDEXER_PASS),
            json=query,
            verify=False,
            timeout=10
        )
        if response.status_code == 200:
            hits = response.json().get('hits', {}).get('hits', [])
            return [h['_source'] for h in hits]

        print(f"[!] Error al consultar el Indexer. Status: {response.status_code}")
        return []

    except requests.exceptions.ConnectionError:
        print(f"[-] No se puede conectar al Indexer ({INDEXER_URL}). Comprueba que esté levantado y accesible.")
        return []
    except Exception as e:
        print(f"[!] Error inesperado consultando el Indexer: {e}")
        return []


# =====================================================================
# MOTORES LLM — BACKENDS POR PROVEEDOR
# =====================================================================

def _consultar_ollama(prompt: str, modelo: str) -> str:
    """
    Envía el prompt al servidor Ollama local y devuelve la respuesta.
    Timeout de 180s porque los LLMs locales pueden ser lentos.
    """
    payload = {"model": modelo, "prompt": prompt, "stream": False}
    try:
        response = requests.post(os.getenv("WZ_OLLAMA_URL"), json=payload, timeout=180)
        ai_output = response.json().get("response", "[Sin respuesta del modelo]")
        return validar_respuesta_ia(ai_output)
    except requests.exceptions.Timeout:
        return "[-] Timeout: el modelo tardó más de 180s. Prueba con un modelo más ligero."
    except requests.exceptions.ConnectionError:
        return f"[-] No se puede conectar a Ollama ({os.getenv('WZ_OLLAMA_URL')}). ¿Está el servicio activo?"
    except Exception as e:
        return f"[-] Error inesperado comunicándose con Ollama: {e}"


def _consultar_gemini(prompt: str, modelo: str) -> str:
    """Envía el prompt a la API de Gemini (Google) y devuelve la respuesta."""
    try:
        from google import genai
    except ImportError:
        return "[-] Paquete 'google-genai' no instalado. Ejecuta: pip install google-genai"

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return "[-] GEMINI_API_KEY no configurada en .env"

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(model=modelo, contents=prompt)
        return validar_respuesta_ia(response.text)
    except Exception as e:
        return f"[-] Error consultando Gemini ({modelo}): {e}"


def _consultar_groq(prompt: str, modelo: str) -> str:
    """Envía el prompt a la API de Groq y devuelve la respuesta. Usa el cliente OpenAI con base URL de Groq."""
    try:
        from openai import OpenAI
    except ImportError:
        return "[-] Paquete 'openai' no instalado. Ejecuta: pip install openai"

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return "[-] GROQ_API_KEY no configurada en .env"

    try:
        client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
        response = client.chat.completions.create(
            model=modelo,
            messages=[{"role": "user", "content": prompt}]
        )
        texto = response.choices[0].message.content
        return validar_respuesta_ia(texto)
    except Exception as e:
        return f"[-] Error consultando Groq ({modelo}): {e}"


def consultar_llm(prompt: str, proveedor: str = "ollama", modelo: str | None = None) -> tuple[str, float]:
    """
    Despacha el prompt al proveedor indicado y devuelve (respuesta, segundos).
    Proveedores disponibles: ollama, gemini, groq.
    """
    modelo_efectivo = modelo or MODELOS_DEFAULT.get(proveedor, proveedor)
    inicio = time.time()

    if proveedor == "ollama":
        respuesta = _consultar_ollama(prompt, modelo_efectivo)
    elif proveedor == "gemini":
        respuesta = _consultar_gemini(prompt, modelo_efectivo)
    elif proveedor == "groq":
        respuesta = _consultar_groq(prompt, modelo_efectivo)
    else:
        respuesta = f"[-] Proveedor no reconocido: '{proveedor}'. Opciones: ollama, gemini, groq"

    return respuesta, round(time.time() - inicio, 2)


# =====================================================================
# CONSTRUCCIÓN DEL PROMPT
# =====================================================================

def construir_prompt_mitre(alerta: dict) -> str:
    """
    Extrae los campos relevantes de la alerta Wazuh e inyecta los valores
    en la plantilla mitre_prompt.txt.
    """
    rule        = alerta.get("rule", {})
    descripcion = rule.get("description", "Desconocida")
    nivel       = rule.get("level", 0)
    rule_id     = rule.get("id", "N/A")
    agente      = alerta.get("agent", {}).get("name", "Desconocido")

    mitre    = rule.get("mitre", {})
    m_id     = mitre.get("id", ["N/A"])
    m_tactic = mitre.get("tactic", ["N/A"])
    m_id     = ", ".join(m_id)     if isinstance(m_id, list) else str(m_id)
    m_tactic = ", ".join(m_tactic) if isinstance(m_tactic, list) else str(m_tactic)

    data     = alerta.get("data", {})
    src_ip   = data.get("srcip", "No registrada")
    usuario  = data.get("srcuser", data.get("dstuser", data.get("user", "No registrado")))

    full_log = alerta.get("full_log", "No disponible")

    prompt_path = os.getenv("WZ_PROMPT_PATH", "prompts/mitre_prompt.txt")
    try:
        with open(prompt_path, "r", encoding="utf-8") as f:
            template = f.read()

        return template.format(
            agente=agente, nivel=nivel, descripcion=descripcion,
            rule_id=rule_id, mitre_id=m_id, mitre_tactic=m_tactic,
            src_ip=src_ip, usuario=usuario, full_log=full_log
        )
    except FileNotFoundError:
        print(f"[-] Archivo de prompt no encontrado: {prompt_path}. Usando prompt de emergencia.")
        return (
            f"Eres un analista SOC. Analiza esta alerta de Wazuh:\n"
            f"Descripción: {descripcion}\nNivel: {nivel}\nAgente: {agente}\n"
            f"MITRE: {m_tactic} ({m_id})\nLog: {full_log}\n"
            f"Proporciona: resumen ejecutivo, análisis forense y 3 acciones de respuesta."
        )


# =====================================================================
# PIPELINE DE ANÁLISIS
# =====================================================================

def analizar_alerta(alerta: dict, proveedor: str = "ollama", modelo: str | None = None) -> tuple[str, float]:
    """
    Pipeline completo para una alerta: extrae contexto → construye prompt → consulta LLM.
    Devuelve (informe, segundos_de_inferencia).
    """
    nivel   = alerta.get("rule", {}).get("level", 0)
    agente  = alerta.get("agent", {}).get("name", "Desconocido")
    rule_id = alerta.get("rule", {}).get("id", "N/A")
    modelo_efectivo = modelo or MODELOS_DEFAULT.get(proveedor, proveedor)

    print(f"\n[IA] Procesando evento de nivel {nivel} en agente '{agente}' (Regla ID: {rule_id})...")
    print(f"[IA] Proveedor: {proveedor} | Modelo: {modelo_efectivo}")

    prompt = construir_prompt_mitre(alerta)
    return consultar_llm(prompt, proveedor, modelo)


# =====================================================================
# PUNTO DE ENTRADA PRINCIPAL
# =====================================================================

OPCIONES_PROVEEDOR = {"1": "ollama", "2": "gemini", "3": "groq"}


def seleccionar_proveedor() -> str:
    """Muestra un menú interactivo para elegir el proveedor LLM."""
    print("\nSelecciona el proveedor LLM:")
    print(f"  [1] Ollama  — {MODELOS_DEFAULT['ollama']} (local)")
    print(f"  [2] Gemini  — {MODELOS_DEFAULT['gemini']}")
    print(f"  [3] Groq    — {MODELOS_DEFAULT['groq']} (nube, open-source)")
    while True:
        opcion = input("\nOpción > ").strip()
        if opcion in OPCIONES_PROVEEDOR:
            return OPCIONES_PROVEEDOR[opcion]
        print("[!] Opción no válida. Escribe 1, 2 o 3.")


def parsear_argumentos():
    """Define los modos de ejecución disponibles via CLI."""
    parser = argparse.ArgumentParser(
        description="wazuh-ia: Middleware TFG para enriquecer alertas Wazuh con LLMs"
    )
    parser.add_argument(
        '--alertas', type=int, default=1, metavar='N',
        help='Número de alertas a analizar (por defecto: 1)'
    )
    parser.add_argument(
        '--nivel', type=int, default=5, metavar='NIVEL',
        help='Nivel mínimo de alerta a procesar (por defecto: 5)'
    )
    parser.add_argument(
        '--proveedor', type=str, default=None,
        choices=['ollama', 'gemini', 'groq'],
        help='Proveedor LLM (si no se indica, se pregunta interactivamente)'
    )
    parser.add_argument(
        '--hunting', action='store_true',
        help='Activa el modo de consultas en lenguaje natural (Threat Hunting)'
    )
    parser.add_argument(
        '--respuesta-activa', action='store_true',
        help='Activa el módulo de Respuesta Activa (requiere confirmación humana)'
    )
    return parser.parse_args()


def main():
    args = parsear_argumentos()
    proveedor = args.proveedor or seleccionar_proveedor()
    modelo_efectivo = MODELOS_DEFAULT.get(proveedor, proveedor)

    print("=" * 70)
    print("  Middleware TFG — Wazuh + LLM  |  Arquitectura SOC")
    print(f"  Proveedor: {proveedor} | Modelo: {modelo_efectivo}")
    print("=" * 70)

    # --- Paso 1: Conectar a la API de Gestión ---
    token = obtener_token()
    if token:
        print("[✓] API de Gestión (Puerto 55000): conectado.")
    else:
        print("[!] API de Gestión inaccesible — modo solo lectura.")

    # --- Paso 2: Modo Threat Hunting — delega en threat_hunting.py ---
    if args.hunting:
        from wazuh_llm.threat_hunting import iniciar_modo_hunting
        iniciar_modo_hunting()
        return

    # --- Paso 3: Obtener alertas del Indexer ---
    print(f"[~] Buscando las {args.alertas} alertas más recientes con nivel >= {args.nivel}...")
    alertas = obtener_alertas_del_indexer(n_alertas=args.alertas, nivel_minimo=args.nivel)

    if not alertas:
        print(f"[-] No se encontraron alertas de nivel >= {args.nivel}. Prueba con --nivel 3.")
        sys.exit(0)

    print(f"[✓] {len(alertas)} alerta(s) capturada(s) del Indexer (Puerto 9200).")

    # --- Paso 4: Analizar cada alerta con el LLM ---
    resultados = []
    tiempos = []
    for i, alerta in enumerate(alertas, start=1):
        print(f"\n{'='*70}")
        print(f"  ALERTA {i}/{len(alertas)}  |  INFORME GENERADO POR LLM")
        print(f"{'='*70}")

        resultado, tiempo = analizar_alerta(alerta, proveedor)
        print(resultado)
        print(f"\n[⏱] Tiempo de inferencia: {tiempo:.2f}s")
        resultados.append(resultado)
        tiempos.append(tiempo)

    print(f"\n{'='*70}")
    print(f"[✓] Análisis completado. {len(alertas)} alerta(s) procesada(s).")
    if len(tiempos) > 1:
        print(f"[⏱] Tiempo total: {sum(tiempos):.2f}s | Media por alerta: {sum(tiempos)/len(tiempos):.2f}s")

    # --- Paso 5: Respuesta Activa — delega en respuesta_activa.py ---
    if args.respuesta_activa:
        from wazuh_llm.respuesta_activa import procesar_respuesta_activa
        for alerta, resultado in zip(alertas, resultados):
            procesar_respuesta_activa(token, alerta, resultado)


if __name__ == "__main__":
    main()
