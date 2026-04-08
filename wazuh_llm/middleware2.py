#!/usr/bin/env python3
import os
import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

# Variables globales cargadas desde .env
API_URL = os.getenv('WZ_API_URL')
API_USER = os.getenv('WZ_API_USER')
API_PASS = os.getenv('WZ_API_PASS')

def obtener_token():
    """Autenticación en la API para obtener el Token JWT."""
    url = f"{API_URL}/security/user/authenticate"
    try:
        r = requests.get(url, auth=(API_USER, API_PASS), verify=False, timeout=10)
        return r.json().get('data', {}).get('token') if r.status_code == 200 else None
    except Exception as e:
        print(f"[-] Error de login: {e}")
        return None

def obtener_alerta_de_api(token):
    """
    Sustituye al Indexer. Pide a la API la última alerta de nivel >= 7.
    """
    # Endpoint de la API para consultar alertas
    url = f"{API_URL}/alerts" 
    headers = {'Authorization': f'Bearer {token}'}
    # Parámetros de la API: 1 resultado, orden descendente por tiempo, nivel >= 7
    params = {
        'limit': 1,
        'sort': '-timestamp',
        'q': 'rule.level>=7' 
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, verify=False, timeout=15)
        if response.status_code == 200:
            data = response.json().get('data', {})
            items = data.get('affected_items', [])
            return items[0] if items else None
        return None
    except Exception as e:
        print(f"[-] Error consultando alertas en la API: {e}")
        return None
    

def consultar_llama3(prompt):
    """Envía el prompt a la IA local Ollama"""
    payload = {
        "model": os.getenv("WZ_MODELO"),
        "prompt": prompt,
        "stream": False
    }
    try:
        response = requests.post(os.getenv("WZ_OLLAMA_URL"), json=payload, timeout=180)
        return response.json().get("response", "Sin respuesta de la IA.")
    except Exception as e:
        return f"[-] Error con Ollama: {e}"

def analizar_con_ia_mitre(alerta):
    """Lógica de Prompt Engineering para MITRE ATT&CK"""
    # Extraemos datos
    descripcion = alerta.get("rule", {}).get("description", "Desconocida")
    nivel = alerta.get("rule", {}).get("level", 0)
    agente = alerta.get("agent", {}).get("name", "Desconocido")
    mitre = alerta.get("rule", {}).get("mitre", {})
    
    m_id = ", ".join(mitre.get("id", ["N/A"])) if isinstance(mitre.get("id"), list) else mitre.get("id", "N/A")
    m_tactic = ", ".join(mitre.get("tactic", ["N/A"])) if isinstance(mitre.get("tactic"), list) else mitre.get("tactic", "N/A")

    # Intentamos cargar el prompt desde el archivo TXT
    try:
        with open(os.getenv("WZ_PROMPT_PATH"), "r") as f:
            template = f.read()
        prompt = template.format(
            agente=agente, nivel=nivel, descripcion=descripcion, 
            mitre_id=m_id, mitre_tactic=m_tactic
        )
    except Exception as e:
        print(f"[-] Error cargando prompt.txt: {e}. Usando prompt de emergencia.")
        prompt = f"Analiza esta alerta: {descripcion}"

    print(f"\n[IA] Procesando evento nivel {nivel} en {agente}...")
    return consultar_llama3(prompt)

def main():
    print("--- Middleware TFG: Conexión Unificada por API ---")
    
    # 1. Obtenemos el Token (Llave maestra)
    token = obtener_token()
    if not token:
        print("[!] No se puede continuar sin acceso a la API.")
        return

    # 2. Pedimos la alerta a la API (usando el Token)
    alerta = obtener_alerta_de_api(token)
    
    if alerta:
        print(f"[✓] Alerta capturada vía API. ID de Regla: {alerta.get('rule', {}).get('id')}")
        # 3. Análisis con IA
        resultado = analizar_con_ia_mitre(alerta)
        print("\n" + "="*60 + "\n" + resultado + "\n" + "="*60)
    else:
        print("[-] No hay alertas nuevas en la API.")

if __name__ == "__main__":
    main()