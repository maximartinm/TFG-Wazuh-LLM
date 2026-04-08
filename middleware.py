import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURACIÓN ---
INDEXER_URL = "https://localhost:9200/wazuh-alerts-*/_search"
INDEXER_USER = "admin"
INDEXER_PASS = "SecretPassword" 

OLLAMA_URL = "http://localhost:11434/api/generate"
MODELO = "llama3.2"

def obtener_alerta_del_indexer():
    query = {
        "size": 1,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": { "range": { "rule.level": {"gte": 7} } }
    }
    try:
        response = requests.post(INDEXER_URL, auth=(INDEXER_USER, INDEXER_PASS), json=query, verify=False, timeout=10)
        if response.status_code == 200:
            hits = response.json().get('hits', {}).get('hits', [])
            if hits:
                return hits[0]['_source']
        return None
    except Exception as e:
        print(f"Error conectando al Indexer: {e}")
        return None

def consultar_llama3(prompt):
    payload = {"model": MODELO, "prompt": prompt, "stream": False}
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=180)
        return response.json().get("response", "Sin respuesta.")
    except Exception as e:
        return f"Error con Ollama: {e}"

def analizar_con_ia_mitre(alerta):
    """
    Función mejorada para extraer datos de MITRE ATT&CK y enriquecer el análisis.
    """
    # 1. Extracción de datos básicos
    descripcion = alerta.get("rule", {}).get("description", "Desconocida")
    nivel = alerta.get("rule", {}).get("level", 0)
    agente = alerta.get("agent", {}).get("name", "Desconocido")
    
    # 2. Extracción de datos de MITRE (Aquí está la clave de tu TFG)
    mitre_data = alerta.get("rule", {}).get("mitre", {})
    mitre_id = mitre_data.get("id", ["N/A"]) # Puede ser una lista o un string
    mitre_tactic = mitre_data.get("tactic", ["N/A"])
    
    # 3. Construcción del Prompt "Inteligente"
    prompt = f"""
    Eres un analista de seguridad experto en el framework MITRE ATT&CK. 
    Analiza esta alerta de Wazuh:
    
    - Agente: {agente}
    - Evento: {descripcion}
    - Nivel de riesgo: {nivel}
    - Identificador MITRE: {mitre_id}
    - Táctica MITRE: {mitre_tactic}
    
    TAREA:
    1. Explica qué significa la técnica MITRE {mitre_id} en este contexto.
    2. ¿En qué etapa de la Cyber Kill Chain se encuentra el atacante?
    3. ¿Qué busca el atacante al usar esta técnica en {agente}?
    """
    
    print(f"\n[IA] Correlacionando alerta con MITRE ATT&CK...")
    return consultar_llama3(prompt)

if __name__ == "__main__":
    print(f"Iniciando Middleware TFG - Fase de Correlación MITRE")
    
    alerta = obtener_alerta_del_indexer()
    
    if alerta:
        analisis = analizar_con_ia_mitre(alerta)
        print("\n" + "="*60) 
        print("ANÁLISIS DE SEGURIDAD ENRIQUECIDO (MITRE ATT&CK)")
        print("="*60)
        print(analisis) 
    else:
        print("No se han encontrado alertas para analizar.")