import requests
import json
import urllib3

# Desactivamos los avisos de certificados SSL no seguros (Wazuh usa certificados auto-firmados)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURACIÓN DEL ENTORNO ---
# Apuntamos al Indexer (Puerto 9200) porque es donde Wazuh guarda el histórico de alertas
INDEXER_URL = "https://localhost:9200/wazuh-alerts-*/_search"
INDEXER_USER = "admin"
INDEXER_PASS = "SecretPassword" # Contraseña del Dashboard

# Configuración de la IA Local (Ollama)
OLLAMA_URL = "http://localhost:11434/api/generate"
MODELO = "llama3.2"  # Hemos cambiado a la versión 3.2 para ganar velocidad en el Mac M1

def obtener_alerta_del_indexer():
    """
    Se conecta a la base de datos OpenSearch (Indexer) de Wazuh
    y recupera la alerta más reciente que tenga un nivel de riesgo >= 7.
    """
    # Consulta en lenguaje DSL de OpenSearch
    query = {
        "size": 1, # Solo queremos la última alerta
        "sort": [{"timestamp": {"order": "desc"}}], # Ordenar por tiempo (más reciente primero)
        "query": {
            "range": {
                "rule.level": {"gte": 7} # Filtrar por nivel de riesgo 7 o superior
            }
        }
    }
    
    try:
        # Realizamos la petición POST con autenticación básica
        response = requests.post(
            INDEXER_URL,
            auth=(INDEXER_USER, INDEXER_PASS),
            json=query,
            verify=False, # Ignorar validación SSL
            timeout=10
        )
        if response.status_code == 200:
            hits = response.json().get('hits', {}).get('hits', [])
            if hits:
                return hits[0]['_source'] # Devolvemos el cuerpo de la alerta original
        return None
    except Exception as e:
        print(f"Error conectando al Indexer: {e}")
        return None

def consultar_llama3(prompt):
    """
    Envía un texto (prompt) a Ollama y espera la respuesta del modelo Llama 3.2.
    """
    payload = {
        "model": MODELO, 
        "prompt": prompt, 
        "stream": False # Esperamos a que la respuesta esté completa antes de recibirla
    }
    try:
        # Mantenemos un timeout alto por si el Mac está saturado con Wazuh
        response = requests.post(OLLAMA_URL, json=payload, timeout=180)
        return response.json().get("response", "Sin respuesta de la IA.")
    except Exception as e:
        return f"Error con Ollama: {e}"

def analizar_con_ia(alerta):
    """
    Toma los datos técnicos de Wazuh y construye un contexto para que la IA
    actúe como un analista de seguridad (SOC).
    """
    # Extraemos campos clave de la alerta de Wazuh
    descripcion = alerta.get("rule", {}).get("description", "Alerta desconocida")
    nivel = alerta.get("rule", {}).get("level", 0)
    agente = alerta.get("agent", {}).get("name", "Desconocido")
    
    # Creamos el 'Prompt' para la IA con técnicas avanzadas (Rol, Tarea, Formato)
    prompt = f"""
    Actúa como un Analista de Seguridad (SOC) Nivel 2 experto en respuesta a incidentes. 
    Tu objetivo es interpretar la siguiente telemetría del SIEM Wazuh y facilitar su triaje.
    
    DATOS DE LA ALERTA:
    - Agente afectado: {agente}
    - Nivel de Criticidad (0-15): {nivel}
    - Descripción del evento: {descripcion}
    
    TAREA:
    Analiza la alerta y genera un informe de incidente estructurado. No inventes datos que no estén en la descripción. 
    Tu respuesta debe tener exactamente este formato:
    
    **1. Resumen Ejecutivo:** (Explica en una oración clara qué ha ocurrido)
    **2. Tipología de la Amenaza:** (Clasifica el ataque. Ej: Fuerza Bruta, Malware, Escalada de Privilegios, etc.)
    **3. Evaluación de Riesgo:** (Explica por qué un nivel {nivel} es importante en este contexto)
    **4. Acciones Recomendadas:** (Sugiere 2 pasos técnicos inmediatos para mitigar o investigar la amenaza)
    """
    
    print(f"\n[IA] Analizando evento de nivel {nivel} en el agente: {agente}...")
    return consultar_llama3(prompt)

# --- BLOQUE PRINCIPAL DE EJECUCIÓN ---
if __name__ == "__main__":
    print(f"Iniciando Middleware TFG con el modelo: {MODELO}")
    
    # 1. Buscamos datos en la base de datos de Wazuh
    alerta = obtener_alerta_del_indexer()
    
    if alerta:
        # 2. Si hay alerta, la procesamos con la IA
        analisis = analizar_con_ia(alerta)
        print("\n" + "="*50) 
        print("RESULTADO DEL ANÁLISIS INTELIGENTE (FASE 1)")
        print("="*50)
        print(analisis) 
    else:
        print("No se han encontrado alertas relevantes en el Indexer.")