import requests
import json
import urllib3

# Wazuh utiliza certificados SSL auto-firmados por defecto. 
# Para evitar que Python lance advertencias de seguridad en la consola constantemente,
# desactivamos los avisos de InsecureRequestWarning.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =====================================================================
# CONFIGURACIÓN DEL ENTORNO Y COMUNICACIONES
# =====================================================================

# Configuración del Indexer de Wazuh (Motor OpenSearch subyacente)
# Apuntamos al puerto 9200 en lugar de la API (55000) para acceder directamente a la BBDD.
INDEXER_URL = "https://localhost:9200/wazuh-alerts-*/_search"
INDEXER_USER = "admin"
INDEXER_PASS = "SecretPassword" # Contraseña por defecto del entorno Docker

# Configuración del LLM Local (Ollama)
OLLAMA_URL = "http://localhost:11434/api/generate"
MODELO = "llama3.2" # Elegimos la versión 3B para no saturar la memoria unificada del Mac

# =====================================================================
# FUNCIONES PRINCIPALES
# =====================================================================

def obtener_alerta_del_indexer():
    """
    Realiza una consulta DSL (Domain Specific Language) a OpenSearch para extraer 
    la última alerta de seguridad crítica registrada por Wazuh.
    
    Returns:
        dict: Un diccionario JSON con los datos de la alerta si tiene éxito, None en caso de error.
    """
    # Construcción de la consulta (Query)
    query = {
        "size": 1, # Límite de resultados: solo queremos procesar 1 alerta a la vez
        "sort": [{"timestamp": {"order": "desc"}}], # Ordenación cronológica inversa (la más reciente primero)
        "query": { 
            "range": { 
                "rule.level": {"gte": 7} # Filtro de criticidad: 'gte' significa Greater Than or Equal (>= 7)
            } 
        }
    }
    
    try:
        # Petición HTTP POST al Indexer
        response = requests.post(
            INDEXER_URL, 
            auth=(INDEXER_USER, INDEXER_PASS), 
            json=query, 
            verify=False, # Imprescindible al usar certificados auto-firmados
            timeout=10    # Límite de espera de 10 segundos para no bloquear el hilo principal
        )
        
        # Verificamos si el servidor respondió correctamente (Código 200 OK)
        if response.status_code == 200:
            # Navegamos por el árbol del JSON de respuesta de OpenSearch: hits -> hits -> array
            hits = response.json().get('hits', {}).get('hits', [])
            if hits:
                return hits[0]['_source'] # '_source' contiene el cuerpo real de la alerta de Wazuh
        return None
        
    except Exception as e:
        print(f"[-] Error de conexión con el Indexer de Wazuh: {e}")
        return None


def consultar_llama3(prompt):
    """
    Envía el contexto estructurado al modelo LLM local a través de la API de Ollama.
    
    Args:
        prompt (str): Las instrucciones y datos que procesará la IA.
        
    Returns:
        str: El texto generado por la IA o un mensaje de error.
    """
    # Preparamos el paquete de datos (Payload) para Ollama
    payload = {
        "model": MODELO, 
        "prompt": prompt, 
        "stream": False # 'False' fuerza a la IA a devolver la respuesta completa de golpe, no palabra por palabra
    }
    
    try:
        # Petición HTTP POST a Ollama. 
        # Timeout alto (180s) porque la inferencia del modelo consume CPU/GPU y puede tardar.
        response = requests.post(OLLAMA_URL, json=payload, timeout=180)
        # Extraemos solo el campo "response" del JSON que devuelve Ollama
        return response.json().get("response", "Sin respuesta de la IA.")
        
    except Exception as e:
        return f"[-] Error de comunicación con Ollama: {e}"


def analizar_con_ia_mitre(alerta):
    """
    Actúa como el motor de inteligencia del middleware. Extrae los metadatos de la alerta,
    aplica lógica de limpieza y construye un prompt avanzado (Prompt Engineering) para el LLM.
    """
    # 1. Extracción segura de campos (usamos .get() para evitar caídas si un campo no existe)
    descripcion = alerta.get("rule", {}).get("description", "Desconocida")
    nivel = alerta.get("rule", {}).get("level", 0)
    agente = alerta.get("agent", {}).get("name", "Desconocido")
    
    # 2. Extracción y saneamiento de datos MITRE ATT&CK
    mitre_data = alerta.get("rule", {}).get("mitre", {})
    
    # Wazuh puede devolver el ID de MITRE como un String ("T1110") o como una Lista (["T1110", "T1078"]).
    # Esta línea verifica si es una lista y, de ser así, la convierte en un texto separado por comas.
    mitre_id = ", ".join(mitre_data.get("id", ["N/A"])) if isinstance(mitre_data.get("id"), list) else mitre_data.get("id", "N/A")
    mitre_tactic = ", ".join(mitre_data.get("tactic", ["N/A"])) if isinstance(mitre_data.get("tactic"), list) else mitre_data.get("tactic", "N/A")
    
    # 3. Diseño del Prompt (Prompt Engineering)
    # Se utiliza asignación de rol (CTI Analyst), contexto estricto y delimitación de formato de salida.
    prompt = f"""
    Actúa como un Analista Experto en Threat Intelligence (CTI). Tu objetivo es contextualizar 
    esta alerta de seguridad basándote estrictamente en el framework MITRE ATT&CK y la Cyber Kill Chain.
    
    DATOS TÉCNICOS EXTRAÍDOS DE WAZUH:
    - Objetivo Afectado: {agente}
    - Gravedad (0-15): {nivel}
    - Descripción Técnica: {descripcion}
    - MITRE ATT&CK ID: {mitre_id}
    - Táctica MITRE Reportada: {mitre_tactic}
    
    TAREA:
    Genera un informe táctico conciso estructurado exactamente con estos 4 puntos. No inventes información.
    
    **1. Mapeo de la Técnica (MITRE ATT&CK):** (Explica brevemente qué es la técnica {mitre_id} y cómo encaja en la táctica de {mitre_tactic}).
    **2. Ubicación en la Cyber Kill Chain:** (Infiere en qué fase de la Cyber Kill Chain se encuentra el adversario basándote en la técnica empleada. Sé preciso).
    **3. Inferencia de Objetivos:** (Deduce qué intenta conseguir el atacante específicamente en el equipo {agente} al usar este método).
    **4. Predicción del Siguiente Paso:** (Basado en el comportamiento habitual de los atacantes, ¿cuál podría ser su próximo movimiento si esta fase tiene éxito?).
    """
    
    # Feedback visual en la consola para saber en qué fase se encuentra el script
    print(f"\n[IA] Correlacionando alerta con MITRE ATT&CK (ID: {mitre_id})...")
    return consultar_llama3(prompt)

# =====================================================================
# BLOQUE DE EJECUCIÓN PRINCIPAL
# =====================================================================

# Este bloque solo se ejecuta si el script se llama directamente (no si se importa desde otro archivo)
if __name__ == "__main__":
    print(f"Iniciando Middleware TFG - Fase de Correlación MITRE")
    
    # Paso 1: Recuperar telemetría
    alerta = obtener_alerta_del_indexer()
    
    if alerta:
        # Paso 2: Procesamiento cognitivo
        analisis = analizar_con_ia_mitre(alerta)
        
        # Paso 3: Renderizado de la salida
        print("\n" + "="*60) 
        print