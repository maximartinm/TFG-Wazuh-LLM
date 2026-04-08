import requests
import json

# Configuración de Ollama (donde vive Llama 3 en tu Mac)
OLLAMA_URL = "http://localhost:11434/api/generate"
MODELO = "llama3"

def consultar_llama3(prompt):
    """Envía una consulta a la API local de Ollama"""
    payload = {
        "model": MODELO,
        "prompt": prompt,
        "stream": False
    }
    try:
        response = requests.post(OLLAMA_URL, json=payload)
        return response.json().get("response", "No hubo respuesta de la IA.")
    except Exception as e:
        return f"Error conectando con Ollama: {e}"

def procesar_alerta_wazuh(alerta_json):
    """
    Simula la recepción de una alerta y genera un resumen inteligente.
    Implementa la 'Transformación de alertas' de la Fase 1 del TFG.
    """
    
    # Extraemos datos clave (como hace remove-threat.py)
    rule_id = alerta_json.get("rule", {}).get("id", "Desconocida")
    description = alerta_json.get("rule", {}).get("description", "Sin descripción")
    agent_name = alerta_json.get("agent", {}).get("name", "Desconocido")
    
    # Verificamos si hay malware detectado por VirusTotal (visto en remove-threat.py)
    vt_file = alerta_json.get("data", {}).get("virustotal", {}).get("source", {}).get("file", None)

    # Construimos el Prompt para la Fase 1 y 2
    prompt_base = f"""
    Eres un experto en ciberseguridad (Analista SOC Nivel 2). 
    He recibido la siguiente alerta de Wazuh:
    - Agente afectado: {agent_name}
    - ID de Regla: {rule_id}
    - Descripción: {description}
    """
    
    if vt_file:
        prompt_base += f"\n- AMENAZA DETECTADA: El archivo {vt_file} ha sido marcado por VirusTotal."
        prompt_base += "\n\nTAREA: Explica qué riesgo supone esto y menciona que se puede usar el script 'remove-threat.py' para eliminarlo."
    else:
        prompt_base += "\n\nTAREA: Resume esta alerta de forma sencilla y dime si es peligrosa."

    print("--- Enviando a Llama 3 ---")
    analisis = consultar_llama3(prompt_base)
    return analisis

# --- SIMULACIÓN DE PRUEBA ---
# Esta es una alerta JSON típica como la que recibiría tu TFG
alerta_ejemplo = {
    "agent": {"name": "ubuntu-mv"},
    "rule": {"id": "1002", "description": "VirusTotal: Alert - Malware detected"},
    "data": {
        "virustotal": {
            "source": {
                "file": "/home/ubuntu/descargas/virus_de_prueba.exe"
            }
        }
    }
}

if __name__ == "__main__":
    resultado = procesar_alerta_wazuh(alerta_ejemplo)
    print("\n### ANÁLISIS DE LA IA ###")
    print(resultado)