#!/usr/bin/env python3
import os
import requests
import urllib3
from dotenv import load_dotenv

# =====================================================================
# CONFIGURACIÓN INICIAL
# =====================================================================

# Wazuh utiliza certificados SSL auto-firmados. Desactivamos las advertencias 
# de urllib3 para evitar que la consola se llene de mensajes de error de seguridad.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Cargamos las variables de entorno desde el archivo .env
load_dotenv()

# ---  1: API DE GESTIÓN (Plano de Control - Puerto 55000) ---
# Se utiliza para acciones de gestión, como obtener tokens o (en el futuro) lanzar bloqueos.
API_URL = os.getenv('WZ_API_URL')
API_USER = os.getenv('WZ_API_USER')
API_PASS = os.getenv('WZ_API_PASS')

# ---  2: INDEXER (Plano de Datos - Puerto 9200) ---
# Se utiliza exclusivamente para obtener datos. Es la base de datos
# donde OpenSearch almacena el histórico de alertas forenses.
INDEXER_URL = os.getenv('WZ_INDEXER_URL')
INDEXER_USER = os.getenv('WZ_INDEXER_USER')
INDEXER_PASS = os.getenv('WZ_INDEXER_PASS')

# Lista de IPs protegidas que NUNCA deben ser bloqueadas (Guardrail)
# Esto responde a las carencias de seguridad detectadas en la investigación del TFG.
LISTA_BLANCA_IPS = ["127.0.0.1", "::1", "0.0.0.0", os.getenv('WZ_MANAGER_IP', '127.0.0.1')]

# =====================================================================
# FUNCIONES DE SEGURIDAD Y VALIDACIÓN DE RESPUESTAS DE LA IA
# =====================================================================

def validar_respuesta_ia(texto_respuesta):
    """
    Analiza la salida de la IA para detectar si sugiere bloquear IPs críticas.
    Sirve para mitigar alucinaciones de seguridad.
    """
    riesgos_detectados = []
    for ip in LISTA_BLANCA_IPS:
        if ip in texto_respuesta:
            # Palabras clave que indican una acción de bloqueo
            palabras_riesgo = ['block', 'iptables', 'deny', 'drop', 'bloquear', 'firewall']
            if any(palabra in texto_respuesta.lower() for palabra in palabras_riesgo):
                riesgos_detectados.append(ip)
    
    if riesgos_detectados:
        aviso = f"\n[!] CONTROL DE SEGURIDAD ACTIVADO: La IA sugirió bloquear IPs críticas: {riesgos_detectados}."
        aviso += "\n[!] Acción neutralizada automáticamente por el middleware para evitar pérdida de acceso."
        return texto_respuesta + "\n" + "="*70 + aviso
    return texto_respuesta

# =====================================================================
# FUNCIONES DE CONEXIÓN CON WAZUH
# =====================================================================

def obtener_token():
    """
    Autenticación en la API RESTful de Wazuh.
    Genera un Token válido para futuras peticiones autorizadas.
    """
    url = f"{API_URL}/security/user/authenticate"
    try:
        # Petición GET. Verify=False es necesario por los certificados auto-firmados de Docker.
        r = requests.get(url, auth=(API_USER, API_PASS), verify=False, timeout=10)
        # Extraemos el string del token de la estructura JSON de respuesta.
        return r.json().get('data', {}).get('token') if r.status_code == 200 else None
    except Exception as e:
        print(f"[-] Error crítico de login en la API: {e}")
        return None

def obtener_alerta_del_indexer():
    """
    Realiza una consulta DSL directa a OpenSearch.
    Extrae la última alerta registrada con nivel >= 5.
    """
    # Consulta optimizada: 1 resultado, orden descendente, nivel >= 5
    query = {
        "size": 1,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": { "range": { "rule.level": {"gte": 7} } } 
    }
    try:
        # Petición POST
        response = requests.post(
            INDEXER_URL,
            auth=(INDEXER_USER, INDEXER_PASS),
            json=query,
            verify=False,
            timeout=10
        )
        if response.status_code == 200:
            # El Indexer devuelve los datos en un árbol jerárquico. 
            # Accedemos al segundo nivel de 'hits' para obtener el array de documentos encontrados.
            data = response.json().get('hits', {}).get('hits', [])
            
            # Extraemos el campo '_source', que contiene el cuerpo de la alerta de Wazuh,
            # garantizando que existan resultados antes de intentar acceder al índice 0.
            return data[0]['_source'] if data else None
        return None
    except Exception as e:
        print(f"[!] Error de conexión consultando el Indexer: {e}")
        return None


# =====================================================================
# FUNCIONES DE INTELIGENCIA ARTIFICIAL
# =====================================================================

def consultar_llama3(prompt):
    """
    Orquesta la petición HTTP POST hacia el servidor local de IA (Ollama).
    Envía el contexto estructurado y devuelve la respuesta en texto plano.
    """
    # Construimos el payload con el modelo, el prompt y la configuración de streaming
    payload = {
        "model": os.getenv("WZ_MODELO"),
        "prompt": prompt,
        "stream": False # False obliga a esperar a que la IA genere toda la respuesta antes de devolverla.
    }
    try:
        # Timeout alto (180s) las LLMs pueden tardar en generar respuestas complejas
        response = requests.post(os.getenv("WZ_OLLAMA_URL"), json=payload, timeout=180)
        ai_output = response.json().get("response", "No response from AI.")
        # Antes de devolver la respuesta, pasamos el texto por la función de validación para detectar posibles riesgos
        return validar_respuesta_ia(ai_output)
        
    except Exception as e:
        return f"[-] Error de comunicación con el motor LLM (Ollama): {e}"

def analizar_con_ia_mitre(alerta):
    """
    Motor de Prompt Engineering.
    Extrae telemetría cruda de Wazuh, la sanea y la inyecta en una plantilla (Template)
    para dotar de contexto forense a la IA.
    """
    # 1. Extracción segura de metadatos básicos, get() evita errores si un campo no existe
    descripcion = alerta.get("rule", {}).get("description", "Desconocida")
    nivel = alerta.get("rule", {}).get("level", 0)
    agente = alerta.get("agent", {}).get("name", "Desconocido")
    rule_id = alerta.get("rule", {}).get("id", "N/A")

    # 2. Extracción de Tácticas y Técnicas MITRE ATT&CK
    mitre = alerta.get("rule", {}).get("mitre", {})
    # Wazuh puede devolver listas o strings, por eso manejamos ambos casos con lógica condicional
    m_id = ", ".join(mitre.get("id", ["N/A"])) if isinstance(mitre.get("id"), list) else mitre.get("id", "N/A")
    m_tactic = ", ".join(mitre.get("tactic", ["N/A"])) if isinstance(mitre.get("tactic"), list) else mitre.get("tactic", "N/A")

    # 3. Extracción de datos de red e identidades
    data = alerta.get("data", {})
    src_ip = data.get("srcip", "No registrada")
    # Otros posibles campos de usuario
    usuario = data.get("srcuser", data.get("dstuser", data.get("user", "No registrado")))

    # 4. Extracción del log completo para análisis forense detallado
    full_log = alerta.get("full_log", "No disponible")

    # 5. Construcción del Prompt con plantilla externa
    try:
        # Leemos el template del prompt desde un archivo de texto
        with open(os.getenv("WZ_PROMPT_PATH"), "r", encoding="utf-8") as f:
            template = f.read()
        
        # Formateamos el string inyectando nuestras variables extraídas
        prompt = template.format(
            agente=agente,
            nivel=nivel,
            descripcion=descripcion,
            rule_id=rule_id,
            mitre_id=m_id,
            mitre_tactic=m_tactic,
            src_ip=src_ip,
            usuario=usuario,
            full_log=full_log
        )
    except Exception as e:
        print(f"[-] Error cargando el archivo prompt.txt: {e}. Usando prompt de emergencia por defecto.")
        prompt = f"Analiza esta alerta de seguridad: {descripcion}. Log forense: {full_log}"

    print(f"\n[IA] Procesando evento de nivel {nivel} en agente '{agente}' (Regla ID: {rule_id})...")
    
    # 6. Llamada a la IA
    return consultar_llama3(prompt)


# =====================================================================
# BLOQUE DE EJECUCIÓN PRINCIPAL (ORQUESTADOR)
# =====================================================================

def main():
    print("--- Middleware TFG: Arquitectura SOC (Fase de Análisis Forense) ---")

    # FASE 1: Comprobación de estado de la API
    token = obtener_token()
    if token:
        print("[✓] Conectado a la API de Gestión (Puerto 55000) - Preparado para futuras acciones.")
    else:
        print("[!] Aviso: API de Gestión inaccesible. El sistema operará en modo de solo lectura.")

    # FASE 2: Obtención de la última alerta forense desde el Indexer
    alerta = obtener_alerta_del_indexer()

    # FASE 3: Análisis de la alerta con IA y generación de informe táctico
    if alerta:
        print(f"[✓] Alerta forense capturada desde el Indexer (Puerto 9200).")
        
        # Invocamos la función de análisis con IA, que a su vez llama a la función de consulta a Ollama.
        resultado = analizar_con_ia_mitre(alerta)
        
        # Mostramos el resultado en la consola con formato destacado
        print("\n" + "="*70)
        print("INFORME DE INTELIGENCIA TÁCTICA GENERADO POR LLM")
        print("="*70)
        print(resultado)
        print("="*70 + "\n")
    else:
        print("[-] El Indexer no reporta alertas recientes de nivel 5 o superior.")

# Punto de entrada del script
if __name__ == "__main__":
    main()