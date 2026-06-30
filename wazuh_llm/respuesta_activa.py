#!/usr/bin/env python3
"""
respuesta_activa.py — Fase 3 del TFG
Módulo de Respuesta Activa: el LLM sugiere bloqueos, el analista aprueba o rechaza.
Implementa el patrón "Human-in-the-Loop" para evitar acciones automáticas peligrosas.

Integración con la API de Wazuh (puerto 55000) para ejecutar active-response.
"""
import re
import os
import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

API_URL  = os.getenv('WZ_API_URL')

# IPs que el sistema NUNCA bloqueará aunque el analista lo confirme
LISTA_BLANCA_IPS = [
    "127.0.0.1", "::1", "0.0.0.0",
    os.getenv('WZ_MANAGER_IP', '127.0.0.1')
]


# =====================================================================
# EXTRACCIÓN DE IOCs DESDE EL INFORME DEL LLM
# =====================================================================

def extraer_ips_del_informe(texto_informe: str) -> list[str]:
    """
    Parsea el informe generado por el LLM y extrae las IPs que aparecen
    en la sección de Respuesta Activa como candidatas a bloqueo.

    No confiamos en que el LLM devuelva IPs en un formato estructurado,
    así que usamos regex para buscarlas en el texto libre.
    """
    # Regex para IPv4 estándar
    patron_ipv4 = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    todas_las_ips = re.findall(patron_ipv4, texto_informe)

    # Filtramos duplicados y loopback/reservadas
    ips_candidatas = []
    vistas = set()
    for ip in todas_las_ips:
        if ip not in vistas and ip not in LISTA_BLANCA_IPS:
            # Validación básica de rango (descarta 0.x.x.x y 255.x.x.x) porque no son IPs válidas para bloquear
            octetos = ip.split('.')
            if all(0 < int(o) < 255 for o in octetos):
                ips_candidatas.append(ip)
                vistas.add(ip)

    return ips_candidatas


# =====================================================================
# CONFIRMACIÓN HUMANA (HUMAN-IN-THE-LOOP)
# =====================================================================

def solicitar_confirmacion(accion: str, detalle: str) -> bool:
    """
    Muestra la acción propuesta y espera confirmación explícita del analista.
    El sistema NUNCA ejecuta acciones sin este paso.

    Args:
        accion:  Descripción de la acción (ej: "Bloquear IP").
        detalle: Parámetros específicos (ej: "192.168.1.100 en agente Ubuntu-Victima").

    Returns:
        True si el analista confirma, False en cualquier otro caso.
    """
    print(f"\n{'='*70}")
    print(f"  [RESPUESTA ACTIVA] Acción propuesta por el sistema:")
    print(f"  Acción : {accion}")
    print(f"  Detalle: {detalle}")
    print(f"{'='*70}")
    print("  Esta acción modificará la configuración del firewall del agente.")
    print("  Escribe 'CONFIRMAR' (en mayúsculas) para ejecutar, cualquier otra cosa cancela.")
    
    
    respuesta = input("\n  Tu decisión > ").strip()
    
    if respuesta == "CONFIRMAR":
        print("[✓] Acción confirmada por el analista.")
        return True
    else:
        print("[~] Acción cancelada.")
        return False


# =====================================================================
# EJECUCIÓN DE RESPUESTA ACTIVA VÍA API WAZUH
# =====================================================================

def bloquear_ip_en_agente(token: str, agent_id: str, ip_atacante: str) -> bool:
    """
    Ejecuta el comando de active-response de Wazuh para bloquear una IP
    en el firewall del agente especificado.

    Usa el endpoint POST /active-response de la API de Wazuh (puerto 55000).
    Requiere que el agente tenga configurado el active-response 'firewall-drop'
    en su ossec.conf (es el que viene por defecto en Wazuh).

    Args:
        token:       JWT obtenido previamente con obtener_token().
        agent_id:    ID del agente Wazuh (ej: "001").
        ip_atacante: IP a bloquear (ej: "45.33.32.156").

    Returns:
        True si la API acepta la orden, False si falla.
    """
    # Guardrail final: doble comprobación antes de llamar a la API
    if ip_atacante in LISTA_BLANCA_IPS:
        print(f"[!] GUARDRAIL: Intento de bloquear IP protegida {ip_atacante}. Operación cancelada.")
        return False

    url = f"{API_URL}/active-response?agents_list={agent_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    # firewall-drop es el comando de active-response estándar de Wazuh
    # que añade una regla iptables DROP para la IP indicada
    payload = {
        "command": "firewall-drop",
        "arguments": [ip_atacante],
        "alert": {
            "data": {"srcip": ip_atacante}
        }
    }

    # Ejecutamos la llamada a la API
    try:
        r = requests.put(url, headers=headers, json=payload, verify=False, timeout=15)
        if r.status_code in (200, 204):
            print(f"[✓] Orden enviada al agente {agent_id}: bloquear {ip_atacante}")
            print(f"    El agente ejecutará: iptables -A INPUT -s {ip_atacante} -j DROP")
            return True
        else:
            print(f"[-] La API rechazó la orden. Status: {r.status_code} — {r.text}")
            return False
    except Exception as e:
        print(f"[-] Error enviando active-response: {e}")
        return False


# =====================================================================
# ORQUESTADOR DE RESPUESTA ACTIVA
# =====================================================================

def procesar_respuesta_activa(token: str | None, alerta: dict, informe_llm: str):
    """
    Punto de entrada del módulo de Respuesta Activa.
    Flujo:
      1. Extrae IPs candidatas del informe del LLM
      2. Para cada IP, solicita confirmación humana
      3. Si se confirma, ejecuta el bloqueo via API de Wazuh
      4. Si no hay token (modo solo lectura), simula la acción

    Args:
        token:       JWT de Wazuh (puede ser None si la API está caída).
        alerta:      Dict con los datos de la alerta de Wazuh.
        informe_llm: Texto completo del informe generado por el LLM.
    """
    agent_id   = alerta.get("agent", {}).get("id", "000")
    agent_name = alerta.get("agent", {}).get("name", "Desconocido")

    print(f"\n{'='*70}")
    print("  MÓDULO DE RESPUESTA ACTIVA — Fase 3")
    print(f"  Agente objetivo: {agent_name} (ID: {agent_id})")
    print(f"{'='*70}")

    # 1. Extraer IPs del informe del LLM
    ips_candidatas = extraer_ips_del_informe(informe_llm)

    # También intentamos coger la IP directamente de la alerta para priorizarla, si no está en la lista blanca
    src_ip_alerta = alerta.get("data", {}).get("srcip")
    if src_ip_alerta and src_ip_alerta not in LISTA_BLANCA_IPS:
        if src_ip_alerta not in ips_candidatas:
            ips_candidatas.insert(0, src_ip_alerta)  # La IP de la alerta tiene prioridad

    if not ips_candidatas:
        print("[~] No se identificaron IPs externas candidatas a bloqueo en este informe.")
        return

    print(f"\n[~] IPs identificadas como candidatas a bloqueo: {ips_candidatas}")
    print("[~] Se requerirá confirmación manual para cada acción.")

    # 2. Iterar sobre cada IP candidata
    acciones_ejecutadas = 0
    for ip in ips_candidatas:
        confirmado = solicitar_confirmacion(
            accion="Bloquear IP entrante en el agente",
            detalle=f"IP: {ip} → Agente: {agent_name} (ID: {agent_id})"
        )

        if confirmado:
            if token:
                exito = bloquear_ip_en_agente(token, agent_id, ip)
                if exito:
                    acciones_ejecutadas += 1
            else:
                # Modo simulación: sin token no podemos llamar a la API
                print(f"[SIM] SIMULACIÓN: Se ejecutaría firewall-drop para {ip} en agente {agent_id}")
                print(f"[SIM] Comando equivalente: iptables -A INPUT -s {ip} -j DROP")
                acciones_ejecutadas += 1

    # 3. Resumen,
    print(f"\n[✓] Respuesta Activa completada: {acciones_ejecutadas}/{len(ips_candidatas)} acción(es) ejecutada(s).")
    if acciones_ejecutadas == 0:
        print("[~] No se ejecutó ninguna acción. El analista puede revisar y actuar manualmente.")