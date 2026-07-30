#!/usr/bin/env python3
"""
3_Threat_Hunting.py — Consultas en lenguaje natural sobre el historial de alertas.
"""
import os
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from wazuh_llm.threat_hunting import nl_a_query_dsl, ejecutar_query, QueryError
from wazuh_llm.nav import render_navbar

load_dotenv()

st.set_page_config(
    page_title="Threat Hunting | Wazuh + LLM",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed",
)

render_navbar("Threat Hunting")

st.title("🔍 Threat Hunting en Lenguaje Natural")
st.caption("Escribe una pregunta y el sistema la traduce a una query OpenSearch para buscar en el historial de alertas")
st.divider()

# ── Input principal ───────────────────────────────────────────────────
consulta = st.text_input(
    "Consulta en lenguaje natural",
    value=st.session_state.get("consulta_hunting", ""),
    placeholder="Ej: intentos de login fallido SSH de las últimas 2 horas",
)

buscar = st.button("🔍  Buscar", type="primary")

# ── Ejemplos ──────────────────────────────────────────────────────────
st.markdown("**Ejemplos de consultas:**")
ejemplos = [
    "Intentos de fuerza bruta SSH de las últimas 6 horas",
    "Escaladas de privilegios con sudo hoy",
    "Alertas críticas de nivel 12 o superior esta semana",
    "Actividad desde la IP 192.168.64.1",
    "Eventos con técnica MITRE T1110",
]
cols = st.columns(len(ejemplos))
for col, ejemplo in zip(cols, ejemplos):
    with col:
        if st.button(ejemplo, use_container_width=True):
            st.session_state["consulta_hunting"] = ejemplo
            st.rerun()

st.caption("ℹ️ La traducción NL → DSL usa Ollama (modelo local).")
st.divider()

# ── Búsqueda ──────────────────────────────────────────────────────────
if buscar and consulta.strip():
    ollama_url = os.getenv("WZ_OLLAMA_URL")
    modelo     = os.getenv("WZ_MODELO", "llama3.2")

    with st.spinner("Traduciendo consulta a Query DSL..."):
        query_dsl = nl_a_query_dsl(consulta.strip(), ollama_url, modelo)

    if not query_dsl:
        st.error("No se pudo traducir la consulta. Prueba a reformularla.")
        st.stop()

    with st.expander("Query DSL generada", expanded=False):
        st.json(query_dsl)

    with st.spinner("Consultando el Indexer de Wazuh..."):
        try:
            resultados = ejecutar_query(query_dsl)
        except QueryError as e:
            st.error(f"**Error al ejecutar la query en OpenSearch:**\n\n{e}")
            st.caption("Comprueba que el Indexer está activo y que la query DSL es válida.")
            st.stop()

    if not resultados:
        import json as _json
        _q_str = _json.dumps(query_dsl)
        _tiene_tiempo = ('"timestamp"' in _q_str and '"range"' in _q_str) or \
                        ('"timestamp"' in _q_str and ('"gt"' in _q_str or '"gte"' in _q_str or '"lt"' in _q_str))
        if _tiene_tiempo:
            st.info(
                f"No hay alertas que coincidan con *{consulta}*.\n\n"
                "La query aplica un **filtro temporal**. Si el laboratorio no ha generado "
                "alertas en el período indicado, prueba consultas sin restricción de fecha: "
                "«Actividad desde la IP 192.168.64.1» o «Eventos con técnica MITRE T1110»."
            )
        else:
            st.info(f"No se encontraron eventos para: *{consulta}*")
    else:
        st.success(f"{len(resultados)} evento(s) encontrado(s)")

        def nivel_badge(nivel):
            if nivel >= 12: return f"🔴 {nivel}"
            if nivel >= 8:  return f"🟠 {nivel}"
            if nivel >= 5:  return f"🟡 {nivel}"
            return f"⚪ {nivel}"

        rows = []
        for a in resultados:
            rule  = a.get("rule", {})
            rows.append({
                "Timestamp":   a.get("timestamp", "")[:19].replace("T", " "),
                "Agente":      a.get("agent", {}).get("name", "—"),
                "Nivel":       nivel_badge(rule.get("level", 0)),
                "Descripción": rule.get("description", "—"),
                "IP Origen":   a.get("data", {}).get("srcip", "—"),
                "Regla ID":    rule.get("id", "—"),
            })

        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)

elif buscar and not consulta.strip():
    st.warning("Escribe una consulta antes de buscar.")
