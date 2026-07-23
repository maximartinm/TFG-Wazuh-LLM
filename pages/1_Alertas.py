#!/usr/bin/env python3
"""
1_Alertas.py — Explorador de alertas del Indexer de Wazuh.
"""
import pandas as pd
import streamlit as st
from wazuh_llm.middleware import obtener_alertas_del_indexer

st.set_page_config(
    page_title="Alertas | Wazuh + LLM",
    page_icon="🚨",
    layout="wide",
)

st.title("🚨 Explorador de Alertas")
st.caption("Visualización y filtrado de alertas recientes del Indexer de Wazuh")
st.divider()

# ── Filtros en el cuerpo ──────────────────────────────────────────────
col1, col2, col3 = st.columns([1, 1, 1])
with col1:
    n_alertas = st.selectbox("Número de alertas", [10, 20, 50, 100], index=1)
with col2:
    nivel_minimo = st.slider("Nivel mínimo de severidad", 1, 15, 5)
with col3:
    st.write("")
    st.write("")
    actualizar = st.button("🔄 Actualizar", use_container_width=True)
    if actualizar:
        st.cache_data.clear()

st.divider()

# ── Carga de alertas ──────────────────────────────────────────────────
@st.cache_data(ttl=60, show_spinner=False)
def cargar_alertas(n, nivel):
    return obtener_alertas_del_indexer(n_alertas=n, nivel_minimo=nivel)

with st.spinner("Cargando alertas del Indexer..."):
    alertas = cargar_alertas(n_alertas, nivel_minimo)

if not alertas:
    st.warning(f"No se encontraron alertas con nivel ≥ {nivel_minimo}. Prueba a bajar el nivel mínimo.")
    st.stop()

st.success(f"{len(alertas)} alerta(s) cargada(s) con nivel ≥ {nivel_minimo}")

# ── Tabla ─────────────────────────────────────────────────────────────
def nivel_badge(nivel):
    if nivel >= 12: return f"🔴 {nivel}"
    if nivel >= 8:  return f"🟠 {nivel}"
    if nivel >= 5:  return f"🟡 {nivel}"
    return f"⚪ {nivel}"

rows = []
for a in alertas:
    rule   = a.get("rule", {})
    mitre  = rule.get("mitre", {})
    ids    = mitre.get("id", [])
    tactic = mitre.get("tactic", [])
    rows.append({
        "Timestamp":   a.get("timestamp", "")[:19].replace("T", " "),
        "Agente":      a.get("agent", {}).get("name", "—"),
        "Nivel":       nivel_badge(rule.get("level", 0)),
        "Descripción": rule.get("description", "—"),
        "IP Origen":   a.get("data", {}).get("srcip", "—"),
        "MITRE ID":    ", ".join(ids)    if isinstance(ids, list)    else str(ids)    or "—",
        "Táctica":     ", ".join(tactic) if isinstance(tactic, list) else str(tactic) or "—",
    })

df = pd.DataFrame(rows)
st.dataframe(df, use_container_width=True, hide_index=True)

# ── Detalle ───────────────────────────────────────────────────────────
st.divider()
st.subheader("Detalle de alerta")

opciones = [
    f"{i+1}. {a.get('timestamp','')[:19].replace('T',' ')}  |  "
    f"{a.get('agent',{}).get('name','?')}  |  "
    f"Nivel {a.get('rule',{}).get('level','?')}  —  "
    f"{a.get('rule',{}).get('description','')[:60]}"
    for i, a in enumerate(alertas)
]
seleccion = st.selectbox("Selecciona una alerta para ver el detalle", opciones)
idx = opciones.index(seleccion)

alerta = alertas[idx]
rule   = alerta.get("rule", {})
mitre  = rule.get("mitre", {})

col1, col2 = st.columns(2)
with col1:
    st.markdown(f"**Agente:** {alerta.get('agent', {}).get('name', '—')}")
    st.markdown(f"**Regla ID:** {rule.get('id', '—')}")
    st.markdown(f"**Descripción:** {rule.get('description', '—')}")
    st.markdown(f"**Nivel:** {rule.get('level', '—')}")
with col2:
    ids    = mitre.get('id', [])
    tactic = mitre.get('tactic', [])
    st.markdown(f"**MITRE ID:** {', '.join(ids) if ids else '—'}")
    st.markdown(f"**Táctica:** {', '.join(tactic) if tactic else '—'}")
    st.markdown(f"**IP Origen:** {alerta.get('data', {}).get('srcip', '—')}")
    st.markdown(f"**Timestamp:** {alerta.get('timestamp', '—')[:19].replace('T', ' ')}")

if alerta.get("full_log"):
    st.text_area("Raw Log", alerta["full_log"], height=120, disabled=True)

with st.expander("Ver JSON completo de la alerta"):
    st.json(alerta)
