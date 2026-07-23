#!/usr/bin/env python3
"""
Home.py — Dashboard principal del middleware Wazuh + LLM.
Punto de entrada de la interfaz web: streamlit run Home.py
"""
import streamlit as st
from wazuh_llm.middleware import obtener_token, obtener_alertas_del_indexer

st.set_page_config(
    page_title="Wazuh + LLM | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .block-container { padding-top: 1.5rem; }
    .tfg-header {
        background: linear-gradient(135deg, #1a1d27 0%, #0e1117 100%);
        border: 1px solid #2d2d3d;
        border-left: 5px solid #e84040;
        border-radius: 8px;
        padding: 1.8rem 2rem;
        margin-bottom: 1.5rem;
    }
    .tfg-title {
        font-size: 1.9rem;
        font-weight: 700;
        color: #fafafa;
        margin: 0 0 0.3rem 0;
    }
    .tfg-subtitle {
        font-size: 1rem;
        color: #aaa;
        margin: 0 0 1.2rem 0;
    }
    .tfg-meta {
        font-size: 0.85rem;
        color: #ccc;
        line-height: 1.8;
    }
    .tfg-meta strong { color: #fafafa; }
</style>
""", unsafe_allow_html=True)

# ── Cabecera del TFG ──────────────────────────────────────────────────
st.markdown("""
<div class="tfg-header">
    <p class="tfg-title">🛡️ Wazuh + LLM</p>
    <p class="tfg-subtitle">Integración de LLMs con Wazuh para enriquecer las alertas y apoyar a la toma de decisiones</p>
    <div class="tfg-meta">
        <strong>Trabajo de Fin de Grado</strong> · Grado en Ingeniería Informática · ETSIIT, Universidad de Granada<br>
        <strong>Autor:</strong> Máximo Martín Moreno<br>
        <strong>Tutores:</strong> Antonio Miguel Mora García · Jesús Chamorro Martínez
    </div>
</div>
""", unsafe_allow_html=True)

# ── Estado del sistema ────────────────────────────────────────────────
@st.cache_data(ttl=30, show_spinner=False)
def verificar_conexiones():
    token  = obtener_token()
    alertas = obtener_alertas_del_indexer(n_alertas=1, nivel_minimo=1)
    return token, len(alertas) > 0

with st.spinner("Verificando conexiones con Wazuh..."):
    token, indexer_ok = verificar_conexiones()

st.subheader("Estado del sistema")
col1, col2 = st.columns(2)
with col1:
    if token:
        st.success("✅  API de Gestión — Puerto 55000 — Conectado")
    else:
        st.error("❌  API de Gestión — Puerto 55000 — Sin conexión")
with col2:
    if indexer_ok:
        st.success("✅  Indexer / OpenSearch — Puerto 9200 — Conectado")
    else:
        st.error("❌  Indexer / OpenSearch — Puerto 9200 — Sin conexión")

st.divider()

# ── Métricas de alertas recientes ─────────────────────────────────────
@st.cache_data(ttl=60, show_spinner=False)
def cargar_resumen():
    return obtener_alertas_del_indexer(n_alertas=50, nivel_minimo=1)

with st.spinner("Cargando resumen de alertas..."):
    alertas = cargar_resumen()

st.subheader("Resumen de alertas recientes")

if alertas:
    niveles = [a.get("rule", {}).get("level", 0) for a in alertas]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Alertas cargadas",    len(alertas))
    c2.metric("🔴 Críticas  (≥ 12)", sum(1 for n in niveles if n >= 12))
    c3.metric("🟠 Altas  (8 – 11)",  sum(1 for n in niveles if 8 <= n < 12))
    c4.metric("🟡 Medias  (5 – 7)",  sum(1 for n in niveles if 5 <= n < 8))

    st.markdown("**Alertas más recientes**")
    for a in alertas[:5]:
        rule   = a.get("rule", {})
        nivel  = rule.get("level", 0)
        agente = a.get("agent", {}).get("name", "—")
        desc   = rule.get("description", "—")
        ts     = a.get("timestamp", "")[:19].replace("T", " ")
        emoji  = "🔴" if nivel >= 12 else "🟠" if nivel >= 8 else "🟡" if nivel >= 5 else "⚪"
        st.markdown(f"{emoji} `{ts}` &nbsp; **{agente}** &nbsp; Nivel {nivel} — {desc}")
else:
    st.warning("No se pudieron cargar alertas. Comprueba la conexión con el Indexer.")

st.divider()
st.info("Usa el **menú lateral** para explorar alertas, analizar con LLM o realizar Threat Hunting.")
