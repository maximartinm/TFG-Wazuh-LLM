#!/usr/bin/env python3
"""
Home.py — Dashboard principal del middleware Wazuh + LLM.
Punto de entrada de la interfaz web: streamlit run Home.py
"""
import streamlit as st
from wazuh_llm.middleware import obtener_token, obtener_alertas_del_indexer
from wazuh_llm.nav import render_navbar

st.set_page_config(
    page_title="Wazuh + LLM | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

render_navbar("Home")

st.markdown("""
<style>
.block-container { padding-bottom: 0 !important; }

/* ── Hero ──────────────────────────────────────────────────────────── */
.hero {
    background: linear-gradient(160deg, #0d1117 0%, #161b22 60%, #0d1117 100%);
    border-bottom: 1px solid #21262d;
    padding: 1.4rem 2rem 1.2rem;
    margin: 0 -1rem 1.5rem;
    text-align: center;
    position: relative;
    overflow: hidden;
}
.hero::after {
    content: '';
    position: absolute;
    bottom: 0; left: 50%; transform: translateX(-50%);
    width: 200px; height: 3px;
    background: linear-gradient(90deg, transparent, #e84040, transparent);
}
.hero-eyebrow {
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: #e84040;
    margin-bottom: 0.4rem;
}
.hero-title {
    font-size: 2rem;
    font-weight: 800;
    color: #f0f6fc;
    margin: 0 0 0.3rem;
    letter-spacing: -0.5px;
    line-height: 1;
}
.hero-subtitle {
    font-size: 0.88rem;
    color: #8b949e;
    margin: 0 auto 1rem;
    max-width: 540px;
    line-height: 1.5;
}
.status-row {
    display: flex;
    gap: 0.75rem;
    justify-content: center;
    flex-wrap: wrap;
}
.status-pill {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.4rem 1rem;
    border-radius: 100px;
    font-size: 0.8rem;
    font-weight: 600;
    letter-spacing: 0.02em;
}
.pill-ok  { background: rgba(46,160,67,0.12); border: 1px solid rgba(46,160,67,0.35); color: #3fb950; }
.pill-err { background: rgba(232,64,64,0.12); border: 1px solid rgba(232,64,64,0.35); color: #e84040; }

/* ── Metric cards ───────────────────────────────────────────────────── */
.mcard {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    padding: 1.3rem 1rem 1.1rem;
    text-align: center;
    transition: border-color 0.2s;
}
.mcard:hover { border-color: #30363d; }
.mval  { font-size: 2.6rem; font-weight: 700; line-height: 1; margin-bottom: 0.35rem; }
.mlbl  { font-size: 0.72rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.06em; }

/* ── Alert feed ─────────────────────────────────────────────────────── */
.feed-title { font-size: 0.78rem; font-weight: 600; color: #8b949e;
              text-transform: uppercase; letter-spacing: 0.08em;
              margin: 1.5rem 0 0.6rem; }
.aitem {
    display: grid;
    grid-template-columns: 1.2rem 9rem 9rem 5rem 1fr;
    align-items: center;
    gap: 0.7rem;
    padding: 0.6rem 0.9rem;
    border-radius: 6px;
    background: #161b22;
    border: 1px solid #21262d;
    margin-bottom: 0.35rem;
    font-size: 0.82rem;
}
.a-ts    { color: #8b949e; font-family: monospace; font-size: 0.78rem; }
.a-agent { color: #58a6ff; font-weight: 600; white-space: nowrap;
           overflow: hidden; text-overflow: ellipsis; }
.a-desc  { color: #c9d1d9; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* ── Footer TFG ─────────────────────────────────────────────────────── */
.tfg-footer {
    margin-top: 3.5rem;
    padding: 1.5rem 2rem;
    border-top: 1px solid #21262d;
    text-align: center;
    color: #8b949e;
    font-size: 0.83rem;
    line-height: 2.2;
}
.tfg-footer strong { color: #c9d1d9; }
</style>
""", unsafe_allow_html=True)

# ── Datos ─────────────────────────────────────────────────────────────
@st.cache_data(ttl=30, show_spinner=False)
def verificar_conexiones():
    token  = obtener_token()
    alertas = obtener_alertas_del_indexer(n_alertas=1, nivel_minimo=1)
    return bool(token), len(alertas) > 0

@st.cache_data(ttl=60, show_spinner=False)
def cargar_resumen():
    return obtener_alertas_del_indexer(n_alertas=50, nivel_minimo=1)

with st.spinner(""):
    api_ok, indexer_ok = verificar_conexiones()

with st.spinner(""):
    alertas = cargar_resumen()

# ── Hero ──────────────────────────────────────────────────────────────
api_pill = (
    '<span class="status-pill pill-ok">✓ API Gestión · :55000</span>'
    if api_ok else
    '<span class="status-pill pill-err">✗ API Gestión · :55000</span>'
)
idx_pill = (
    '<span class="status-pill pill-ok">✓ Indexer OpenSearch · :9200</span>'
    if indexer_ok else
    '<span class="status-pill pill-err">✗ Indexer OpenSearch · :9200</span>'
)

st.markdown(f"""
<div class="hero">
    <div class="hero-eyebrow">SOC Dashboard</div>
    <div class="hero-title">🛡️ Wazuh + LLM</div>
    <div class="hero-subtitle">
        Integración de modelos de lenguaje con Wazuh para enriquecer las alertas
        de seguridad y apoyar a la toma de decisiones
    </div>
    <div class="status-row">{api_pill}{idx_pill}</div>
</div>
""", unsafe_allow_html=True)

# ── Métricas ──────────────────────────────────────────────────────────
if alertas:
    niveles  = [a.get("rule", {}).get("level", 0) for a in alertas]
    total    = len(alertas)
    criticas = sum(1 for n in niveles if n >= 12)
    altas    = sum(1 for n in niveles if 8 <= n < 12)
    medias   = sum(1 for n in niveles if 5 <= n < 8)

    c1, c2, c3, c4 = st.columns(4)
    cards = [
        (c1, total,    "#f0f6fc", "Alertas cargadas"),
        (c2, criticas, "#e84040", "🔴 Críticas  ≥ 12"),
        (c3, altas,    "#f97316", "🟠 Altas  8 – 11"),
        (c4, medias,   "#eab308", "🟡 Medias  5 – 7"),
    ]
    for col, val, color, label in cards:
        col.markdown(
            f'<div class="mcard">'
            f'<div class="mval" style="color:{color}">{val}</div>'
            f'<div class="mlbl">{label}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    # ── Feed de alertas recientes ──────────────────────────────────────
    st.markdown('<div class="feed-title">Alertas más recientes</div>', unsafe_allow_html=True)

    for a in alertas[:5]:
        rule   = a.get("rule", {})
        nivel  = rule.get("level", 0)
        agente = a.get("agent", {}).get("name", "—")
        desc   = rule.get("description", "—")
        ts     = a.get("timestamp", "")[:19].replace("T", " ")
        if nivel >= 12:   emoji, color = "🔴", "#e84040"
        elif nivel >= 8:  emoji, color = "🟠", "#f97316"
        elif nivel >= 5:  emoji, color = "🟡", "#eab308"
        else:             emoji, color = "⚪", "#8b949e"

        st.markdown(
            f'<div class="aitem">'
            f'<span>{emoji}</span>'
            f'<span class="a-ts">{ts}</span>'
            f'<span class="a-agent">{agente}</span>'
            f'<span style="color:{color};font-weight:600;font-size:0.78rem">Nivel {nivel}</span>'
            f'<span class="a-desc">{desc}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )
else:
    st.warning("No se pudieron cargar alertas. Comprueba la conexión con el Indexer.")

st.markdown("<br>", unsafe_allow_html=True)
st.info("Usa la **barra de navegación** superior para explorar alertas, analizar con LLM o realizar Threat Hunting.")

# ── Footer académico ──────────────────────────────────────────────────
st.markdown("""
<div class="tfg-footer">
    <strong>Trabajo de Fin de Grado</strong> · Grado en Ingeniería Informática · ETSIIT, Universidad de Granada<br>
    Autor: <strong>Máximo Martín Moreno</strong>
    &nbsp;·&nbsp;
    Tutores: Antonio Miguel Mora García · Jesús Chamorro Martínez
</div>
""", unsafe_allow_html=True)
