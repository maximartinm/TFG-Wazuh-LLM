#!/usr/bin/env python3
"""
2_Analisis_LLM.py — Análisis de alertas Wazuh con LLM.
"""
import streamlit as st
from wazuh_llm.middleware import (
    obtener_alertas_del_indexer,
    analizar_alerta,
    MODELOS_DEFAULT,
)

st.set_page_config(
    page_title="Análisis LLM | Wazuh + LLM",
    page_icon="🤖",
    layout="wide",
)

st.title("🤖 Análisis de Alertas con LLM")
st.caption("El LLM genera informes de triaje estructurados con correlación MITRE ATT&CK")
st.divider()

# ── 1. Selección de proveedor ─────────────────────────────────────────
st.subheader("1 · Proveedor LLM")
col1, col2, col3 = st.columns(3)

with col1:
    sel_ollama = st.button(
        f"🖥️ Ollama\n\n`{MODELOS_DEFAULT['ollama']}` · local",
        use_container_width=True,
        key="btn_ollama",
    )
with col2:
    sel_gemini = st.button(
        f"✨ Gemini\n\n`{MODELOS_DEFAULT['gemini']}` · nube",
        use_container_width=True,
        key="btn_gemini",
    )
with col3:
    sel_groq = st.button(
        f"⚡ Groq\n\n`{MODELOS_DEFAULT['groq']}` · nube open-source",
        use_container_width=True,
        key="btn_groq",
    )

if sel_ollama: st.session_state["proveedor"] = "ollama"
if sel_gemini: st.session_state["proveedor"] = "gemini"
if sel_groq:   st.session_state["proveedor"] = "groq"

proveedor = st.session_state.get("proveedor", "ollama")
st.info(f"Proveedor activo: **{proveedor.capitalize()}** — `{MODELOS_DEFAULT[proveedor]}`")

st.divider()

# ── 2. Selección de alertas ───────────────────────────────────────────
st.subheader("2 · Alertas a analizar")

col_modo, col_nivel = st.columns([1, 1])
with col_modo:
    modo = st.radio("Modo de selección", ["Últimas N alertas", "Selección manual"], horizontal=True)
with col_nivel:
    nivel_minimo = st.slider("Nivel mínimo de severidad", 1, 15, 5)

alertas_a_analizar = []

if modo == "Últimas N alertas":
    n_alertas = st.select_slider(
        "Número de alertas", options=[1, 3, 5, 10], value=1
    )
else:
    @st.cache_data(ttl=60, show_spinner=False)
    def cargar_catalogo(nivel):
        return obtener_alertas_del_indexer(n_alertas=50, nivel_minimo=nivel)

    with st.spinner("Cargando alertas disponibles..."):
        catalogo = cargar_catalogo(nivel_minimo)

    if not catalogo:
        st.warning(f"No hay alertas con nivel ≥ {nivel_minimo}.")
        st.stop()

    opciones = [
        f"{a.get('timestamp','')[:19].replace('T',' ')}  |  "
        f"{a.get('agent',{}).get('name','?')}  |  "
        f"Nivel {a.get('rule',{}).get('level','?')}  —  "
        f"{a.get('rule',{}).get('description','')[:60]}"
        for a in catalogo
    ]
    seleccion = st.multiselect("Selecciona alertas", opciones, default=opciones[:1])
    alertas_a_analizar = [catalogo[opciones.index(s)] for s in seleccion]

st.divider()

# ── 3. Lanzar análisis ────────────────────────────────────────────────
st.subheader("3 · Análisis")

col_btn, col_clear = st.columns([3, 1])
with col_btn:
    analizar = st.button("▶  Analizar alertas", type="primary", use_container_width=True)
with col_clear:
    if st.button("🗑️  Limpiar resultados", use_container_width=True):
        st.session_state.pop("resultados_analisis", None)
        st.rerun()

if analizar:
    if modo == "Últimas N alertas":
        with st.spinner("Obteniendo alertas del Indexer..."):
            alertas_a_analizar = obtener_alertas_del_indexer(
                n_alertas=n_alertas, nivel_minimo=nivel_minimo
            )

    if not alertas_a_analizar:
        st.warning("No hay alertas para analizar. Ajusta los filtros o selecciona alertas.")
    else:
        resultados = []
        barra = st.progress(0, text="Iniciando análisis...")

        for i, alerta in enumerate(alertas_a_analizar):
            agente  = alerta.get("agent", {}).get("name", "?")
            rule_id = alerta.get("rule", {}).get("id", "?")
            barra.progress(
                i / len(alertas_a_analizar),
                text=f"Analizando {i + 1}/{len(alertas_a_analizar)} — Regla {rule_id} en {agente}..."
            )
            with st.spinner(f"LLM procesando alerta {i + 1} de {len(alertas_a_analizar)}..."):
                informe, tiempo = analizar_alerta(alerta, proveedor=proveedor)

            resultados.append({
                "alerta":    alerta,
                "informe":   informe,
                "tiempo":    tiempo,
                "proveedor": proveedor,
                "modelo":    MODELOS_DEFAULT[proveedor],
            })

        barra.progress(1.0, text="Análisis completado")
        st.session_state["resultados_analisis"] = resultados

# ── Resultados ────────────────────────────────────────────────────────
resultados = st.session_state.get("resultados_analisis", [])

if resultados:
    st.divider()
    tiempos = [r["tiempo"] for r in resultados]
    c1, c2, c3 = st.columns(3)
    c1.metric("Alertas analizadas", len(resultados))
    c2.metric("Tiempo total",       f"{sum(tiempos):.1f} s")
    c3.metric("Media por alerta",   f"{sum(tiempos) / len(tiempos):.1f} s")

    st.subheader("Informes generados")
    for i, r in enumerate(resultados, 1):
        alerta = r["alerta"]
        nivel  = alerta.get("rule", {}).get("level", 0)
        agente = alerta.get("agent", {}).get("name", "?")
        rid    = alerta.get("rule", {}).get("id", "?")
        desc   = alerta.get("rule", {}).get("description", "")[:70]
        emoji  = "🔴" if nivel >= 12 else "🟠" if nivel >= 8 else "🟡" if nivel >= 5 else "⚪"

        with st.expander(
            f"{emoji} Alerta {i}  |  Nivel {nivel}  |  {agente}  |  Regla {rid}: {desc}",
            expanded=(i == 1),
        ):
            col_m1, col_m2 = st.columns(2)
            col_m1.caption(f"⏱️ Inferencia: **{r['tiempo']:.2f} s**")
            col_m2.caption(f"🤖 {r['proveedor'].capitalize()} — `{r['modelo']}`")
            st.divider()
            st.markdown(r["informe"])
