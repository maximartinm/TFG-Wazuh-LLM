#!/usr/bin/env python3
"""
2_Analisis_LLM.py — Análisis de alertas Wazuh con LLM.
Permite elegir proveedor (Ollama / Gemini / Groq) y ver los informes generados.
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

# ── Sidebar ───────────────────────────────────────────────────────────
with st.sidebar:
    st.subheader("Proveedor LLM")
    proveedor = st.radio(
        "Selecciona el modelo",
        options=["ollama", "gemini", "groq"],
        format_func=lambda p: {
            "ollama": f"🖥️  Ollama — {MODELOS_DEFAULT['ollama']} (local)",
            "gemini": f"✨  Gemini — {MODELOS_DEFAULT['gemini']}",
            "groq":   f"⚡  Groq — {MODELOS_DEFAULT['groq']}",
        }[p],
    )
    st.caption(f"Modelo activo: `{MODELOS_DEFAULT[proveedor]}`")
    st.divider()
    st.subheader("Alertas")
    n_alertas    = st.selectbox("Número de alertas a analizar", [1, 3, 5, 10], index=0)
    nivel_minimo = st.slider("Nivel mínimo", 1, 15, 5)

# ── Controles principales ─────────────────────────────────────────────
col_btn, col_clear = st.columns([2, 1])
with col_btn:
    analizar = st.button("▶  Analizar alertas", type="primary", use_container_width=True)
with col_clear:
    if st.button("🗑️  Limpiar", use_container_width=True):
        st.session_state.pop("resultados_analisis", None)
        st.rerun()

# ── Análisis ──────────────────────────────────────────────────────────
if analizar:
    with st.spinner("Obteniendo alertas del Indexer..."):
        alertas = obtener_alertas_del_indexer(n_alertas=n_alertas, nivel_minimo=nivel_minimo)

    if not alertas:
        st.warning(f"No se encontraron alertas con nivel ≥ {nivel_minimo}.")
    else:
        resultados = []
        barra = st.progress(0, text="Iniciando análisis...")

        for i, alerta in enumerate(alertas):
            agente  = alerta.get("agent", {}).get("name", "?")
            rule_id = alerta.get("rule", {}).get("id", "?")
            barra.progress(
                i / len(alertas),
                text=f"Analizando {i + 1}/{len(alertas)} — Regla {rule_id} en {agente}..."
            )
            with st.spinner(f"LLM procesando alerta {i + 1} de {len(alertas)}..."):
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
    c2.metric("Tiempo total", f"{sum(tiempos):.1f} s")
    c3.metric("Media por alerta", f"{sum(tiempos) / len(tiempos):.1f} s")

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
            col_meta1, col_meta2 = st.columns(2)
            col_meta1.caption(f"⏱️ Inferencia: **{r['tiempo']:.2f} s**")
            col_meta2.caption(f"🤖 {r['proveedor'].capitalize()} — `{r['modelo']}`")
            st.divider()
            st.markdown(r["informe"])
