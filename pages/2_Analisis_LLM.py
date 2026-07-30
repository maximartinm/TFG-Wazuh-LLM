#!/usr/bin/env python3
"""
2_Analisis_LLM.py — Análisis de alertas Wazuh con LLM.
"""
import streamlit as st
from wazuh_llm.nav import render_navbar
from wazuh_llm.middleware import (
    obtener_alertas_del_indexer,
    analizar_alerta,
    MODELOS_DEFAULT,
    obtener_token,
)
from wazuh_llm.respuesta_activa import extraer_ips_del_informe, bloquear_ip_en_agente

st.set_page_config(
    page_title="Análisis LLM | Wazuh + LLM",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="collapsed",
)

render_navbar("Análisis LLM")

st.title("🤖 Análisis de Alertas con LLM")
st.caption("El LLM genera informes de triaje estructurados con correlación MITRE ATT&CK")
st.divider()

# ── 1. Selección de proveedor ─────────────────────────────────────────
st.subheader("1 · Proveedor LLM")

proveedor = st.session_state.get("proveedor", "ollama")

st.markdown("""
<style>
.pcard {
    border: 2px solid #e84040;
    border-radius: 8px;
    padding: 0.7rem 1rem 0.8rem;
    text-align: center;
    background: rgba(232, 64, 64, 0.08);
    box-shadow: 0 0 12px rgba(232, 64, 64, 0.12);
}
.pcard-name  { font-size: 1rem; font-weight: 700; color: #fafafa; margin-bottom: 0.2rem; }
.pcard-model { font-size: 0.78rem; color: #e84040; font-family: monospace; margin-bottom: 0.25rem; }
.pcard-badge { font-size: 0.7rem; color: #e84040; font-weight: 600; }
</style>
""", unsafe_allow_html=True)

_providers = [
    ("ollama", "🖥️ Ollama", MODELOS_DEFAULT["ollama"], "local"),
    ("gemini", "✨ Gemini", MODELOS_DEFAULT["gemini"], "nube"),
    ("groq",   "⚡ Groq",   MODELOS_DEFAULT["groq"],   "nube open-source"),
]

col1, col2, col3 = st.columns(3)
for col, (prov, name, model, tipo) in zip([col1, col2, col3], _providers):
    with col:
        if prov == proveedor:
            st.markdown(
                f'<div class="pcard">'
                f'<div class="pcard-name">{name}</div>'
                f'<div class="pcard-model">{model} · {tipo}</div>'
                f'<div class="pcard-badge">✓ seleccionado</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
        else:
            if st.button(f"{name}\n\n`{model}` · {tipo}", use_container_width=True, key=f"btn_{prov}"):
                st.session_state["proveedor"] = prov
                st.rerun()

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

st.checkbox(
    "🛡️ Activar sugerencia de Respuesta Activa",
    key="activar_ra",
    help=(
        "Si se marca, tras el análisis se identificarán IPs candidatas a bloqueo "
        "presentes en el informe. Se requerirá escribir CONFIRMAR para ejecutar "
        "cualquier acción en el firewall del agente (human-in-the-loop)."
    ),
)

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

            # ── Respuesta Activa (si está activada) ───────────────────
            if st.session_state.get("activar_ra"):
                ips = extraer_ips_del_informe(r["informe"])
                # Añadir srcip de la alerta si no estaba ya en el informe
                src_ip = r["alerta"].get("data", {}).get("srcip")
                if src_ip and src_ip not in ips:
                    ips.insert(0, src_ip)

                if ips:
                    st.divider()
                    st.warning(
                        f"🛡️ **Respuesta Activa** — {len(ips)} IP(s) candidata(s) "
                        f"identificada(s): `{'`, `'.join(ips)}`\n\n"
                        "Escribe **CONFIRMAR** (exactamente, en mayúsculas) y pulsa "
                        "el botón para ejecutar el bloqueo en el firewall del agente. "
                        "Esta acción es **irreversible** hasta reiniciar el agente."
                    )
                    agent_id   = r["alerta"].get("agent", {}).get("id", "000")
                    agent_name = r["alerta"].get("agent", {}).get("name", "?")

                    ra_col1, ra_col2 = st.columns([3, 1])
                    with ra_col1:
                        confirmacion = st.text_input(
                            "Confirmación",
                            placeholder="Escribe CONFIRMAR",
                            key=f"ra_confirm_{i}",
                            label_visibility="collapsed",
                        )
                    with ra_col2:
                        ejecutar = st.button(
                            f"🔒 Bloquear en {agent_name}",
                            key=f"ra_btn_{i}",
                            use_container_width=True,
                        )

                    if ejecutar:
                        if confirmacion == "CONFIRMAR":
                            token = obtener_token()
                            for ip in ips:
                                ok = bloquear_ip_en_agente(token, agent_id, ip)
                                if ok:
                                    st.success(f"✓ IP `{ip}` bloqueada en agente **{agent_name}**")
                                else:
                                    st.error(f"✗ No se pudo bloquear `{ip}` — comprueba la API y el agente")
                        else:
                            st.error("Escribe exactamente **CONFIRMAR** (en mayúsculas) para confirmar la acción.")
