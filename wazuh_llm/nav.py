"""nav.py — Barra de navegación superior (SPA, sin recarga completa)."""
import streamlit as st

# Orden importa: debe coincidir con el nombre exacto pasado a render_navbar()
_PAGES = [
    ("Home",           "Home.py",                  "🏠"),
    ("Alertas",        "pages/1_Alertas.py",        "🚨"),
    ("Análisis LLM",   "pages/2_Analisis_LLM.py",  "🤖"),
    ("Threat Hunting", "pages/3_Threat_Hunting.py", "🔍"),
]

_CSS = """<style>
/* ── Ocultar sidebar y header nativos ────────────────── */
[data-testid="stSidebar"],
[data-testid="collapsedControl"],
[data-testid="stSidebarNav"]   { display: none !important; }
[data-testid="stHeader"]       { display: none !important; }

/* ── Espacio reservado para el navbar fijo ───────────── */
.block-container { padding-top: 4rem !important; }

/* ── Navbar: stHorizontalBlock que contiene #wazuh-llm-nav ──
   position:fixed + left:0 + right:0 extiende al 100% del
   viewport sin importar el overflow del padre (a diferencia
   de sticky + width:100vw que se clipa en contenedores con
   overflow distinto de visible).                            */
[data-testid="stHorizontalBlock"]:has(#wazuh-llm-nav) {
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    right: 0 !important;
    z-index: 1000 !important;
    background: #161b22 !important;
    border-bottom: 1px solid #21262d !important;
    padding: 0.7rem 2rem !important;
    box-sizing: border-box !important;
    align-items: center !important;
}

/* ── Marca ────────────────────────────────────────────── */
#wazuh-llm-nav {
    color: #f0f6fc;
    font-weight: 700;
    font-size: 1rem;
    letter-spacing: -0.2px;
    white-space: nowrap;
    line-height: 1;
}

/* ── Links de navegación ──────────────────────────────── */
[data-testid="stHorizontalBlock"]:has(#wazuh-llm-nav)
[data-testid="stPageLink"] a {
    display: flex !important;
    justify-content: center !important;
    align-items: center !important;
    color: #8b949e !important;
    text-decoration: none !important;
    padding: 0.5rem 1rem !important;
    border-radius: 8px !important;
    font-size: 0.92rem !important;
    font-weight: 500 !important;
    border: 1px solid transparent !important;
    white-space: nowrap !important;
    transition: color 0.15s, background 0.15s, border-color 0.15s !important;
    min-height: 2.2rem !important;
}
[data-testid="stHorizontalBlock"]:has(#wazuh-llm-nav)
[data-testid="stPageLink"] a:hover {
    color: #f0f6fc !important;
    background: #21262d !important;
    border-color: #30363d !important;
    text-decoration: none !important;
}

/* ── Página activa (disabled) ─────────────────────────── */
[data-testid="stHorizontalBlock"]:has(#wazuh-llm-nav)
[data-testid="stPageLink"] a[aria-disabled="true"] {
    color: #f0f6fc !important;
    background: #21262d !important;
    border-color: #30363d !important;
    opacity: 1 !important;
    cursor: default !important;
    text-decoration: none !important;
}
[data-testid="stHorizontalBlock"]:has(#wazuh-llm-nav)
[data-testid="stPageLink"] a[aria-disabled="true"] p,
[data-testid="stHorizontalBlock"]:has(#wazuh-llm-nav)
[data-testid="stPageLink"] a[aria-disabled="true"] span {
    color: #f0f6fc !important;
}

/* ── Comprimir padding de columnas dentro del nav ─────── */
[data-testid="stHorizontalBlock"]:has(#wazuh-llm-nav)
[data-testid="stColumn"] { padding: 0 0.15rem !important; }
</style>"""


def render_navbar(current: str) -> None:
    """Navbar superior con st.page_link() — navegación SPA sin recarga de página.

    Args:
        current: nombre exacto de la página activa según _PAGES,
                 p.ej. "Home", "Alertas", "Análisis LLM", "Threat Hunting".
    """
    st.markdown(_CSS, unsafe_allow_html=True)

    # [marca | Home | Alertas | Análisis LLM | Threat Hunting | espaciador]
    cols = st.columns([2.5, 1.1, 1.1, 1.5, 1.7, 2])

    with cols[0]:
        # ID único → CSS usa :has(#wazuh-llm-nav) para apuntar solo a este bloque
        st.markdown('<span id="wazuh-llm-nav">🛡️ Wazuh + LLM</span>', unsafe_allow_html=True)

    for col, (name, page_file, icon) in zip(cols[1:], _PAGES):
        with col:
            st.page_link(
                page_file,
                label=f"{icon} {name}",
                disabled=(name == current),
                use_container_width=True,
            )
    # cols[-1] queda vacío como espaciador derecho
