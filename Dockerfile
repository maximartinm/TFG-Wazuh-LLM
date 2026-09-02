# =====================================================================
# Imagen del middleware TFG — Wazuh + LLM
# Contiene el dashboard Streamlit (proceso principal) y la CLI wazuh-ia.
# =====================================================================
FROM python:3.12-slim

# PYTHONDONTWRITEBYTECODE: el rootfs del pod es de solo lectura, así que
# Python no debe intentar escribir __pycache__ en /app.
# HOME=/tmp: único punto de escritura (emptyDir montado por el Deployment).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

WORKDIR /app

# Las dependencias se instalan antes de copiar el código de la aplicación:
# así la capa de pip se reutiliza mientras no cambie pyproject.toml.
COPY pyproject.toml README.md ./
COPY wazuh_llm/ ./wazuh_llm/
RUN pip install --no-cache-dir .

COPY Home.py ./
COPY pages/ ./pages/
COPY prompts/ ./prompts/
COPY .streamlit/ ./.streamlit/

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser
USER 10001

EXPOSE 8501

CMD ["streamlit", "run", "Home.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0"]
