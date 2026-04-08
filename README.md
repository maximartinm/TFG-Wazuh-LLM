# TFG-Wazuh-LLM 🛡️🧠

![Python Version](https://img.shields.io/badge/python-%3E%3D3.8-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-En%20Desarrollo-orange)

**Middleware para enriquecer alertas de Wazuh usando LLMs locales (Ollama).**

Este proyecto es parte de un Trabajo de Fin de Grado (TFG) de Ingeniería. Su objetivo principal es actuar como un orquestador entre un despliegue de **Wazuh (SIEM/XDR)** y un **Modelo de Lenguaje Extenso (LLM)** ejecutado de forma local, mejorando la capacidad de los analistas de seguridad (SOC) para investigar y responder a incidentes.

## 🚀 Características Principales

- **Conexión Directa:** Extrae alertas en tiempo real desde el Wazuh Indexer (OpenSearch) vía API REST.
- **Enriquecimiento Semántico:** Transforma el JSON técnico de las alertas en informes de incidentes comprensibles.
- **Inteligencia de Amenazas (CTI):** Correlaciona automáticamente los eventos con el framework **MITRE ATT&CK**, situando el ataque en la *Cyber Kill Chain* e infiriendo los objetivos del adversario.
- **Privacidad Total:** Utiliza **Ollama** (ej. Llama 3.2) para ejecutar la IA en hardware local, asegurando que los datos sensibles de la infraestructura no se envíen a servidores de terceros.
- **CLI Nativa:** Ejecutable directamente desde la terminal mediante el comando `wazuh-ia`.

## 📋 Requisitos Previos

Para ejecutar este middleware, necesitas tener instalado y configurado:

- **Python:** Versión 3.8 o superior.
- **Wazuh:** Un entorno de Wazuh (Manager, Indexer, Dashboard) accesible.
- **Ollama:** El motor de IA local ejecutando el modelo correspondiente (por defecto `llama3.2`).

## 🛠️ Instalación

El proyecto está empaquetado utilizando estándares modernos de Python (`pyproject.toml`). Para instalarlo, sigue estos pasos:

1. Clona el repositorio:
   ```
   bash
   git clone [https://github.com/maximartinm/TFG-Wazuh-LLM.git](https://github.com/maximartinm/TFG-Wazuh-LLM.git)
   cd TFG-Wazuh-LLM
   ``` 

2. Crea y activa un entorno virtual:
    ```
    python3 -m venv venv
    source venv/bin/activate  # En Linux/macOS
    # .\venv\Scripts\activate # En Windows
    ```

3. Instala el paquete (el modo -e permite realizar cambios en el código sin tener que reinstalar):
    ```
    pip install -e .
    ```

## Uso

Una vez instalado, el paquete expone un comando global en tu terminal. Ya no necesitas llamar a Python directamente.

Simplemente ejecuta:
```wazuh-ia```

El script conectará con el Indexer de Wazuh, buscará la alerta crítica más reciente y generará el análisis táctico a través del LLM.