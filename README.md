# TFG-Wazuh-LLM

![Python Version](https://img.shields.io/badge/python-%3E%3D3.8-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-En%20Desarrollo-orange)

**Middleware para enriquecer alertas de Wazuh usando LLMs locales (Ollama).**

Este proyecto es parte de un Trabajo de Fin de Grado (TFG) de Ingeniería. Su objetivo principal es actuar como un orquestador entre un despliegue de **Wazuh (SIEM/XDR)** y un **Modelo de Lenguaje Extenso (LLM)** ejecutado de forma local, mejorando la capacidad de los analistas de seguridad (SOC) para investigar y responder a incidentes.

## Características Principales

- **Conexión Directa:** Extrae alertas en tiempo real desde el Wazuh Indexer (OpenSearch) vía API REST.
- **Enriquecimiento Semántico:** Transforma el JSON técnico de las alertas en informes de incidentes comprensibles.
- **Inteligencia de Amenazas (CTI):** Correlaciona automáticamente los eventos con el framework **MITRE ATT&CK**, situando el ataque en la *Cyber Kill Chain* e infiriendo los objetivos del adversario.
- **Privacidad Total:** Utiliza **Ollama** (ej. Llama 3.2) para ejecutar la IA en hardware local, asegurando que los datos sensibles de la infraestructura no se envíen a servidores de terceros.
- **CLI Nativa:** Ejecutable directamente desde la terminal mediante el comando `wazuh-ia`.

## Requisitos Previos

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

Simplemente ejecuta:   ```wazuh-ia```

El script conectará con el Indexer de Wazuh, buscará la alerta crítica más reciente y generará el análisis táctico a través del LLM.

## Diagrama de arquitectura

graph TD
    %% Estilos de las cajas
    classDef wazuh fill:#00a9e5,stroke:#005c8a,stroke-width:2px,color:#fff;
    classDef python fill:#ffd43b,stroke:#306998,stroke-width:2px,color:#000;
    classDef ai fill:#10a37f,stroke:#0d7a5e,stroke-width:2px,color:#fff;
    classDef endpoint fill:#e0e0e0,stroke:#999,stroke-width:2px,color:#000;

    subgraph Zona 1: Endpoints Monitorizados
        A1[Ubuntu VM - Sudo/SSH]:::endpoint
        A2[Windows VM - Mimikatz]:::endpoint
    end

    subgraph Zona 2: Ecosistema Wazuh
        WM[Wazuh Manager API]:::wazuh
        WI[(Wazuh Indexer / OpenSearch)]:::wazuh
    end

    subgraph Zona 3: Middleware Python TFG
        MW[wazuh-ia Orquestador]:::python
        PR[mitre_prompt.txt]:::python
        MW -. Lee .-> PR
    end

    subgraph Zona 4: Inteligencia Artificial Local
        OLL[Ollama Server]:::ai
        LLM((Llama 3.2)):::ai
        OLL --- LLM
    end

    %% Conexiones
    A1 -- Logs (Pto 1514) --> WM
    A2 -- Logs (Pto 1514) --> WM
    WM -- Indexación --> WI
    
    MW -- 1. Plano de Datos: Extrae Alerta (Pto 9200) --> WI
    MW -- 3. Plano de Gestión: JWT / Bloqueos (Pto 55000) --> WM
    
    MW -- 2. Inyecta Contexto y Genera Respuesta (Pto 11434) --> OLL
