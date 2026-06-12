# TFG-Wazuh-LLM

![Python](https://img.shields.io/badge/python-%3E%3D3.10-blue)
![Wazuh](https://img.shields.io/badge/wazuh-4.8+-teal)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/estado-En%20Desarrollo-orange)

Middleware de código abierto que conecta **Wazuh XDR** con un **LLM local (Ollama)** para transformar alertas de seguridad crudas en informes de inteligencia táctica accionables, sin enviar datos sensibles a servicios externos.

Trabajo de Fin de Grado — Ingeniería Informática, Universidad de Granada  
Autor: Máximo Martín Moreno · Tutores: Antonio M. Mora García / Jesús Chamorro Martínez

---

## ¿Qué problema resuelve?

Un analista SOC recibe decenas de alertas diarias en formato JSON técnico como esta:

```json
{ "rule.id": "5710", "rule.description": "sshd: Attempt to login using a non-existent user", "data.srcip": "45.33.32.156" }
```

Este middleware convierte esa alerta en un informe estructurado con contexto MITRE ATT&CK, análisis forense del log crudo, posibles objetivos del atacante y acciones de respuesta concretas — en segundos, sin conexión a internet.

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│  Zona 1: Endpoints Monitorizados                            │
│  Ubuntu VM (SSH / Sudo / Escalada de privilegios)           │
└──────────────────┬──────────────────────────────────────────┘
                   │ Logs (Puerto 1514)
┌──────────────────▼──────────────────────────────────────────┐
│  Zona 2: Ecosistema Wazuh                                   │
│  Wazuh Manager  →  Wazuh Indexer / OpenSearch               │
└──────────────────┬──────────────────────────────────────────┘
        ┌──────────┴───────────┐
        │ Puerto 9200          │ Puerto 55000
        │ (Plano de Datos)     │ (Plano de Gestión / JWT)
┌───────▼──────────────────────▼──────────────────────────────┐
│  Zona 3: Middleware Python (este repositorio)               │
│  middleware.py  ·  respuesta_activa.py  ·  threat_hunting.py│
└──────────────────────────────┬──────────────────────────────┘
                               │ Puerto 11434
┌──────────────────────────────▼──────────────────────────────┐
│  Zona 4: IA Local                                           │
│  Ollama Server  →  LLM (Llama 3.2)                         │
└─────────────────────────────────────────────────────────────┘
```

El middleware actúa como orquestador en tres flujos:

**Plano de datos** (puerto 9200): consulta alertas directamente a OpenSearch con queries DSL filtrando por nivel de severidad.

**Plano de gestión** (puerto 55000): se autentica con JWT para ejecutar respuestas activas (bloqueos de IP) en los agentes.

**Motor IA** (puerto 11434): envía prompts estructurados a Ollama y valida las respuestas antes de mostrarlas.

---

## Módulos

### `middleware.py` — Análisis forense de alertas
Extrae alertas del Indexer, construye un prompt con el contexto forense (full_log, IPs, técnicas MITRE) y genera un informe táctico con el LLM.

```bash
wazuh-ia                        # Analiza la última alerta crítica
wazuh-ia --alertas 5            # Analiza las 5 más recientes
wazuh-ia --alertas 10 --nivel 7 # Las 10 alertas de nivel >= 7
```

Ejemplo de salida:
```
[✓] API de Gestión (Puerto 55000): conectado.
[✓] 3 alerta(s) capturada(s) del Indexer (Puerto 9200).

[IA] Procesando evento de nivel 10 en agente 'Ubuntu-Victima' (Regla ID: 5710)...

======================================================================
  ALERTA 1/3  |  INFORME GENERADO POR LLM
======================================================================
📄 RESUMEN EJECUTIVO Y KILL CHAIN
El atacante realizó un ataque de fuerza bruta SSH contra el usuario 'root'
desde 45.33.32.156. Fase Kill Chain: Acceso Inicial (Initial Access).
...
```

---

### `respuesta_activa.py` — Fase 3: bloqueo con confirmación humana
Implementa el patrón **Human-in-the-Loop**: el LLM sugiere bloqueos, el analista los aprueba o rechaza explícitamente. El sistema nunca ejecuta acciones automáticas.

```bash
wazuh-ia --alertas 1 --respuesta-activa
```

Flujo:
```
LLM genera informe con IPs sospechosas
        ↓
Middleware extrae IPs candidatas (regex + validación lista blanca)
        ↓
Analista escribe CONFIRMAR para cada acción
        ↓
API Wazuh ejecuta firewall-drop en el agente afectado
```

Guardrails implementados: las IPs `127.0.0.1`, `::1` y la IP del propio Manager nunca pueden bloquearse, independientemente de lo que sugiera el LLM.

---

### `threat_hunting.py` — Fase 3: consultas en lenguaje natural
Modo interactivo donde el analista escribe preguntas en español. El LLM las traduce a queries DSL de OpenSearch y el middleware las ejecuta contra el Indexer.

```bash
wazuh-ia --hunting
```

```
🔍 [HUNTING] > intentos de fuerza bruta SSH de las últimas 6 horas
[~] Query DSL generada: {"size":10,"query":{"bool":{"must":[{"match":...}]}}}
[~] Consultando el Indexer de Wazuh...

  RESULTADOS: 3 evento(s) encontrado(s)
  [1] 2026-06-12T08:43:45Z | Ubuntu-Victima | Nivel 10 | 45.33.32.156
  [2] ...
```

---

## Instalación

### Requisitos previos

- Python 3.10 o superior
- Wazuh 4.8+ desplegado (ver sección Infraestructura)
- Ollama con un modelo descargado

### Clonar e instalar

```bash
git clone https://github.com/maximartinm/TFG-Wazuh-LLM.git
cd TFG-Wazuh-LLM
python3 -m venv venv
source venv/bin/activate       # Linux/macOS
# .\venv\Scripts\activate      # Windows
pip install -e .
```

### Configurar variables de entorno

Crea un archivo `.env` en la raíz del proyecto (nunca lo subas a Git):

```env
# API de Gestión — Puerto 55000
WZ_API_URL=https://localhost:55000
WZ_API_USER=wazuh-wui
WZ_API_PASS=MyS3cr3tP4ssw0rd

# Indexer OpenSearch — Puerto 9200
WZ_INDEXER_URL=https://localhost:9200/wazuh-alerts-*/_search
WZ_INDEXER_USER=admin
WZ_INDEXER_PASS=SecretPassword

# IP del Manager (se añade automáticamente a la lista blanca)
WZ_MANAGER_IP=192.168.1.73

# Ollama
WZ_OLLAMA_URL=http://localhost:11434/api/generate
WZ_MODELO=llama3.2

# Ruta al archivo de prompt
WZ_PROMPT_PATH=prompts/mitre_prompt.txt
```

### Verificar instalación

```bash
wazuh-ia --help
```

---

## Infraestructura de laboratorio

El entorno de desarrollo y pruebas está compuesto por:

**Wazuh (Docker — single-node)**
```bash
git clone https://github.com/wazuh/wazuh-docker.git -b 4.8.0
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```
Dashboard accesible en `https://localhost:443` (admin / SecretPassword)

**Ollama (macOS con Apple Silicon)**
```bash
brew install ollama
brew services start ollama
ollama pull llama3.2
```

**Agente Ubuntu víctima (UTM / ARM64)**
```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.0-1_arm64.deb
sudo WAZUH_MANAGER='192.168.1.73' WAZUH_AGENT_NAME='Ubuntu-Victima' dpkg -i ./wazuh-agent_4.9.0-1_arm64.deb
sudo systemctl enable --now wazuh-agent
```

---

## Vectores de ataque probados

| Ataque | Regla Wazuh | MITRE | Agente |
|---|---|---|---|
| Fuerza bruta SSH (usuario inexistente) | 5710 | T1110.001 | Ubuntu |
| Contraseña SSH incorrecta | 5503 | T1110 | Ubuntu |
| Escalada de privilegios (sudo) | 5404 | T1548.003 | Ubuntu |

---

## Estado del desarrollo

- [x] Fase 1: Transformación de alertas en informes legibles
- [x] Fase 2: Correlación con MITRE ATT&CK e inferencia de Kill Chain
- [x] Fase 3a: Respuesta Activa con confirmación human-in-the-loop
- [x] Fase 3b: Threat Hunting mediante consultas en lenguaje natural

---

## Estructura del repositorio

```
TFG-Wazuh-LLM/
├── wazuh_llm/
│   ├── __init__.py
│   ├── middleware.py          # Orquestador principal
│   ├── respuesta_activa.py    # Módulo de bloqueo (Fase 3a)
│   └── threat_hunting.py      # Consultas NL (Fase 3b)
├── prompts/
│   └── mitre_prompt.txt       # Plantilla de análisis forense
├── .env.example               # Plantilla de configuración
├── .gitignore
├── pyproject.toml
└── README.md
```

---

## Licencia

MIT — ver [LICENSE](LICENSE) para más detalles.