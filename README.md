# TFG-Wazuh-LLM

![Python](https://img.shields.io/badge/python-%3E%3D3.10-blue)
![Wazuh](https://img.shields.io/badge/wazuh-4.9+-teal)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/estado-Completado-brightgreen)

Middleware de código abierto que conecta **Wazuh XDR** con un **LLM** para transformar alertas de seguridad crudas en informes de inteligencia táctica accionables, sin enviar datos sensibles a servicios externos.

Incluye una **interfaz web** (Streamlit) que expone los tres modos de operación con visualización interactiva de alertas, análisis multi-modelo y respuesta activa con confirmación humana.

Trabajo de Fin de Grado — Ingeniería Informática, Universidad de Granada  
Autor: Máximo Martín Moreno · Tutores: Antonio Miguel Mora García / Jesús Chamorro Martínez

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
│  Interfaz web: Home.py + pages/                             │
└──────────────────────────────┬──────────────────────────────┘
                               │ Puerto 11434 / API externa
┌──────────────────────────────▼──────────────────────────────┐
│  Zona 4: IA                                                 │
│  Ollama (local, Llama 3.2) · Gemini Flash · Groq            │
└─────────────────────────────────────────────────────────────┘
```

El middleware actúa como orquestador en tres flujos:

**Plano de datos** (puerto 9200): consulta alertas directamente a OpenSearch con queries DSL filtrando por nivel de severidad.

**Plano de gestión** (puerto 55000): se autentica con JWT para ejecutar respuestas activas (bloqueos de IP) en los agentes.

**Motor IA**: envía prompts estructurados al proveedor configurado (Ollama en local, Gemini Flash o Llama 3.3-70B vía Groq) y valida las respuestas antes de mostrarlas.

---

## Módulos

### `middleware.py` — Análisis forense de alertas

Extrae alertas del Indexer, construye un prompt con el contexto forense (full_log, IPs, técnicas MITRE) y genera un informe táctico con el LLM.

```bash
wazuh-ia                        # Analiza la última alerta crítica
wazuh-ia --alertas 5            # Analiza las 5 más recientes
wazuh-ia --alertas 10 --nivel 7 # Las 10 alertas de nivel >= 7
wazuh-ia --alertas 1 --respuesta-activa  # Con respuesta activa
wazuh-ia --hunting              # Modo threat hunting interactivo
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

### `respuesta_activa.py` — Bloqueo con confirmación humana

Implementa el patrón **Human-in-the-Loop**: el LLM sugiere bloqueos, el analista los aprueba explícitamente. El sistema nunca ejecuta acciones automáticas.

Flujo:
```
LLM genera informe con IPs sospechosas
        ↓
Middleware extrae IPs candidatas (regex + lista blanca)
        ↓
Analista escribe CONFIRMAR para cada acción
        ↓
API Wazuh ejecuta firewall-drop en el agente afectado
```

La lista blanca protege siempre `127.0.0.1`, `::1` y la IP del Manager, independientemente de lo que sugiera el LLM.

**Prerrequisito en el Manager:** Para que Wazuh acepte llamadas programáticas a `firewall-drop`, el fichero `ossec.conf` del Manager debe incluir el bloque `<active-response>` siguiente (sin `rules_id` ni `level`, ya que el disparo es por API, no por regla):

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
</active-response>
```

Tras reiniciar el Manager (`docker compose restart wazuh.manager`), Wazuh genera automáticamente la entrada `firewall-drop0` en `etc/shared/ar.conf` (sufijo `0` = bloqueo permanente sin expiración). El middleware usa el nombre `firewall-drop0` en el payload de la llamada a la API (puerto 55000). Sin este bloque la API devuelve error 404 al intentar ejecutar el bloqueo.

---

### `threat_hunting.py` — Consultas en lenguaje natural

Modo interactivo donde el analista escribe preguntas en español. El LLM las traduce a queries DSL de OpenSearch con timestamps absolutos calculados en tiempo de ejecución y el middleware las ejecuta contra el Indexer.

```
🔍 [HUNTING] > intentos de fuerza bruta SSH de las últimas 6 horas
[~] Query DSL generada: {"size":10,"query":{"bool":{"must":[...]}}}
[~] Consultando el Indexer de Wazuh...

  RESULTADOS: 3 evento(s) encontrado(s)
  [1] 2026-07-26T08:43:45Z | Ubuntu-Victima | Nivel 10 | 45.33.32.156
```

---

### Interfaz web (Streamlit)

Dashboard interactivo que expone los tres modos de operación sin necesidad de usar la línea de comandos.

```bash
streamlit run Home.py
```

Páginas disponibles:

- **Home** — estado de las conexiones (API Gestión + Indexer) y feed de alertas recientes.
- **Alertas** — tabla filtrable por severidad con detalle completo de cada evento y su JSON.
- **Análisis con LLM** — selección de proveedor (Ollama / Gemini Flash / Groq), configuración de alertas y visualización del informe con métricas de tiempo y tokens. Incluye respuesta activa con confirmación.
- **Threat Hunting** — consultas en lenguaje natural con visualización de los resultados en tabla.

---

## Soporte multi-modelo

| Proveedor | Modelo | Modo |
|---|---|---|
| Ollama (local) | Llama 3.2 | Sin internet, datos privados |
| Google AI | Gemini Flash | API externa |
| Groq | Llama 3.3-70B | API externa, alta velocidad |

El proveedor se selecciona en la interfaz web o mediante las variables de entorno `WZ_OLLAMA_URL` / `WZ_GEMINI_KEY` / `WZ_GROQ_KEY`.

---

## Instalación

### Requisitos previos

- Python 3.10 o superior
- Wazuh 4.9 o superior desplegado (ver sección Infraestructura)
- Ollama con un modelo descargado, o claves de API para Gemini/Groq

### Clonar e instalar

```bash
git clone https://github.com/maximartinm/TFG-Wazuh-LLM.git
cd TFG-Wazuh-LLM
python3 -m venv venv
source venv/bin/activate       # Linux/macOS
pip install -e .
```

### Configurar variables de entorno

Crea un archivo `.env` en la raíz del proyecto a partir de `.env.example`:

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

# Ollama (modelo local)
WZ_OLLAMA_URL=http://localhost:11434/api/generate
WZ_MODELO=llama3.2

# Proveedores externos (opcional)
WZ_GEMINI_KEY=tu_clave_gemini
WZ_GROQ_KEY=tu_clave_groq

# Ruta al archivo de prompt
WZ_PROMPT_PATH=prompts/mitre_prompt.txt
```

### Verificar instalación

```bash
wazuh-ia --help
```

---

## Infraestructura de laboratorio

**Wazuh (Docker — single-node)**
```bash
git clone https://github.com/wazuh/wazuh-docker.git -b 4.9.0
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

## Vectores de ataque evaluados

| Ataque | Regla Wazuh | MITRE | Agente |
|---|---|---|---|
| Fuerza bruta SSH | 5710 / 5503 | T1110.001 | Ubuntu |
| Login SSH exitoso tras fuerza bruta | — | T1078 | Ubuntu |
| Escaneo de puertos (nmap) | — | T1046 | Ubuntu |
| Escalada de privilegios (sudo) | 5404 | T1548.003 | Ubuntu |
| Creación de usuario no autorizado | — | T1136.001 | Ubuntu |

---

## Estado del desarrollo

- [x] Transformación de alertas en informes legibles con contexto MITRE ATT&CK
- [x] Correlación con Kill Chain e inferencia de objetivos del atacante
- [x] Respuesta activa con confirmación human-in-the-loop
- [x] Threat hunting mediante consultas en lenguaje natural
- [x] Interfaz web con soporte multi-modelo (Ollama / Gemini / Groq)

---

## Estructura del repositorio

```
TFG-Wazuh-LLM/
├── wazuh_llm/
│   ├── __init__.py
│   ├── middleware.py          # Orquestador principal
│   ├── nav.py                 # Barra de navegación web
│   ├── respuesta_activa.py    # Módulo de bloqueo
│   └── threat_hunting.py      # Consultas en lenguaje natural
├── pages/
│   ├── 1_Alertas.py           # Explorador de alertas
│   ├── 2_Analisis_LLM.py      # Análisis con LLM
│   └── 3_Threat_Hunting.py    # Hunting interactivo
├── prompts/
│   └── mitre_prompt.txt       # Plantilla de análisis forense
├── Home.py                    # Dashboard principal (Streamlit)
├── tests/
│   └── test_middleware.py      # Tests unitarios (pytest)
├── .env.example               # Plantilla de configuración
├── .gitignore
├── pyproject.toml
└── README.md
```

---

## Licencia

MIT — ver [LICENSE](LICENSE) para más detalles.
