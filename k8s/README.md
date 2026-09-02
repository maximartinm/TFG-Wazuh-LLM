# Despliegue en Kubernetes (kind sobre podman)

Runbook para desplegar el dashboard Streamlit del TFG en un cluster local de
kind usando **podman** como toolkit de contenedores, manteniendo **Wazuh y
Ollama fuera del cluster**. El razonamiento completo del diseño está en
[`../plan-k8s.txt`](../plan-k8s.txt).

## Arquitectura

```
┌──────────── kind cluster (dentro de la podman machine) ───────────┐
│                                                                   │
│  Ingress nginx ──► Service ──► Deployment wazuh-llm (1 pod)       │
│  :8080 / :8443                 └─ streamlit run Home.py :8501     │
│                                            │                      │
│                Services SIN selector +     │                      │
│                EndpointSlice manuales  ◄───┘                      │
│                  wazuh-manager :55000                             │
│                  wazuh-indexer :9200                              │
│                  ollama        :11434                             │
└────────────────────────────┬──────────────────────────────────────┘
                             │ IP LAN del host
             ┌───────────────┴───────────────┐
             │  Wazuh (docker/podman compose)│
             │  Ollama (brew, Apple Silicon) │
             └───────────────────────────────┘
```

Ollama se queda fuera porque el cluster corre dentro de la VM de podman en
macOS y **un pod no puede acceder a la GPU Metal de Apple Silicon**: meterlo en
el cluster significaría inferencia solo-CPU.

## Requisitos previos

- `podman` con la máquina arrancada (`podman machine start`)
- `kind` y `kubectl` (>= 1.27, por `EndpointSlice`):

  ```bash
  brew install kind kubernetes-cli
  ```

- Wazuh 4.9 corriendo en el host y publicando 55000 y 9200
- Ollama corriendo en el host **y escuchando en todas las interfaces**:

  ```bash
  launchctl setenv OLLAMA_HOST 0.0.0.0
  brew services restart ollama
  ```

  Por defecto Ollama solo escucha en `127.0.0.1` y no sería alcanzable desde
  el cluster.

> **kind usa docker por defecto.** Hay que seleccionar podman explícitamente en
> **cada** invocación de `kind`:
>
> ```bash
> export KIND_EXPERIMENTAL_PROVIDER=podman
> ```
>
> Añádelo a tu `~/.zshrc` para no tener que repetirlo.

> **Memoria de la VM.** La podman machine de esta máquina tiene 3 GiB. El
> cluster + ingress-nginx + la app caben, pero van justos. Si ves pods en
> `Evicted` u `OOMKilled`:
> `podman machine stop && podman machine set --memory 6144 && podman machine start`.

## Despliegue

### 1. Crear el cluster y el ingress

```bash
export KIND_EXPERIMENTAL_PROVIDER=podman
kind create cluster --config k8s/kind-cluster.yaml

kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml

kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=180s
```

### 2. Construir y cargar la imagen

No hay registry: la imagen se inyecta directamente en el nodo de kind. Con
podman se hace vía archivo, que es el camino fiable independientemente de la
versión de kind:

```bash
podman build -t localhost/wazuh-llm:0.1.0 .
podman save localhost/wazuh-llm:0.1.0 -o /tmp/wazuh-llm.tar
kind load image-archive /tmp/wazuh-llm.tar --name wazuh-llm
```

`kind load docker-image` también suele funcionar con el proveedor podman, pero
`image-archive` no depende de que kind sepa hablar con el almacén de podman.

> **El prefijo `localhost/` no es opcional.** podman nombra las imágenes
> locales como `localhost/<nombre>`, y ese es el nombre que viaja dentro del
> archive. Los manifiestos referencian `localhost/wazuh-llm:0.1.0` justo por
> eso: sin el prefijo, containerd normalizaría a
> `docker.io/library/wazuh-llm:0.1.0` e intentaría descargarla de Docker Hub,
> con el consiguiente `ErrImagePull`.

Comprobar que la imagen llegó al nodo:

```bash
podman exec wazuh-llm-control-plane crictl images | grep wazuh-llm
```

### 3. Configurar credenciales e IP del host

```bash
cp k8s/.env.k8s.example k8s/.env.k8s
$EDITOR k8s/.env.k8s          # contraseñas de Wazuh y claves de API
```

Los manifiestos apuntan a `192.168.1.3`. Si tu IP cambia (es DHCP), hay que
actualizarla en **tres** sitios:

```bash
# La interfaz activa puede ser en0 (Ethernet) o en1 (Wi-Fi)
ipconfig getifaddr en1 || ipconfig getifaddr en0
```

| Fichero | Campo |
|---|---|
| `k8s/externals.yaml` | las tres `addresses:` de los EndpointSlice |
| `k8s/configmap.yaml` | `WZ_MANAGER_IP` (alimenta la lista blanca del guardrail) |
| `k8s/networkpolicy.yaml` | el `ipBlock` de egress |

No uses `127.0.0.1`: dentro de un pod se refiere al propio pod. Tampoco
`host.containers.internal`: apunta a la VM de podman, no a macOS.

### 4. Aplicar

```bash
kubectl apply -k k8s/
kubectl rollout status deploy/wazuh-llm -n wazuh-llm
```

Abrir **<http://wazuh-llm.localtest.me:8080>** — el dominio `localtest.me`
resuelve siempre a `127.0.0.1`, no hay que tocar `/etc/hosts`. El puerto es
8080 y no 80 porque podman corre rootless y no puede publicar puertos
privilegiados (ver `kind-cluster.yaml`).

Alternativa sin Ingress:

```bash
kubectl port-forward -n wazuh-llm svc/wazuh-llm 8501:80
```

## Operación

**Reconstruir tras cambiar el código** — hay que recargar la imagen y forzar
el rollout, porque la etiqueta no cambia:

```bash
podman build -t localhost/wazuh-llm:0.1.0 .
podman save localhost/wazuh-llm:0.1.0 -o /tmp/wazuh-llm.tar
kind load image-archive /tmp/wazuh-llm.tar --name wazuh-llm
kubectl rollout restart deploy/wazuh-llm -n wazuh-llm
```

**Tras editar el ConfigMap** — no lleva sufijo hash, así que no dispara
rollout solo:

```bash
kubectl rollout restart deploy/wazuh-llm -n wazuh-llm
```

Cambiar `k8s/.env.k8s` **sí** dispara rollout automático (el Secret lo genera
kustomize con sufijo hash).

**CLI interactiva** — no se despliega como workload; se ejecuta contra el pod:

```bash
kubectl exec -it -n wazuh-llm deploy/wazuh-llm -- \
  wazuh-ia --proveedor groq --alertas 3

# Threat hunting en lenguaje natural
kubectl exec -it -n wazuh-llm deploy/wazuh-llm -- \
  wazuh-ia --proveedor ollama --hunting
```

**Triaje programado** — `cronjob-batch.yaml` se entrega suspendido:

```bash
kubectl patch cronjob wazuh-llm-batch -n wazuh-llm -p '{"spec":{"suspend":false}}'
kubectl logs -n wazuh-llm -l app.kubernetes.io/component=batch
```

## Diagnóstico

**El pod arranca pero el dashboard muestra las dos conexiones en rojo.** Es un
problema de alcance al host, no de la app. Comprobar desde dentro del pod:

```bash
kubectl exec -it -n wazuh-llm deploy/wazuh-llm -- \
  python -c "import requests; print(requests.get('https://wazuh-indexer:9200', verify=False).status_code)"
```

Si falla, revisar que la IP de `externals.yaml` es la del host y que Wazuh
publica los puertos en esa interfaz (no solo en `localhost`). Recuerda que hay
dos saltos de red: pod → VM de podman → macOS.

**Ollama da connection refused.** Casi siempre es `OLLAMA_HOST`: sin `0.0.0.0`
solo acepta conexiones locales. Verificar con `lsof -iTCP:11434 -sTCP:LISTEN`
en el host.

**El análisis se queda en blanco tras ~1 minuto.** Timeout del proxy. Las
anotaciones `proxy-read-timeout: 300` de `ingress.yaml` existen justo para
esto; comprobar que se aplicaron con
`kubectl describe ingress wazuh-llm -n wazuh-llm`.

**`ErrImagePull` / `ImagePullBackOff`.** La imagen no llegó al nodo. Repetir el
paso 2 y verificar con `crictl images`. El nombre del cluster es `wazuh-llm`.

**`kind create cluster` falla o usa docker.** Falta
`export KIND_EXPERIMENTAL_PROVIDER=podman`, o la podman machine está parada
(`podman machine start`).

**El puerto 8080 no responde.** Comprobar el mapeo del nodo con
`podman port wazuh-llm-control-plane`.

## Limitaciones conocidas

- **La NetworkPolicy no filtra nada en un kind estándar.** kindnet, el CNI por
  defecto, no implementa NetworkPolicy: el manifiesto se aplica sin error pero
  es un no-op. Para que surta efecto hay que crear el cluster con
  `disableDefaultCNI: true` (ver `kind-cluster.yaml`) e instalar Calico.
- **Puertos 8080/8443 en vez de 80/443**, por el modo rootless de podman.
- **Una sola réplica.** `st.session_state` vive en memoria del proceso; escalar
  exigiría sticky sessions o externalizar el estado.
- **Sin autenticación.** Quien alcance el Ingress puede lanzar la respuesta
  activa (bloqueo de IPs). En `ingress.yaml` quedan preparadas y comentadas las
  anotaciones de basic auth.
- **TLS sin verificar** contra Wazuh (`verify=False`, certificados
  autofirmados del laboratorio).
