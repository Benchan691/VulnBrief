# Standalone GPU Preprocessor

This folder runs an Atlas-only vulnerability preprocessing worker and a local
`llama.cpp` inference server. It supports two deployment modes:

1. **tensor-split** — one model split across multiple GPUs (large models).
2. **per-gpu** — one model copy per GPU, one worker session per GPU (parallel throughput).

The existing webserver continues to route tasks, process uploads and overflow
with Company AI, and create final report summaries with Company AI.

## Ubuntu Setup

1. Install a supported NVIDIA driver and verify GPUs with `nvidia-smi`.
2. Install Docker Engine and the NVIDIA Container Toolkit.
3. Configure and verify the NVIDIA Docker runtime:

   ```sh
   sudo nvidia-ctk runtime configure --runtime=docker
   sudo systemctl restart docker
   docker run --rm --gpus all ubuntu nvidia-smi
   ```

4. Copy this `GPU_server` folder to the GPU machine.

## Model And Configuration

Place a multilingual instruction-tuned GGUF model in `models/`. Model files are
ignored by Git and are never downloaded automatically.

```sh
cp .env.example .env
chmod 600 .env
```

Set the Atlas URI, RabbitMQ URI, `AI_TASK_COLLECTION`, and `GPU_MODEL_PATH`. Queue names,
`PREPROCESSING_CACHE_VERSION`, and report compaction settings must match the
webserver.

In `.env`, escape `${language}` for Docker Compose as `$${language}` in
`GPU_FINAL_SUMMARY_PROMPT` (see `.env.example`). Otherwise Compose warns that
`language` is unset.

GPU services use `deploy.resources.reservations.devices` instead of the
top-level `gpus` key so older Compose schema validators accept the file. Requires
Docker Compose v2 with NVIDIA Container Toolkit.

Match `GPU_WORKER_CONCURRENCY` on the **webserver** `.env` to the number of GPU
worker sessions you run here so the router load-balances correctly.

## Deployment modes

### Per-GPU (one session per GPU)

Best when each GPU can hold a full copy of the model (for example 7B–8B Q4 on 8 GB cards).

In `GPU_server/.env`:

```env
GPU_INSTANCE_COUNT=3
GPU_WORKER_CONCURRENCY=3
GPU_ENABLED=true
```

Start:

```sh
docker compose --profile per-gpu up -d --build
docker compose logs -f llama-server-0 llama-server-1 llama-server-2 gpu-worker
```

Worker `0` uses `llama-server-0` (GPU 0), worker `1` → GPU 1, worker `2` → GPU 2.
Host health checks: `http://127.0.0.1:8080/health`, `:8081/health`, `:8082/health`.

The Docker `gpu-worker` service uses `host.docker.internal` and the published
host ports above so it does not depend on compose DNS names like `llama-server-0`.
Override with `GPU_INFERENCE_BASE_URLS` in `.env` if needed.

### Tensor-split (one model across GPUs)

Best for one large model that does not fit on a single card.

In `GPU_server/.env`:

```env
GPU_INSTANCE_COUNT=1
GPU_TENSOR_SPLIT=1,1,1
GPU_WORKER_CONCURRENCY=1
```

Start:

```sh
docker compose --profile tensor-split up -d --build
docker compose logs -f llama-server gpu-worker-tensor
curl http://127.0.0.1:8080/health
```

## Shared settings

- `GPU_MAX_TASK_ATTEMPTS` controls attempts before queued Company AI fallback.
- `GPU_FINAL_SUMMARY_PROMPT` configures queued final report-summary generation.
- Set `GPU_ENABLED` and `COMPANY_AI_ENABLED` to match the webserver router.
- `GPU_START_PROMPT` is sent and ignored before every task JSON.

## Operations

```sh
docker compose --profile per-gpu restart gpu-worker
docker compose --profile per-gpu restart llama-server-0 llama-server-1 llama-server-2
docker compose --profile per-gpu down
docker compose --profile per-gpu up -d
```

The GPU worker preserves durable queue messages and recovers stale Atlas claims.
Use `company_ai_preprocessor.py --purge-queues` only when queued work must be
intentionally discarded. Increase
`PREPROCESSING_CACHE_VERSION` on both deployments when preprocessing changes
should invalidate existing caches.
