# Standalone GPU Preprocessor

This folder runs an Atlas-only vulnerability preprocessing worker and a single
tensor-split `llama.cpp` inference server. One 30B model is spread across GPUs
with `--tensor-split 1,1,1`.

The webserver continues to route tasks, process uploads and overflow with
Company AI, and create final report summaries with Company AI.

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

## Configuration

Non-sensitive settings live in [`config/gpu_server.json`](config/gpu_server.json).
Secrets live only in `.env`:

```sh
cp .env.example .env
chmod 600 .env
```

Set `ATLAS_MONGO_URI` and `RABBITMQ_URL` in `.env`. Everything else (model path,
queues, prompts, report compaction, timeouts) is read from `config/gpu_server.json`.

Default model file name:

`models/Qwen3_Qwen3_30B-A3B-Instruct-2507_Q4_K_M.gguf`

Place the GGUF in `models/`. Model files are ignored by Git and are never
downloaded automatically.

Optional: set `GPU_SERVER_CONFIG` in `.env` to point at a different JSON file.

### Webserver alignment

Match these in **webserver** `.env` so the router load-balances correctly:

```env
GPU_ENABLED=true
GPU_WORKER_CONCURRENCY=1
RABBITMQ_GPU_QUEUE=gpu_processing
PREPROCESSING_CACHE_VERSION=1
REPORT_MAX_DEPTH=10
```

Queue names, `PREPROCESSING_CACHE_VERSION`, and report compaction settings in
`config/gpu_server.json` must match the webserver.

## Start

```sh
docker compose up -d --build
docker compose logs -f llama-server gpu-worker
curl http://127.0.0.1:8080/health
```

The `gpu-worker` container reads `config/gpu_server.json` and reaches llama via
`host.docker.internal:8080` (published host port).

## Native host worker (optional)

Outside Docker, run:

```sh
python gpu_worker.py
```

The worker auto-starts native `llama-server` processes when configured in JSON
(`auto_start_llama_servers`) and uses `http://127.0.0.1:8080/v1`.

## Operations

```sh
docker compose restart gpu-worker
docker compose restart llama-server
docker compose down
docker compose up -d
```

The GPU worker preserves durable queue messages and recovers stale Atlas claims.
Use `company_ai_preprocessor.py --purge-queues` only when queued work must be
intentionally discarded. Increase `processing.cache_version` in
`config/gpu_server.json` (and webserver `PREPROCESSING_CACHE_VERSION`) when
preprocessing changes should invalidate existing caches.
