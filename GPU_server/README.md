# Standalone GPU Preprocessor

This folder runs an Atlas-only vulnerability preprocessing worker and a local
`llama.cpp` inference server. It targets Ubuntu with three NVIDIA RTX 2080 SUPER
GPUs. The ASPEED display adapter is not used.

The existing webserver continues to route tasks, process uploads and overflow
with Company AI, and create final report summaries with Company AI.

## Ubuntu Setup

1. Install a supported NVIDIA driver and verify all three cards with `nvidia-smi`.
2. Install Docker Engine and the NVIDIA Container Toolkit.
3. Configure and verify the NVIDIA Docker runtime:

   ```sh
   sudo nvidia-ctk runtime configure --runtime=docker
   sudo systemctl restart docker
   docker run --rm --gpus all ubuntu nvidia-smi
   ```

4. Copy this `GPU_server` folder to the GPU machine.

## Model And Configuration

Place a multilingual instruction-tuned GGUF model in `models/`. A Qwen 14B
Q4-class GGUF is the recommended starting point for the three 8 GB cards. Model
files are ignored by Git and are never downloaded automatically.

```sh
cp .env.example .env
chmod 600 .env
```

Set the Atlas URI, RabbitMQ URI, `AI_TASK_COLLECTION`, and `GPU_MODEL_PATH`. Queue names,
`PREPROCESSING_CACHE_VERSION`, and report compaction settings must match the
webserver.

- Start `GPU_WORKER_CONCURRENCY` at `1`.
- `GPU_MAX_TASK_ATTEMPTS` controls attempts before queued Company AI fallback.
- `GPU_FINAL_SUMMARY_PROMPT` configures queued final report-summary generation.
- `GPU_TENSOR_SPLIT` distributes model layers across NVIDIA GPUs `0,1,2`.
- Set `GPU_ENABLED` and `COMPANY_AI_ENABLED` to match the webserver router.
- `GPU_START_PROMPT` is sent and ignored before every task JSON.

## Start And Verify

```sh
docker compose pull
docker compose build
docker compose up -d
docker compose ps
docker compose logs -f llama-server gpu-worker
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/v1/models
docker exec gpu-preprocessor-llama nvidia-smi
```

Monitor RabbitMQ queues `gpu_preprocessing` and `company_ai_processing`.
Confirm an English task and a Chinese task complete with
`html_json.<language>.provider` set to `gpu_local`.

## Operations

```sh
docker compose restart gpu-worker
docker compose restart llama-server
docker compose down
docker compose up -d
```

The GPU worker preserves durable queue messages and recovers stale Atlas claims.
Use `company_ai_preprocessor.py --purge-queues` only when queued work must be
intentionally discarded. Increase
`PREPROCESSING_CACHE_VERSION` on both deployments when preprocessing changes
should invalidate existing caches.
