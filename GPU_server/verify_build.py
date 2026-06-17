#!/usr/bin/env python3
"""Pre-build checks for GPU_server Docker image. Run on the GPU host before compose build."""
import json
import os
import subprocess
import sys
import time


def _agent_debug_log(location, message, data, hypothesis_id, run_id='pre-fix'):
    payload = {
        'sessionId': '45cf15',
        'timestamp': int(time.time() * 1000),
        'location': location,
        'message': message,
        'data': data,
        'hypothesisId': hypothesis_id,
        'runId': run_id,
    }
    # #region agent log
    debug_log = os.environ.get('AGENT_DEBUG_LOG', '')
    if not debug_log:
        base = os.path.dirname(os.path.abspath(__file__))
        debug_log = os.path.normpath(os.path.join(base, '..', '.cursor', 'debug-45cf15.log'))
    try:
        log_dir = os.path.dirname(debug_log)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        with open(debug_log, 'a', encoding='utf-8') as handle:
            handle.write(json.dumps(payload) + '\n')
    except OSError:
        pass
    # #endregion
    print(f'[verify_build] {message}: {data}')


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    required_files = [
        'Dockerfile',
        'requirements.txt',
        'gpu_config.py',
        'gpu_worker.py',
        'config/gpu_server.json',
        'docker-compose.yml',
    ]
    missing = []
    present = []
    for rel_path in required_files:
        full_path = os.path.join(base_dir, rel_path)
        if os.path.isfile(full_path):
            present.append(rel_path)
        else:
            missing.append(rel_path)

    _agent_debug_log(
        'verify_build.py:files',
        'Required build files',
        {'base_dir': base_dir, 'present': present, 'missing': missing},
        'A',
    )

    compose_ok = False
    compose_error = ''
    try:
        result = subprocess.run(
            ['docker', 'compose', 'config', '--quiet'],
            cwd=base_dir,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        compose_ok = result.returncode == 0
        compose_error = (result.stderr or result.stdout or '').strip()[:2000]
    except Exception as exc:
        compose_error = str(exc)

    _agent_debug_log(
        'verify_build.py:compose',
        'docker compose config',
        {'ok': compose_ok, 'error': compose_error},
        'C',
    )

    cwd = os.getcwd()
    _agent_debug_log(
        'verify_build.py:cwd',
        'Working directory',
        {'cwd': cwd, 'expected_gpu_server_dir': base_dir, 'cwd_matches': os.path.samefile(cwd, base_dir)},
        'E',
    )

    if missing:
        print('FAIL: missing files required for docker build:', ', '.join(missing), file=sys.stderr)
        print('Sync GPU_server from git (need gpu_config.py and config/gpu_server.json).', file=sys.stderr)
        return 1
    if not compose_ok:
        print('FAIL: docker compose config validation failed.', file=sys.stderr)
        if compose_error:
            print(compose_error, file=sys.stderr)
        return 2
    print('OK: build context looks complete. Run: docker compose build gpu-worker')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
