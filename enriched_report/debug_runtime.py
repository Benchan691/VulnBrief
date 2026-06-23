import json
import urllib.request
from uuid import uuid4


_DEBUG_URL = 'http://host.docker.internal:7930/ingest/963a9c32-06bb-450a-a312-2a970a022ece'


def debug_log(location, message, data, run_id, hypothesis_id):
    payload = {
        'sessionId': '9775a4',
        'id': f'log_{uuid4().hex}',
        'timestamp': __import__('time').time_ns() // 1_000_000,
        'location': location,
        'message': message,
        'data': data,
        'runId': run_id,
        'hypothesisId': hypothesis_id,
    }
    request = urllib.request.Request(
        _DEBUG_URL,
        data=json.dumps(payload, ensure_ascii=False, default=str).encode('utf-8'),
        headers={
            'Content-Type': 'application/json',
            'X-Debug-Session-Id': '9775a4',
        },
        method='POST',
    )
    try:
        with urllib.request.urlopen(request, timeout=2):
            pass
    except Exception:
        pass
