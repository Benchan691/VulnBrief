import re

import json_repair

from .llama_client import EnrichedLLMError


def _json_candidate(text):
    cleaned = str(text or '').strip()
    if not cleaned:
        return ''
    match = re.search(r'```(?:json)?\s*(.*?)```', cleaned, flags=re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    start = cleaned.find('{')
    end = cleaned.rfind('}')
    if start != -1 and end != -1 and end > start:
        return cleaned[start:end + 1]
    start = cleaned.find('[')
    end = cleaned.rfind(']')
    if start != -1 and end != -1 and end > start:
        return cleaned[start:end + 1]
    return cleaned


def extract_json(text):
    candidate = _json_candidate(text)
    if not candidate:
        raise EnrichedLLMError('LLM returned an empty response.')
    try:
        result = json_repair.loads(candidate)
    except (ValueError, TypeError) as exc:
        raise EnrichedLLMError(str(exc)) from exc
    if result == '' or result is None:
        raise EnrichedLLMError('LLM returned empty JSON.')
    return result
