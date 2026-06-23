import re

import json_repair

from .debug_runtime import debug_log
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
    # #region agent log
    debug_log(
        'enriched_report/json_response.py:extract_json',
        'Prepared JSON candidate from LLM text',
        {
            'input_chars': len(str(text or '')),
            'candidate_chars': len(candidate),
            'candidate_preview': candidate[:200],
        },
        'initial-debug',
        'H2',
    )
    # #endregion
    if not candidate:
        raise EnrichedLLMError('LLM returned an empty response.')
    try:
        result = json_repair.loads(candidate)
    except (ValueError, TypeError) as exc:
        raise EnrichedLLMError(str(exc)) from exc
    # #region agent log
    debug_log(
        'enriched_report/json_response.py:extract_json',
        'Parsed JSON candidate',
        {
            'result_type': type(result).__name__,
            'result_is_empty_string': result == '',
            'result_is_none': result is None,
            'result_keys': sorted(result.keys()) if isinstance(result, dict) else None,
            'result_length': len(result) if hasattr(result, '__len__') else None,
        },
        'initial-debug',
        'H2',
    )
    # #endregion
    if result == '' or result is None:
        raise EnrichedLLMError('LLM returned empty JSON.')
    return result
