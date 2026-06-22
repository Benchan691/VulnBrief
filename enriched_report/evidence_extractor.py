import json
import logging
from datetime import datetime, timezone

from .evidence_cache import lookup_cached_payload, store_cached_payload
from .llama_client import EnrichedLlamaClient, EnrichedLLMError
from .pipeline_collections import collection
from .schemas import TASK_TYPES, validate_source_evidence_card

logger = logging.getLogger(__name__)

_UNCONFIRMED_PREFIX = 'not confirmed'


def _is_unconfirmed(value):
    if value is None:
        return True
    if isinstance(value, str):
        normalized = value.strip().lower()
        return not normalized or normalized == 'n/a' or normalized.startswith(_UNCONFIRMED_PREFIX)
    return False


def _nullable_string(value):
    if _is_unconfirmed(value):
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return str(value) if value is not None else None


def _nullable_bool(value):
    if _is_unconfirmed(value) or value is None or value == '':
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {'true', 'yes', '1'}:
            return True
        if normalized in {'false', 'no', '0'}:
            return False
    return None


def _nullable_number(value):
    if _is_unconfirmed(value) or value is None or value == '':
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        try:
            return float(stripped) if '.' in stripped else int(stripped)
        except ValueError:
            return None
    return None


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, '')]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _prompt(result, candidate, page_char_limit):
    page_content = (result.get('page_content') or result.get('snippet') or '')[:page_char_limit]
    source = {
        'url': result.get('url'),
        'title': result.get('title'),
        'page_content': page_content,
    }
    # Avoid duplicating Tavily snippet when full page_content is already present.
    if not result.get('page_content') and result.get('snippet'):
        source['snippet'] = page_content
    task_type = result['task_type']
    system = (
        'You extract cybersecurity evidence from one source page. Use only the supplied page '
        'content. Do not infer or invent facts. Answer only the requested task_type in plain text. '
        'Write 2-4 sentences maximum. If the page does not support an answer, return exactly: NULL. '
        'Do not return JSON, markdown, bullet lists, or field labels.'
    )
    user = {
        'task_type': task_type,
        'cve_id': candidate['cve_id'],
        'candidate': {
            'vendor': candidate.get('vendor'),
            'product': candidate.get('product'),
            'title': candidate.get('title'),
        },
        'source': source,
    }
    return system, json.dumps(user, ensure_ascii=False, default=str)


def _parse_text_response(text, task_type):
    if task_type not in TASK_TYPES:
        return {}
    cleaned = (text or '').strip()
    if not cleaned or cleaned.upper() == 'NULL':
        return {}
    return {
        task_type: cleaned,
        'confidence': 'medium',
    }


def _unwrap_card_payload(raw):
    if not isinstance(raw, dict):
        return raw or {}
    for key in ('required_output', 'card', 'result', 'data'):
        nested = raw.get(key)
        if isinstance(nested, dict):
            return nested
    return raw


def _normalize_card(raw, result):
    card = {
        'run_id': result['run_id'],
        'candidate_id': result['candidate_id'],
        'cve_id': result['cve_id'],
        'task_type': result['task_type'],
        'source_url': result.get('url') or '',
        'confidence': 'low',
        'title': None,
        'what_happened': None,
        'why_matters': None,
        'how_to_respond': None,
        'affected_versions': [],
        'fixed_versions': [],
        'cvss_score': None,
        'cvss_vector': None,
        'exploit_status': None,
        'cisa_kev': None,
        'epss': None,
        'business_impact': None,
        'references': [],
        'extracted_at': _now_iso(),
    }
    card.update(_unwrap_card_payload(raw))
    card.update({
        'run_id': result['run_id'],
        'candidate_id': result['candidate_id'],
        'cve_id': result['cve_id'],
        'task_type': result['task_type'],
        'source_url': result.get('url') or card.get('source_url') or '',
        'extracted_at': card.get('extracted_at') or _now_iso(),
        'title': _nullable_string(card.get('title')),
        'what_happened': _nullable_string(card.get('what_happened')),
        'why_matters': _nullable_string(card.get('why_matters')),
        'how_to_respond': _nullable_string(card.get('how_to_respond')),
        'cvss_score': _nullable_number(card.get('cvss_score')),
        'cvss_vector': _nullable_string(card.get('cvss_vector')),
        'exploit_status': _nullable_string(card.get('exploit_status')),
        'cisa_kev': _nullable_bool(card.get('cisa_kev')),
        'epss': _nullable_number(card.get('epss')),
        'business_impact': _nullable_string(card.get('business_impact')),
    })
    if card.get('confidence') not in {'high', 'medium', 'low'}:
        card['confidence'] = 'low'
    card['affected_versions'] = _list(card.get('affected_versions'))
    card['fixed_versions'] = _list(card.get('fixed_versions'))
    card['references'] = _list(card.get('references')) or [card['source_url']]
    return validate_source_evidence_card(card)


def extract_evidence_cards(web_database, run_id, config, client=None, progress_callback=None):
    candidates = {
        item['candidate_id']: item
        for item in collection(web_database, 'candidate_vulnerability_items').find({'run_id': run_id})
    }
    results = list(collection(web_database, 'filtered_enrichment_results').find({'run_id': run_id}))
    client = client or EnrichedLlamaClient(config)
    page_char_limit = int(config.get('ENRICHED_LLM_PAGE_CHARS', 12000))
    cache_enabled = bool(config.get('ENRICHED_EVIDENCE_CACHE_ENABLED', True))
    cache_version = str(config.get('ENRICHED_EVIDENCE_CACHE_VERSION', '1'))
    cards = []
    total = len(results)
    cache_hits = 0
    for index, result in enumerate(results, start=1):
        candidate = candidates.get(result.get('candidate_id'))
        if candidate is None:
            continue
        cached_payload = None
        if cache_enabled:
            cached_payload = lookup_cached_payload(web_database, result, cache_version)
        if cached_payload is not None:
            cache_hits += 1
            logger.info(
                'enriched llm evidence cache hit %d/%d cve=%s task_type=%s url=%s',
                index,
                total,
                result.get('cve_id'),
                result.get('task_type'),
                result.get('url'),
            )
            cards.append(_normalize_card(cached_payload, result))
            if progress_callback is not None:
                progress_callback(
                    index,
                    total,
                    f'Evidence cache hit {index}/{total} {result.get("cve_id")} {result.get("task_type")}',
                )
            continue
        logger.info(
            'enriched llm evidence task %d/%d cve=%s task_type=%s',
            index,
            total,
            result.get('cve_id'),
            result.get('task_type'),
        )
        system, prompt = _prompt(result, candidate, page_char_limit)
        extracted = False
        try:
            text, _ = client.complete_text(
                system,
                prompt,
                max_output_tokens=client.evidence_max_output_tokens,
            )
            raw = _parse_text_response(text, result['task_type'])
            card = _normalize_card(raw, result)
            extracted = True
        except EnrichedLLMError as exc:
            logger.warning(
                'enriched llm evidence failed cve=%s task_type=%s url=%s error=%s',
                result.get('cve_id'),
                result.get('task_type'),
                result.get('url'),
                exc,
            )
            card = _normalize_card({}, result)
        if cache_enabled and extracted:
            store_cached_payload(web_database, result, card, cache_version)
        cards.append(card)
        if progress_callback is not None:
            progress_callback(
                index,
                total,
                f'Evidence extracted {index}/{total} {result.get("cve_id")} {result.get("task_type")}',
            )

    if cache_enabled:
        logger.info(
            'enriched evidence extraction complete run=%s total=%d cache_hits=%d llm_calls=%d',
            run_id,
            total,
            cache_hits,
            total - cache_hits,
        )

    target = collection(web_database, 'source_evidence_cards')
    target.delete_many({'run_id': run_id})
    if cards:
        target.insert_many(cards)
    return cards

