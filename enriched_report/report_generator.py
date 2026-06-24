import json
import logging
from string import Template

from jsonschema import ValidationError
from jsonschema import validate

from .debug_runtime import debug_log
from .json_response import extract_json
from .llama_client import EnrichedLlamaClient, EnrichedLLMError
from .prompts import resolve_prompt
from .schemas import ENRICHED_REPORT_SCHEMA, validate_enriched_report
from .section_parsers import (
    build_appendix,
    build_vulnerability_detail_table,
)
from .section_chunking import (
    chunk_card_count,
    chunk_cards,
    evidence_for_cve_ids,
    should_chunk_section,
)

logger = logging.getLogger(__name__)


SECTION_SCHEMAS = {
    'vulnerability_detail_table': ENRICHED_REPORT_SCHEMA['properties']['vulnerability_detail_table'],
    'remediation_playbook': ENRICHED_REPORT_SCHEMA['properties']['remediation_playbook'],
    'appendix': ENRICHED_REPORT_SCHEMA['properties']['appendix'],
    'weekly_risk_trend': ENRICHED_REPORT_SCHEMA['properties']['weekly_risk_trend'],
    'executive_summary': ENRICHED_REPORT_SCHEMA['properties']['executive_summary'],
}

DETERMINISTIC_SECTIONS = frozenset({'vulnerability_detail_table', 'appendix'})
TABLE_DERIVED_SECTIONS = frozenset({
    'executive_summary',
    'weekly_risk_trend',
    'remediation_playbook',
})
REMEDIATION_PLAYBOOK_SECTION = 'remediation_playbook'
PARTIALS_ONLY_MERGE_SECTIONS = frozenset({
    'executive_summary',
    'weekly_risk_trend',
    'remediation_playbook',
})

SECTION_JSON_EXAMPLES = {
    'executive_summary': {
        'summary': '<paragraph>',
        'key_findings': ['<finding>'],
    },
    'weekly_risk_trend': {
        'summary': '<paragraph>',
        'trend_points': ['<trend point>'],
    },
    'remediation_playbook': {
        'summary': '<paragraph>',
        'actions': [{
            'priority': '<priority>',
            'action': '<action>',
            'cve_ids': ['CVE-YYYY-NNNN'],
        }],
    },
}


def _card_payload(cards):
    return [
        {
            'cve_id': card.get('cve_id'),
            'title': card.get('title'),
            'vendor': card.get('vendor'),
            'product': card.get('product'),
            'severity': card.get('severity'),
            'what_happened': card.get('what_happened'),
            'why_matters': card.get('why_matters'),
            'how_to_respond': card.get('how_to_respond'),
            'priority_score': card.get('priority_score'),
            'patch_priority': card.get('patch_priority'),
            'source_references': card.get('source_references'),
            'missing_fields': card.get('missing_fields'),
            'conflicts': card.get('conflicts'),
        }
        for card in cards
    ]


def _row_payload(section_name, rows):
    if section_name == 'executive_summary':
        keys = (
            'cve_id', 'title', 'vendor', 'product', 'severity',
            'priority_score', 'patch_priority', 'what_happened',
        )
    elif section_name == 'remediation_playbook':
        keys = (
            'cve_id', 'title', 'vendor', 'product', 'severity',
            'priority_score', 'patch_priority', 'how_to_respond',
        )
    else:
        keys = ('cve_id', 'title', 'vendor', 'product', 'severity', 'why_matters')
    return [{key: row.get(key) for key in keys} for row in rows]


def _evidence_payload(evidence_cards):
    return [
        {
            'cve_id': card.get('cve_id'),
            'task_type': card.get('task_type'),
            'source_url': card.get('source_url'),
            'confidence': card.get('confidence'),
        }
        for card in evidence_cards
    ]


def _section_user_instructions(section_name, config):
    if section_name == REMEDIATION_PLAYBOOK_SECTION:
        return resolve_prompt(config, 'report_section_user_instructions_remediation_playbook')
    return resolve_prompt(config, 'report_section_user_instructions')


def _section_prompt(section_name, cards, metrics, evidence_cards, language, config):
    payload = {
        'section_name': section_name,
        'language': language,
        'instructions': _section_user_instructions(section_name, config),
    }
    if section_name in TABLE_DERIVED_SECTIONS:
        payload['vulnerability_rows'] = _row_payload(section_name, cards)
    else:
        raise ValueError(f'Unsupported LLM section prompt: {section_name}')
    return json.dumps(payload, ensure_ascii=False, default=str)


def _build_deterministic_section(section_name, cards, metrics, evidence_cards):
    if section_name == 'vulnerability_detail_table':
        return build_vulnerability_detail_table(cards)
    if section_name == 'appendix':
        return build_appendix(cards, evidence_cards, metrics)
    raise ValueError(f'Unsupported deterministic section: {section_name}')


def _section_json_example(section_name):
    return json.dumps(
        SECTION_JSON_EXAMPLES[section_name],
        ensure_ascii=False,
        indent=2,
    )


def _section_system_prompt(section_name, config):
    example = _section_json_example(section_name)
    return resolve_prompt(
        config,
        'report_section_system',
        section_example=example,
    )


def _merge_system_prompt(section_name, config):
    prompt_name = (
        'report_section_merge_system_remediation_playbook'
        if section_name == 'remediation_playbook'
        else 'report_section_merge_system'
    )
    return resolve_prompt(
        config,
        prompt_name,
        section_example=_section_json_example(section_name),
    )


def _merge_user_prompt(section_name, partials, cards, metrics, evidence_cards, language, config):
    instructions_name = (
        'report_section_merge_user_remediation_playbook'
        if section_name == 'remediation_playbook'
        else 'report_section_merge_user'
    )
    payload = {
        'section_name': section_name,
        'language': language,
        'instructions': resolve_prompt(config, instructions_name),
        'partial_sections': partials,
    }
    if section_name not in PARTIALS_ONLY_MERGE_SECTIONS:
        payload['vulnerability_cards'] = _card_payload(cards)
        payload['report_metrics'] = metrics
        payload['evidence_references'] = _evidence_payload(evidence_cards)
    return json.dumps(payload, ensure_ascii=False, default=str)


def _parse_and_validate_json_section(section_name, text, schema):
    section = extract_json(text)
    validate(instance=section, schema=schema)
    return section


def _json_repair_prompt(config, text, error):
    template = str(config.get('REPORT_JSON_ERROR_MESSAGE') or '')
    if not template:
        template = (
            'The JSON above is invalid.\n\nError:\n${error}\n\n'
            'Fix it and return only valid JSON. No Markdown, no explanation, no extra text. '
            'Keep the original fields and meaning. Make only the minimum changes needed so '
            'it can parse with `json.loads()`.'
        )
    return text + '\n\n' + Template(template).safe_substitute(error=str(error))


def _complete_json_section_with_retries(section_name, system, text, schema, client, config, retry_key='REPORT_ITEM_JSON_RETRIES'):
    retries = max(0, int(config.get(retry_key, 0)))
    for attempt in range(retries + 1):
        try:
            return _parse_and_validate_json_section(section_name, text, schema)
        except (EnrichedLLMError, ValidationError, TypeError, ValueError) as exc:
            if attempt >= retries:
                if isinstance(exc, EnrichedLLMError):
                    raise
                raise EnrichedLLMError(str(exc)) from exc
            # #region agent log
            debug_log(
                'enriched_report/report_generator.py:_complete_json_section_with_retries',
                'Retrying invalid report section JSON',
                {
                    'section_name': section_name,
                    'attempt': attempt + 1,
                    'max_attempts': retries + 1,
                    'error': str(exc),
                    'bad_response_preview': text[:200],
                },
                f'section-{section_name}',
                'H6',
            )
            # #endregion
            text, _ = client.complete_text(
                system,
                _json_repair_prompt(config, text, exc),
                max_output_tokens=client.report_max_output_tokens,
            )
            # #region agent log
            debug_log(
                'enriched_report/report_generator.py:_complete_json_section_with_retries',
                'Received retry report section text',
                {
                    'section_name': section_name,
                    'attempt': attempt + 2,
                    'response_chars': len(text),
                    'response_preview': text[:200],
                },
                f'section-{section_name}',
                'H6',
            )
            # #endregion


def _merge_section_partials_with_ai(
    section_name, partials, cards, metrics, evidence_cards, client, language, config,
    progress_callback=None, progress_current=None, progress_total=None,
):
    schema = SECTION_SCHEMAS[section_name]
    system = _merge_system_prompt(section_name, config)
    user_prompt = _merge_user_prompt(
        section_name, partials, cards, metrics, evidence_cards, language, config,
    )
    logger.info(
        'enriched llm report section merge section=%s chunks=%d',
        section_name,
        len(partials),
    )
    text, _ = client.complete_text(
        system,
        user_prompt,
        max_output_tokens=client.report_max_output_tokens,
    )
    merged = _complete_json_section_with_retries(
        section_name,
        system,
        text,
        schema,
        client,
        config,
        retry_key='REPORT_FINAL_JSON_RETRIES',
    )
    if progress_callback is not None:
        progress_callback(progress_current, progress_total, f'Merged report section {section_name}')
    return merged


def _generate_text_section_chunked(
    section_name, cards, metrics, evidence_cards, client, language, config,
    progress_callback=None, progress_current=None, progress_total=None,
):
    schema = SECTION_SCHEMAS[section_name]
    system = _section_system_prompt(section_name, config)
    card_batches = list(chunk_cards(cards, chunk_card_count(config)))
    partials = []
    total_chunks = len(card_batches)

    logger.info(
        'enriched llm report section chunking section=%s chunks=%d cards=%d',
        section_name,
        total_chunks,
        len(cards),
    )

    for chunk_index, card_batch in enumerate(card_batches, start=1):
        chunk_evidence_count = 0
        if section_name != REMEDIATION_PLAYBOOK_SECTION:
            chunk_cve_ids = {card.get('cve_id') for card in card_batch if card.get('cve_id')}
            chunk_evidence = evidence_for_cve_ids(evidence_cards, chunk_cve_ids)
            chunk_evidence_count = len(chunk_evidence)
        user_prompt = _section_prompt(
            section_name,
            card_batch,
            metrics,
            evidence_cards if section_name != REMEDIATION_PLAYBOOK_SECTION else [],
            language,
            config,
        )
        logger.info(
            'enriched llm report section chunk %d/%d section=%s cards=%d evidence=%d prompt_chars=%d',
            chunk_index,
            total_chunks,
            section_name,
            len(card_batch),
            chunk_evidence_count,
            len(user_prompt),
        )
        text, _ = client.complete_text(
            system,
            user_prompt,
            max_output_tokens=client.report_max_output_tokens,
        )
        partials.append(
            _complete_json_section_with_retries(
                section_name,
                system,
                text,
                schema,
                client,
                config,
            ),
        )

    if len(partials) == 1:
        return partials[0]
    return _merge_section_partials_with_ai(
        section_name, partials, cards, metrics, evidence_cards, client, language, config,
        progress_callback, progress_current, progress_total,
    )


def _generate_text_section(
    section_name, cards, metrics, evidence_cards, client, language, config,
    progress_callback=None, progress_current=None, progress_total=None,
):
    schema = SECTION_SCHEMAS[section_name]
    system = _section_system_prompt(section_name, config)
    user_prompt = _section_prompt(section_name, cards, metrics, evidence_cards, language, config)
    if should_chunk_section(section_name, len(user_prompt), len(cards), config):
        return _generate_text_section_chunked(
            section_name, cards, metrics, evidence_cards, client, language, config,
            progress_callback, progress_current, progress_total,
        )
    # #region agent log
    debug_log(
        'enriched_report/report_generator.py:_generate_text_section',
        'Starting report section generation',
        {
            'section_name': section_name,
            'language': language,
            'system_prompt_chars': len(system),
            'user_prompt_chars': len(user_prompt),
            'card_count': len(cards),
            'evidence_count': len(evidence_cards),
        },
        f'section-{section_name}',
        'H5',
    )
    # #endregion
    text, _ = client.complete_text(
        system,
        user_prompt,
        max_output_tokens=client.report_max_output_tokens,
    )
    # #region agent log
    debug_log(
        'enriched_report/report_generator.py:_generate_text_section',
        'Received report section text',
        {
            'section_name': section_name,
            'response_chars': len(text),
            'response_preview': text[:200],
        },
        f'section-{section_name}',
        'H3',
    )
    # #endregion
    return _complete_json_section_with_retries(
        section_name,
        system,
        text,
        schema,
        client,
        config,
    )


def _generate_section(
    section_name, cards, metrics, evidence_cards, client, language, config,
    progress_callback=None, progress_current=None, progress_total=None,
):
    schema = SECTION_SCHEMAS[section_name]
    if section_name in DETERMINISTIC_SECTIONS:
        section = _build_deterministic_section(section_name, cards, metrics, evidence_cards)
        validate(instance=section, schema=schema)
        return section
    return _generate_text_section(
        section_name, cards, metrics, evidence_cards, client, language, config,
        progress_callback, progress_current, progress_total,
    )


def generate_enriched_report(
    vulnerability_cards,
    report_metrics,
    evidence_cards,
    config,
    report_language='en',
    client=None,
    progress_callback=None,
):
    client = client or EnrichedLlamaClient(config)
    cards = sorted(vulnerability_cards, key=lambda item: item.get('priority_score', 0), reverse=True)
    sections = {}
    section_names = (
        'vulnerability_detail_table',
        'executive_summary',
        'weekly_risk_trend',
        'remediation_playbook',
        'appendix',
    )
    total_sections = len(section_names)

    for index, section_name in enumerate(section_names, start=1):
        logger.info(
            'enriched llm report section task %d/%d section=%s',
            index,
            total_sections,
            section_name,
        )
        section_cards = (
            sections['vulnerability_detail_table']['rows']
            if section_name in TABLE_DERIVED_SECTIONS
            else cards
        )
        sections[section_name] = _generate_section(
            section_name, section_cards, report_metrics, evidence_cards, client, report_language, config,
            progress_callback, index, total_sections,
        )
        if progress_callback is not None:
            progress_callback(
                index,
                total_sections,
                f'Generated report section {section_name}',
            )

    report = {
        'title': 'Weekly Cybersecurity Intelligence Report',
        'executive_summary': sections['executive_summary'],
        'weekly_risk_trend': sections['weekly_risk_trend'],
        'vulnerability_detail_table': sections['vulnerability_detail_table'],
        'remediation_playbook': sections['remediation_playbook'],
        'appendix': sections['appendix'],
    }
    return validate_enriched_report(report)
