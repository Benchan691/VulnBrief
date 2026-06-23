import json
import logging

from jsonschema import ValidationError
from jsonschema import validate

from .json_response import extract_json
from .llama_client import EnrichedLlamaClient, EnrichedLLMError
from .prompts import resolve_prompt
from .schemas import ENRICHED_REPORT_SCHEMA, validate_enriched_report
from .section_parsers import (
    build_appendix,
    build_vulnerability_detail_table,
)

logger = logging.getLogger(__name__)


SECTION_SCHEMAS = {
    'vulnerability_detail_table': ENRICHED_REPORT_SCHEMA['properties']['vulnerability_detail_table'],
    'remediation_playbook': ENRICHED_REPORT_SCHEMA['properties']['remediation_playbook'],
    'appendix': ENRICHED_REPORT_SCHEMA['properties']['appendix'],
    'weekly_risk_trend': ENRICHED_REPORT_SCHEMA['properties']['weekly_risk_trend'],
    'research_scope': ENRICHED_REPORT_SCHEMA['properties']['research_scope'],
    'executive_summary': ENRICHED_REPORT_SCHEMA['properties']['executive_summary'],
    'management_brief': ENRICHED_REPORT_SCHEMA['properties']['management_brief'],
}

DETERMINISTIC_SECTIONS = frozenset({'vulnerability_detail_table', 'appendix'})

SECTION_JSON_EXAMPLES = {
    'executive_summary': {
        'summary': '<paragraph>',
        'key_findings': ['<finding>'],
    },
    'research_scope': {
        'summary': '<paragraph>',
        'criteria': ['<criterion>'],
    },
    'weekly_risk_trend': {
        'summary': '<paragraph>',
        'trend_points': ['<trend point>'],
    },
    'management_brief': {
        'summary': '<paragraph>',
        'business_impact': '<paragraph>',
        'decisions_needed': ['<decision>'],
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


def _section_prompt(section_name, cards, metrics, evidence_cards, language, config):
    return json.dumps({
        'section_name': section_name,
        'language': language,
        'instructions': resolve_prompt(config, 'report_section_user_instructions'),
        'vulnerability_cards': _card_payload(cards),
        'report_metrics': metrics,
        'evidence_references': _evidence_payload(evidence_cards),
    }, ensure_ascii=False, default=str)


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


def _parse_and_validate_json_section(section_name, text, schema):
    section = extract_json(text)
    validate(instance=section, schema=schema)
    return section


def _generate_text_section(section_name, cards, metrics, evidence_cards, client, language, config):
    schema = SECTION_SCHEMAS[section_name]
    system = _section_system_prompt(section_name, config)
    user_prompt = _section_prompt(section_name, cards, metrics, evidence_cards, language, config)
    text, _ = client.complete_text(
        system,
        user_prompt,
        max_output_tokens=client.report_max_output_tokens,
    )
    try:
        return _parse_and_validate_json_section(section_name, text, schema)
    except EnrichedLLMError:
        raise
    except (ValidationError, TypeError, ValueError) as exc:
        raise EnrichedLLMError(str(exc)) from exc


def _generate_section(section_name, cards, metrics, evidence_cards, client, language, config):
    schema = SECTION_SCHEMAS[section_name]
    if section_name in DETERMINISTIC_SECTIONS:
        section = _build_deterministic_section(section_name, cards, metrics, evidence_cards)
        validate(instance=section, schema=schema)
        return section
    return _generate_text_section(section_name, cards, metrics, evidence_cards, client, language, config)


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
        'remediation_playbook',
        'appendix',
        'weekly_risk_trend',
        'research_scope',
        'executive_summary',
        'management_brief',
    )
    total_sections = len(section_names)

    for index, section_name in enumerate(section_names, start=1):
        logger.info(
            'enriched llm report section task %d/%d section=%s',
            index,
            total_sections,
            section_name,
        )
        sections[section_name] = _generate_section(
            section_name, cards, report_metrics, evidence_cards, client, report_language, config,
        )
        if progress_callback is not None:
            progress_callback(
                index,
                total_sections,
                f'Generated report section {section_name}',
            )

    report = {
        'title': 'Weekly Cybersecurity Intelligence Report',
        **sections,
    }
    return validate_enriched_report(report)
