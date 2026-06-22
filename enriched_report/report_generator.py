import json
import logging
from datetime import datetime, timezone

from .llama_client import EnrichedLlamaClient
from .schemas import ENRICHED_REPORT_SCHEMA, validate_enriched_report
from .verifier import verify_and_finalize_report

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


def _section_prompt(section_name, cards, metrics, evidence_cards, language):
    return json.dumps({
        'section_name': section_name,
        'language': language,
        'instructions': (
            'Use only vulnerability_cards, report_metrics, and evidence references. '
            'Do not use raw Tavily results. Do not invent facts. Use "Not confirmed from '
            'available sources." when evidence is missing.'
        ),
        'vulnerability_cards': _card_payload(cards),
        'report_metrics': metrics,
        'evidence_references': _evidence_payload(evidence_cards),
    }, ensure_ascii=False, default=str)


def _normalize_section(section_name, raw):
    if section_name in raw and isinstance(raw[section_name], dict):
        return raw[section_name]
    return raw


def _generate_section(section_name, cards, metrics, evidence_cards, client, language):
    system = (
        'You write one section of an enriched weekly cybersecurity report as valid JSON. '
        'Follow the provided JSON schema exactly.'
    )
    raw, _ = client.complete_json(
        system,
        _section_prompt(section_name, cards, metrics, evidence_cards, language),
        SECTION_SCHEMAS[section_name],
        f'enriched_{section_name}',
        max_output_tokens=client.report_max_output_tokens,
    )
    return _normalize_section(section_name, raw)


def generate_enriched_report(
    vulnerability_cards,
    report_metrics,
    evidence_cards,
    config,
    report_language='en',
    client=None,
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
            section_name, cards, report_metrics, evidence_cards, client, report_language,
        )

    report = {
        'title': 'Enriched Weekly Cybersecurity Report',
        **sections,
        'verification': {
            'python_checks': 'pending',
            'ai_checks': 'pending',
            'issues': [],
            'unsupported_claims': [],
            'verified_at': datetime.now(timezone.utc).isoformat(),
        },
    }
    validate_enriched_report(report)
    return verify_and_finalize_report(report, cards, report_metrics, evidence_cards, client)
