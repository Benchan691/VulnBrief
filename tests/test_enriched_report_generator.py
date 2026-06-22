import pytest

from enriched_report.section_parsers import (
    SectionParseError,
    build_appendix,
    build_vulnerability_detail_table,
    parse_executive_summary,
    parse_management_brief,
    parse_remediation_playbook,
    parse_research_scope,
    parse_unsupported_claims,
    parse_weekly_risk_trend,
)
from enriched_report.schemas import ENRICHED_REPORT_SCHEMA


def _sample_card():
    return {
        'cve_id': 'CVE-2026-7000',
        'title': 'Acme Widget RCE',
        'vendor': 'Acme',
        'product': 'Widget',
        'severity': 'Critical',
        'priority_score': 58,
        'patch_priority': 'Critical',
        'what_happened': 'Acme Widget has a remote code execution vulnerability.',
        'why_matters': 'Remote code execution can affect internet-facing systems.',
        'how_to_respond': 'Upgrade to version 2.0.',
        'source_references': ['https://acme.example/advisory'],
    }


def test_build_vulnerability_detail_table_maps_card_fields():
    table = build_vulnerability_detail_table([_sample_card()])

    row = table['rows'][0]
    assert row['cve_id'] == 'CVE-2026-7000'
    assert row['title'] == 'Acme Widget RCE'
    assert row['vendor'] == 'Acme'
    assert row['product'] == 'Widget'
    assert row['severity'] == 'Critical'
    assert row['priority_score'] == 58
    assert row['patch_priority'] == 'Critical'
    assert row['what_happened'] == 'Acme Widget has a remote code execution vulnerability.'
    assert row['why_matters'] == 'Remote code execution can affect internet-facing systems.'
    assert row['how_to_respond'] == 'Upgrade to version 2.0.'
    assert row['source_urls'] == ['https://acme.example/advisory']


def test_build_appendix_dedupes_urls_across_cards_and_evidence():
    cards = [_sample_card()]
    evidence_cards = [{
        'cve_id': 'CVE-2026-7000',
        'source_url': 'https://acme.example/advisory',
    }, {
        'cve_id': 'CVE-2026-7000',
        'source_url': 'https://extra.example/details',
    }]
    metrics = {
        'run_id': 'job-1',
        '_id': 'metrics-id',
        'total_vulnerabilities': 1,
        'severity_counts': {'Critical': 1},
    }

    appendix = build_appendix(cards, evidence_cards, metrics)

    assert appendix['metrics'] == {
        'total_vulnerabilities': 1,
        'severity_counts': {'Critical': 1},
    }
    urls = [item['url'] for item in appendix['source_references']]
    assert urls == [
        'https://acme.example/advisory',
        'https://extra.example/details',
    ]


def test_parse_executive_summary_happy_path():
    text = (
        'SUMMARY:\n'
        'One Acme Widget CVE requires patching.\n\n'
        'KEY_FINDINGS:\n'
        '- Upgrade to 2.0.\n'
        '- Monitor internet-facing systems.'
    )

    section = parse_executive_summary(text)

    assert section['summary'] == 'One Acme Widget CVE requires patching.'
    assert section['key_findings'] == [
        'Upgrade to 2.0.',
        'Monitor internet-facing systems.',
    ]


def test_parse_executive_summary_missing_label_raises():
    with pytest.raises(SectionParseError, match='KEY_FINDINGS'):
        parse_executive_summary('SUMMARY:\nOnly a summary.')


def test_parse_research_scope_happy_path():
    text = (
        'SUMMARY:\n'
        'CVE-only Mongo discovery with Tavily enrichment.\n\n'
        'CRITERIA:\n'
        '- cve_review only'
    )

    section = parse_research_scope(text)

    assert 'Mongo discovery' in section['summary']
    assert section['criteria'] == ['cve_review only']


def test_parse_weekly_risk_trend_happy_path():
    text = (
        'SUMMARY:\n'
        'Risk is concentrated in one critical CVE.\n\n'
        'TREND_POINTS:\n'
        'One critical Acme issue.'
    )

    section = parse_weekly_risk_trend(text)

    assert section['summary'] == 'Risk is concentrated in one critical CVE.'
    assert section['trend_points'] == ['One critical Acme issue.']


def test_parse_management_brief_happy_path():
    text = (
        'SUMMARY:\n'
        'Prioritize remediation for Acme Widget.\n\n'
        'BUSINESS_IMPACT:\n'
        'Potential service compromise.\n\n'
        'DECISIONS_NEEDED:\n'
        '- Approve emergency patching.'
    )

    section = parse_management_brief(text)

    assert section['summary'] == 'Prioritize remediation for Acme Widget.'
    assert section['business_impact'] == 'Potential service compromise.'
    assert section['decisions_needed'] == ['Approve emergency patching.']


def test_parse_remediation_playbook_pipe_format():
    text = (
        'SUMMARY:\n'
        'Patch Acme Widget first.\n\n'
        'ACTIONS:\n'
        'High | Upgrade Acme Widget to version 2.0. | CVE-2026-7000'
    )

    section = parse_remediation_playbook(text)

    assert section['summary'] == 'Patch Acme Widget first.'
    assert section['actions'] == [{
        'priority': 'High',
        'action': 'Upgrade Acme Widget to version 2.0.',
        'cve_ids': ['CVE-2026-7000'],
    }]


def test_parse_remediation_playbook_invalid_action_raises():
    text = (
        'SUMMARY:\n'
        'Patch Acme Widget first.\n\n'
        'ACTIONS:\n'
        'High | Missing CVE column'
    )

    with pytest.raises(SectionParseError, match='Invalid action line'):
        parse_remediation_playbook(text)


def test_parse_remediation_playbook_none_actions():
    text = (
        'SUMMARY:\n'
        'No actions required.\n\n'
        'ACTIONS:\n'
        'NONE'
    )

    section = parse_remediation_playbook(text)

    assert section['actions'] == []


def test_parse_unsupported_claims_none():
    assert parse_unsupported_claims('UNSUPPORTED_CLAIMS:\nNONE') == []


def test_parse_unsupported_claims_bullets():
    text = (
        'UNSUPPORTED_CLAIMS:\n'
        '- Unsupported claim appears here.\n'
        '- Another unsupported snippet.'
    )

    assert parse_unsupported_claims(text) == [
        'Unsupported claim appears here.',
        'Another unsupported snippet.',
    ]


def test_parsed_sections_validate_against_schema():
    schema_map = {
        'executive_summary': ENRICHED_REPORT_SCHEMA['properties']['executive_summary'],
        'research_scope': ENRICHED_REPORT_SCHEMA['properties']['research_scope'],
        'weekly_risk_trend': ENRICHED_REPORT_SCHEMA['properties']['weekly_risk_trend'],
        'management_brief': ENRICHED_REPORT_SCHEMA['properties']['management_brief'],
        'remediation_playbook': ENRICHED_REPORT_SCHEMA['properties']['remediation_playbook'],
        'vulnerability_detail_table': ENRICHED_REPORT_SCHEMA['properties']['vulnerability_detail_table'],
        'appendix': ENRICHED_REPORT_SCHEMA['properties']['appendix'],
    }

    from jsonschema import validate

    validate(instance=parse_executive_summary(
        'SUMMARY:\nSummary text.\n\nKEY_FINDINGS:\n- Finding one'
    ), schema=schema_map['executive_summary'])
    validate(instance=build_vulnerability_detail_table([_sample_card()]), schema=schema_map['vulnerability_detail_table'])
    validate(instance=build_appendix([_sample_card()], [], {'total_vulnerabilities': 1}), schema=schema_map['appendix'])
