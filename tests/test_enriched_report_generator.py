from enriched_report.section_parsers import (
    build_appendix,
    build_vulnerability_detail_table,
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
    urls = appendix['source_references'][0]['urls']
    assert urls == [
        'https://acme.example/advisory',
        'https://extra.example/details',
    ]


def test_generate_text_section_accepts_json_in_code_fence():
    class FenceClient:
        report_max_output_tokens = 2048

        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            return (
                '```json\n'
                '{"summary": "Risk is concentrated.", "trend_points": ["One critical issue."]}\n'
                '```',
                {},
            )

    from enriched_report.report_generator import _generate_text_section

    section = _generate_text_section(
        'weekly_risk_trend',
        [],
        {},
        [],
        FenceClient(),
        'en',
        {},
    )

    assert section['summary'] == 'Risk is concentrated.'
    assert section['trend_points'] == ['One critical issue.']


def test_generate_text_section_repairs_malformed_json_without_second_llm_call():
    class SingleCallClient:
        report_max_output_tokens = 2048
        calls = 0

        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            SingleCallClient.calls += 1
            return (
                '{"summary": "Patch Acme Widget first.", "actions": [{'
                '"priority": "High", '
                '"action": "Upgrade Acme Widget to version 2.0.", '
                '"cve_ids": ["CVE-2026-7000"],'
                '}],}',
                {},
            )

    from enriched_report.report_generator import _generate_text_section

    section = _generate_text_section(
        'remediation_playbook',
        [],
        {},
        [],
        SingleCallClient(),
        'en',
        {},
    )

    assert SingleCallClient.calls == 1
    assert section['actions'][0]['cve_ids'] == ['CVE-2026-7000']


def test_deterministic_sections_validate_against_schema():
    schema_map = {
        'vulnerability_detail_table': ENRICHED_REPORT_SCHEMA['properties']['vulnerability_detail_table'],
        'appendix': ENRICHED_REPORT_SCHEMA['properties']['appendix'],
    }

    from jsonschema import validate

    validate(instance=build_vulnerability_detail_table([_sample_card()]), schema=schema_map['vulnerability_detail_table'])
    validate(instance=build_appendix([_sample_card()], [], {'total_vulnerabilities': 1}), schema=schema_map['appendix'])
