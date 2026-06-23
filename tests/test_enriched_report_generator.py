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


def test_generate_text_section_retries_when_first_response_is_thinking_text():
    class RetryClient:
        report_max_output_tokens = 2048

        def __init__(self):
            self.calls = 0

        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            self.calls += 1
            if self.calls == 1:
                return (
                    '<think>\nI should summarize the issues first before formatting.\n',
                    {},
                )
            return (
                '{"summary": "Patch Acme Widget first.", "actions": [{'
                '"priority": "High", '
                '"action": "Upgrade Acme Widget to version 2.0.", '
                '"cve_ids": ["CVE-2026-7000"]'
                '}]}',
                {},
            )

    from enriched_report.report_generator import _generate_text_section

    client = RetryClient()
    section = _generate_text_section(
        'remediation_playbook',
        [],
        {},
        [],
        client,
        'en',
        {'REPORT_ITEM_JSON_RETRIES': 1},
    )

    assert client.calls == 2
    assert section['summary'] == 'Patch Acme Widget first.'
    assert section['actions'][0]['cve_ids'] == ['CVE-2026-7000']


def test_deterministic_sections_validate_against_schema():
    schema_map = {
        'vulnerability_detail_table': ENRICHED_REPORT_SCHEMA['properties']['vulnerability_detail_table'],
        'appendix': ENRICHED_REPORT_SCHEMA['properties']['appendix'],
    }

    from jsonschema import validate

    validate(instance=build_vulnerability_detail_table([_sample_card()]), schema=schema_map['vulnerability_detail_table'])
    validate(instance=build_appendix([_sample_card()], [], {'total_vulnerabilities': 1}), schema=schema_map['appendix'])


def _card(cve_id, priority_score=50, patch_priority='High'):
    return {
        'cve_id': cve_id,
        'title': f'Issue {cve_id}',
        'vendor': 'Acme',
        'product': 'Widget',
        'severity': patch_priority,
        'priority_score': priority_score,
        'patch_priority': patch_priority,
        'what_happened': f'{cve_id} has a vulnerability.',
        'why_matters': 'It matters.',
        'how_to_respond': f'Patch {cve_id}.',
        'source_references': [f'https://acme.example/{cve_id}'],
        'missing_fields': [],
        'conflicts': [],
    }


def test_merge_remediation_playbook_partials_dedupes_and_sorts_actions():
    from enriched_report.section_chunking import merge_remediation_playbook_partials

    merged = merge_remediation_playbook_partials([
        {
            'summary': 'Chunk one.',
            'actions': [{
                'priority': 'High',
                'action': 'Upgrade Acme Widget to version 2.0.',
                'cve_ids': ['CVE-2026-7000'],
            }],
        },
        {
            'summary': 'Chunk two.',
            'actions': [
                {
                    'priority': 'Critical',
                    'action': 'Patch CVE-2026-7001 immediately.',
                    'cve_ids': ['CVE-2026-7001'],
                },
                {
                    'priority': 'High',
                    'action': 'Upgrade Acme Widget to version 2.0.',
                    'cve_ids': ['CVE-2026-7000'],
                },
            ],
        },
    ])

    assert len(merged['actions']) == 2
    assert merged['actions'][0]['priority'] == 'Critical'
    assert merged['actions'][1]['cve_ids'] == ['CVE-2026-7000']
    assert '2 items' in merged['summary']


def test_generate_text_section_chunks_remediation_playbook_when_prompt_is_large():
    cards = [_card(f'CVE-2026-{index:04d}') for index in range(6)]
    evidence_cards = [
        {
            'cve_id': card['cve_id'],
            'task_type': 'what_happened',
            'source_url': card['source_references'][0],
            'confidence': 'high',
        }
        for card in cards
    ]

    class ChunkClient:
        report_max_output_tokens = 2048

        def __init__(self):
            self.calls = 0
            self.chunk_card_counts = []

        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            self.calls += 1
            payload = __import__('json').loads(user_prompt)
            self.chunk_card_counts.append(len(payload['vulnerability_cards']))
            cve_ids = [card['cve_id'] for card in payload['vulnerability_cards']]
            return (
                __import__('json').dumps({
                    'summary': 'Chunk summary.',
                    'actions': [{
                        'priority': 'High',
                        'action': f'Patch {cve_ids[0]}.',
                        'cve_ids': cve_ids[:1],
                    }],
                }),
                {},
            )

    from enriched_report.report_generator import _generate_text_section

    client = ChunkClient()
    section = _generate_text_section(
        'remediation_playbook',
        cards,
        {'total_vulnerabilities': len(cards)},
        evidence_cards,
        client,
        'en',
        {
            'REPORT_SECTION_CHUNK_PROMPT_CHARS': 1,
            'REPORT_SECTION_CHUNK_CARD_COUNT': 2,
        },
    )

    assert client.calls == 3
    assert client.chunk_card_counts == [2, 2, 2]
    assert len(section['actions']) == 3
    assert section['actions'][0]['cve_ids'] == ['CVE-2026-0000']


def test_generate_text_section_uses_single_call_when_prompt_is_small():
    class SingleClient:
        report_max_output_tokens = 2048
        calls = 0

        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            SingleClient.calls += 1
            return (
                '{"summary": "Patch Acme Widget first.", "actions": [{'
                '"priority": "High", '
                '"action": "Upgrade Acme Widget to version 2.0.", '
                '"cve_ids": ["CVE-2026-7000"]'
                '}]}',
                {},
            )

    from enriched_report.report_generator import _generate_text_section

    SingleClient.calls = 0
    section = _generate_text_section(
        'remediation_playbook',
        [_card('CVE-2026-7000')],
        {},
        [],
        SingleClient(),
        'en',
        {'REPORT_SECTION_CHUNK_PROMPT_CHARS': 100000},
    )

    assert SingleClient.calls == 1
    assert section['actions'][0]['cve_ids'] == ['CVE-2026-7000']


def test_generate_text_section_chunk_retry_recovers_from_invalid_chunk_json():
    cards = [_card(f'CVE-2026-{index:04d}') for index in range(4)]

    class RetryChunkClient:
        report_max_output_tokens = 2048

        def __init__(self):
            self.calls = 0

        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            self.calls += 1
            if self.calls == 1:
                return '<think>\nStill planning.\n', {}
            try:
                payload = __import__('json').loads(user_prompt)
            except ValueError:
                return (
                    '{"summary": "Recovered chunk.", "actions": [{'
                    '"priority": "High", '
                    '"action": "Patch CVE-2026-0000.", '
                    '"cve_ids": ["CVE-2026-0000"]'
                    '}]}',
                    {},
                )
            cve_id = payload['vulnerability_cards'][0]['cve_id']
            return (
                __import__('json').dumps({
                    'summary': 'Chunk summary.',
                    'actions': [{
                        'priority': 'High',
                        'action': f'Patch {cve_id}.',
                        'cve_ids': [cve_id],
                    }],
                }),
                {},
            )

    from enriched_report.report_generator import _generate_text_section

    client = RetryChunkClient()
    section = _generate_text_section(
        'remediation_playbook',
        cards,
        {},
        [],
        client,
        'en',
        {
            'REPORT_SECTION_CHUNK_PROMPT_CHARS': 1,
            'REPORT_SECTION_CHUNK_CARD_COUNT': 2,
            'REPORT_ITEM_JSON_RETRIES': 1,
        },
    )

    assert client.calls == 3
    assert len(section['actions']) == 2

