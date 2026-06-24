import json

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


def test_merge_section_partials_with_ai_executive_summary():
    class MergeClient:
        report_max_output_tokens = 2048

        def __init__(self):
            self.payload = None

        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            self.payload = json.loads(user_prompt)
            return json.dumps({
                'summary': 'Merged executive summary.',
                'key_findings': ['Patch Acme first.'],
            }), {}

    from enriched_report.report_generator import _merge_section_partials_with_ai

    client = MergeClient()
    merged = _merge_section_partials_with_ai(
        'executive_summary',
        [
            {'summary': 'Chunk one.', 'key_findings': ['Patch Acme.']},
            {'summary': 'Chunk two.', 'key_findings': ['Validate exposure.']},
        ],
        [_card('CVE-2026-7000')],
        {'total_vulnerabilities': 1},
        [],
        client,
        'en',
        {},
    )

    assert client.payload['section_name'] == 'executive_summary'
    assert client.payload['partial_sections'][1]['summary'] == 'Chunk two.'
    assert set(client.payload) == {
        'section_name',
        'language',
        'instructions',
        'partial_sections',
    }
    assert merged['summary'] == 'Merged executive summary.'
    assert merged['key_findings'] == ['Patch Acme first.']


def _table_rows(cards):
    return build_vulnerability_detail_table(cards)['rows']


def test_remediation_playbook_section_prompt_uses_table_rows_only():
    from enriched_report.report_generator import _section_prompt

    row = _table_rows([_card('CVE-2026-7000')])[0]

    payload = json.loads(_section_prompt(
        'remediation_playbook',
        [row],
        {},
        [],
        'en',
        {},
    ))

    assert set(payload.keys()) == {
        'section_name',
        'language',
        'instructions',
        'vulnerability_rows',
    }
    slim_row = payload['vulnerability_rows'][0]
    assert slim_row['cve_id'] == 'CVE-2026-7000'
    assert slim_row['how_to_respond'] == 'Patch CVE-2026-7000.'
    assert 'what_happened' not in slim_row
    assert 'why_matters' not in slim_row
    assert 'vulnerability_cards' not in payload
    assert 'top_remediation_items' not in payload
    assert 'report_metrics' not in payload
    assert 'evidence_references' not in payload


def test_merge_remediation_playbook_payload_is_partials_only():
    class MergeClient:
        report_max_output_tokens = 2048

        def __init__(self):
            self.payload = None

        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            self.payload = json.loads(user_prompt)
            return json.dumps({
                'summary': 'Merged remediation summary.',
                'actions': [
                    {
                        'priority': 'High',
                        'action': 'Patch CVE-2026-7000.',
                        'cve_ids': ['CVE-2026-7000'],
                    },
                ],
            }), {}

    from enriched_report.report_generator import _merge_section_partials_with_ai

    client = MergeClient()
    merged = _merge_section_partials_with_ai(
        'remediation_playbook',
        [
            {
                'summary': 'Chunk one.',
                'actions': [{
                    'priority': 'High',
                    'action': 'Patch CVE-2026-7000.',
                    'cve_ids': ['CVE-2026-7000'],
                }],
            },
            {
                'summary': 'Chunk two.',
                'actions': [{
                    'priority': 'Medium',
                    'action': 'Patch CVE-2026-7001.',
                    'cve_ids': ['CVE-2026-7001'],
                }],
            },
        ],
        [_card('CVE-2026-7000'), _card('CVE-2026-7001')],
        {'total_vulnerabilities': 2},
        [{
            'cve_id': 'CVE-2026-7000',
            'task_type': 'what_happened',
            'source_url': 'https://acme.example/CVE-2026-7000',
            'confidence': 'high',
        }],
        client,
        'en',
        {},
    )

    assert set(client.payload.keys()) == {
        'section_name',
        'language',
        'instructions',
        'partial_sections',
    }
    assert 'vulnerability_cards' not in client.payload
    assert 'report_metrics' not in client.payload
    assert 'evidence_references' not in client.payload
    assert merged['summary'] == 'Merged remediation summary.'
    assert merged['actions'][0]['cve_ids'] == ['CVE-2026-7000']


def test_generate_text_section_chunks_remediation_playbook_when_prompt_is_large():
    cards = [_card(f'CVE-2026-{index:04d}') for index in range(6)]
    rows = _table_rows(cards)

    class ChunkClient:
        report_max_output_tokens = 2048

        def __init__(self):
            self.calls = 0
            self.chunk_row_counts = []
            self.chunk_payloads = []
            self.merge_payloads = []

        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            self.calls += 1
            payload = json.loads(user_prompt)
            if 'partial_sections' in payload:
                self.merge_payloads.append(payload)
                return json.dumps({
                    'summary': 'Merged summary.',
                    'actions': [
                        action
                        for partial in payload['partial_sections']
                        for action in partial.get('actions', [])
                    ],
                }), {}
            self.chunk_payloads.append(payload)
            self.chunk_row_counts.append(len(payload['vulnerability_rows']))
            cve_ids = [row['cve_id'] for row in payload['vulnerability_rows']]
            return (
                json.dumps({
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
        rows,
        {},
        [],
        client,
        'en',
        {
            'REPORT_SECTION_CHUNK_PROMPT_CHARS': 1,
            'REPORT_SECTION_CHUNK_CARD_COUNT': 2,
        },
    )

    assert client.calls == 5
    assert client.chunk_row_counts == [2, 2, 2]
    assert [len(payload['partial_sections']) for payload in client.merge_payloads] == [2, 2]
    assert all(set(payload) == {
        'section_name',
        'language',
        'instructions',
        'partial_sections',
    } for payload in client.merge_payloads)
    assert len(client.chunk_payloads) == 3
    for payload in client.chunk_payloads:
        assert 'vulnerability_rows' in payload
        assert 'what_happened' not in payload['vulnerability_rows'][0]
        assert 'why_matters' not in payload['vulnerability_rows'][0]
        assert 'how_to_respond' in payload['vulnerability_rows'][0]
        assert 'vulnerability_cards' not in payload
        assert 'top_remediation_items' not in payload
        assert 'report_metrics' not in payload
        assert 'evidence_references' not in payload
    assert len(section['actions']) == 3
    assert section['actions'][0]['cve_ids'] == ['CVE-2026-0000']


def test_chunked_executive_summary_calls_merge_when_multiple_chunks():
    cards = [_card(f'CVE-2026-{index:04d}') for index in range(3)]

    class ChunkClient:
        report_max_output_tokens = 2048

        def __init__(self):
            self.merge_calls = 0
            self.chunk_payloads = []

        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            payload = json.loads(user_prompt)
            if 'partial_sections' in payload:
                self.merge_calls += 1
                return json.dumps({
                    'summary': 'Merged executive summary.',
                    'key_findings': ['Three issues need review.'],
                }), {}
            self.chunk_payloads.append(payload)
            cve_id = payload['vulnerability_rows'][0]['cve_id']
            return json.dumps({
                'summary': f'Chunk {cve_id}.',
                'key_findings': [f'Review {cve_id}.'],
            }), {}

    from enriched_report.report_generator import _generate_text_section

    client = ChunkClient()
    section = _generate_text_section(
        'executive_summary',
        cards,
        {},
        [],
        client,
        'en',
        {
            'REPORT_SECTION_CHUNK_PROMPT_CHARS': 100000,
            'REPORT_SECTION_CHUNK_CARD_COUNT': 2,
        },
    )

    assert client.merge_calls == 1
    assert 'why_matters' not in client.chunk_payloads[0]['vulnerability_rows'][0]
    assert 'how_to_respond' not in client.chunk_payloads[0]['vulnerability_rows'][0]
    assert 'priority_score' in client.chunk_payloads[0]['vulnerability_rows'][0]
    assert section['summary'] == 'Merged executive summary.'


def test_chunked_executive_summary_merges_recursively():
    rows = _table_rows([_card(f'CVE-2026-{index:04d}') for index in range(10)])

    class ChunkClient:
        report_max_output_tokens = 2048

        def __init__(self):
            self.calls = 0
            self.merge_sizes = []

        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            self.calls += 1
            payload = json.loads(user_prompt)
            if 'partial_sections' in payload:
                self.merge_sizes.append(len(payload['partial_sections']))
                findings = [
                    finding
                    for partial in payload['partial_sections']
                    for finding in partial.get('key_findings', [])
                ]
                return json.dumps({
                    'summary': 'Merged executive summary.',
                    'key_findings': findings or ['Merged.'],
                }), {}
            cve_id = payload['vulnerability_rows'][0]['cve_id']
            return json.dumps({
                'summary': f'Chunk {cve_id}.',
                'key_findings': [f'Review {cve_id}.'],
            }), {}

    from enriched_report.report_generator import _generate_text_section

    client = ChunkClient()
    section = _generate_text_section(
        'executive_summary',
        rows,
        {},
        [],
        client,
        'en',
        {
            'REPORT_SECTION_CHUNK_PROMPT_CHARS': 100000,
            'REPORT_SECTION_CHUNK_CARD_COUNT': 2,
        },
    )

    assert client.calls == 9
    assert client.merge_sizes == [2, 2, 2, 2]
    assert section['summary'] == 'Merged executive summary.'


def test_weekly_risk_trend_uses_filtered_table_rows():
    class RowClient:
        report_max_output_tokens = 2048

        def __init__(self):
            self.payload = None

        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            self.payload = json.loads(user_prompt)
            return json.dumps({
                'summary': 'Weekly trend.',
                'trend_points': ['Risk impact is clustered.'],
            }), {}

    from enriched_report.report_generator import _generate_text_section

    client = RowClient()
    section = _generate_text_section(
        'weekly_risk_trend',
        [_card('CVE-2026-7000')],
        {},
        [],
        client,
        'en',
        {'REPORT_SECTION_CHUNK_PROMPT_CHARS': 100000},
    )

    row = client.payload['vulnerability_rows'][0]
    assert 'why_matters' in row
    assert 'what_happened' not in row
    assert 'how_to_respond' not in row
    assert 'priority_score' not in row
    assert 'patch_priority' not in row
    assert section['summary'] == 'Weekly trend.'


def test_chunked_weekly_risk_trend_merges_recursively():
    rows = _table_rows([_card(f'CVE-2026-{index:04d}') for index in range(6)])

    class ChunkClient:
        report_max_output_tokens = 2048

        def __init__(self):
            self.merge_sizes = []

        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            payload = json.loads(user_prompt)
            if 'partial_sections' in payload:
                self.merge_sizes.append(len(payload['partial_sections']))
                return json.dumps({
                    'summary': 'Merged trend.',
                    'trend_points': [
                        point
                        for partial in payload['partial_sections']
                        for point in partial.get('trend_points', [])
                    ] or ['Merged point.'],
                }), {}
            cve_id = payload['vulnerability_rows'][0]['cve_id']
            return json.dumps({
                'summary': f'Chunk {cve_id}.',
                'trend_points': [f'Trend {cve_id}.'],
            }), {}

    from enriched_report.report_generator import _generate_text_section

    client = ChunkClient()
    section = _generate_text_section(
        'weekly_risk_trend',
        rows,
        {},
        [],
        client,
        'en',
        {
            'REPORT_SECTION_CHUNK_PROMPT_CHARS': 100000,
            'REPORT_SECTION_CHUNK_CARD_COUNT': 2,
        },
    )

    assert client.merge_sizes == [2, 2]
    assert section['summary'] == 'Merged trend.'


def test_single_chunk_skips_merge_llm_call():
    class ChunkClient:
        report_max_output_tokens = 2048

        def __init__(self):
            self.calls = 0

        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            self.calls += 1
            payload = json.loads(user_prompt)
            assert 'partial_sections' not in payload
            assert 'vulnerability_rows' in payload
            return json.dumps({
                'summary': 'One chunk summary.',
                'key_findings': ['One finding.'],
            }), {}

    from enriched_report.report_generator import _generate_text_section

    client = ChunkClient()
    section = _generate_text_section(
        'executive_summary',
        [_card('CVE-2026-7000')],
        {},
        [],
        client,
        'en',
        {
            'REPORT_SECTION_CHUNK_PROMPT_CHARS': 1,
            'REPORT_SECTION_CHUNK_CARD_COUNT': 10,
        },
    )

    assert client.calls == 1
    assert section['summary'] == 'One chunk summary.'


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
        _table_rows([_card('CVE-2026-7000')]),
        {},
        [],
        SingleClient(),
        'en',
        {'REPORT_SECTION_CHUNK_PROMPT_CHARS': 100000},
    )

    assert SingleClient.calls == 1
    assert section['actions'][0]['cve_ids'] == ['CVE-2026-7000']


def test_generate_text_section_chunk_retry_recovers_from_invalid_chunk_json():
    rows = _table_rows([_card(f'CVE-2026-{index:04d}') for index in range(4)])

    class RetryChunkClient:
        report_max_output_tokens = 2048

        def __init__(self):
            self.calls = 0

        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            self.calls += 1
            if self.calls == 1:
                return '<think>\nStill planning.\n', {}
            try:
                payload = json.loads(user_prompt)
            except ValueError:
                return (
                    '{"summary": "Recovered chunk.", "actions": [{'
                    '"priority": "High", '
                    '"action": "Patch CVE-2026-0000.", '
                    '"cve_ids": ["CVE-2026-0000"]'
                    '}]}',
                    {},
                )
            if 'partial_sections' in payload:
                return json.dumps({
                    'summary': 'Merged summary.',
                    'actions': [
                        action
                        for partial in payload['partial_sections']
                        for action in partial.get('actions', [])
                    ],
                }), {}
            cve_id = payload['vulnerability_rows'][0]['cve_id']
            return (
                json.dumps({
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
        rows,
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

    assert client.calls == 4
    assert len(section['actions']) == 2
