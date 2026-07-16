import json

from reports.enriched.section_parsers import (
    build_vulnerability_detail_table,
)
from reports.enriched.schemas import ENRICHED_REPORT_SCHEMA


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
    assert row['card_anchor'] == 'card-cve-2026-7000-acme-widget'
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


def test_deterministic_sections_validate_against_schema():
    schema_map = {
        'vulnerability_detail_table': ENRICHED_REPORT_SCHEMA['properties']['vulnerability_detail_table'],
        'executive_summary': ENRICHED_REPORT_SCHEMA['properties']['executive_summary'],
    }

    from jsonschema import validate

    from reports.enriched.section_parsers import build_executive_summary

    validate(instance=build_vulnerability_detail_table([_sample_card()]), schema=schema_map['vulnerability_detail_table'])
    rows = build_vulnerability_detail_table([_sample_card()])['rows']
    validate(instance=build_executive_summary(rows), schema=schema_map['executive_summary'])


def test_generate_text_section_accepts_json_in_code_fence():
    class FenceClient:
        report_max_output_tokens = 2048

        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            return (
                '```json\n'
                '{"summary": "Risk is concentrated.", "key_findings": ["One critical issue."]}\n'
                '```',
                {},
            )

    from reports.enriched.report_generator import _generate_text_section

    section = _generate_text_section(
        'executive_summary',
        [],
        {},
        [],
        FenceClient(),
        'en',
        {},
    )

    assert section['key_findings'] == ['One critical issue.']


def test_generate_text_section_repairs_malformed_json_without_second_llm_call():
    class SingleCallClient:
        report_max_output_tokens = 2048
        calls = 0

        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            SingleCallClient.calls += 1
            return (
                '{"summary": "Patch Acme Widget first.", '
                '"key_findings": ["Upgrade Acme Widget to version 2.0.",],}',
                {},
            )

    from reports.enriched.report_generator import _generate_text_section

    section = _generate_text_section(
        'executive_summary',
        [],
        {},
        [],
        SingleCallClient(),
        'en',
        {},
    )

    assert SingleCallClient.calls == 1
    assert section['key_findings'][0] == 'Upgrade Acme Widget to version 2.0.'


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
                '{"summary": "Patch Acme Widget first.", '
                '"key_findings": ["Upgrade Acme Widget to version 2.0."]}',
                {},
            )

    from reports.enriched.report_generator import _generate_text_section

    client = RetryClient()
    section = _generate_text_section(
        'executive_summary',
        [],
        {},
        [],
        client,
        'en',
        {'REPORT_ITEM_JSON_RETRIES': 1},
    )

    assert client.calls == 2
    assert section['key_findings'][0] == 'Upgrade Acme Widget to version 2.0.'


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

    from reports.enriched.report_generator import _merge_section_partials_with_ai

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
    assert set(client.payload) == {
        'section_name',
        'language',
        'instructions',
        'partial_sections',
    }
    assert merged['key_findings'] == ['Patch Acme first.']


def _table_rows(cards):
    return build_vulnerability_detail_table(cards)['rows']


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

    from reports.enriched.report_generator import _generate_text_section

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
    assert section['key_findings'] == ['Three issues need review.']


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

    from reports.enriched.report_generator import _generate_text_section

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
    assert section['key_findings']


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

    from reports.enriched.report_generator import _generate_text_section

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
    assert section['key_findings'] == ['One finding.']


def test_generate_text_section_uses_single_call_when_prompt_is_small():
    class SingleClient:
        report_max_output_tokens = 2048
        calls = 0

        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            SingleClient.calls += 1
            return (
                '{"summary": "Patch Acme Widget first.", '
                '"key_findings": ["Upgrade Acme Widget to version 2.0."]}',
                {},
            )

    from reports.enriched.report_generator import _generate_text_section

    SingleClient.calls = 0
    section = _generate_text_section(
        'executive_summary',
        _table_rows([_card('CVE-2026-7000')]),
        {},
        [],
        SingleClient(),
        'en',
        {'REPORT_SECTION_CHUNK_PROMPT_CHARS': 100000},
    )

    assert SingleClient.calls == 1
    assert section['key_findings'][0] == 'Upgrade Acme Widget to version 2.0.'


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
                return '{"summary": "Recovered chunk.", "key_findings": ["Patch CVE-2026-0000."]}', {}
            if 'partial_sections' in payload:
                return json.dumps({
                    'summary': 'Merged summary.',
                    'key_findings': [
                        finding
                        for partial in payload['partial_sections']
                        for finding in partial.get('key_findings', [])
                    ],
                }), {}
            cve_id = payload['vulnerability_rows'][0]['cve_id']
            return (
                json.dumps({
                    'summary': 'Chunk summary.',
                    'key_findings': [f'Patch {cve_id}.'],
                }),
                {},
            )

    from reports.enriched.report_generator import _generate_text_section

    client = RetryChunkClient()
    section = _generate_text_section(
        'executive_summary',
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
    assert len(section['key_findings']) == 2
