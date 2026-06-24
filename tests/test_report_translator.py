import json

from enriched_report.translator import _translate_fragment, translate_report


class FakeClient:
    report_max_output_tokens = 2048

    def __init__(self):
        self.calls = []

    def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
        self.calls.append((system_prompt, user_prompt, max_output_tokens))
        start = user_prompt.rfind('\n\n')
        payload = user_prompt[start + 2:]
        return payload.replace('English', '中文').replace('Patch', '修補'), {}


def test_translate_string_fragment_unwraps_single_key_object():
    report = 'English Report'

    class WrappingClient(FakeClient):
        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            self.calls.append((system_prompt, user_prompt, max_output_tokens))
            return '{"English Report": "中文報告"}', {}

    translated = _translate_fragment(report, 'zh', WrappingClient(), {})
    assert translated == '中文報告'


def test_translate_template_report_splits_top_level_and_highlights():
    client = FakeClient()
    progress = []
    report = {
        'title': 'English Report',
        'executive_summary': 'English summary',
        'trends': ['English trend'],
        'recommendations': ['Patch systems'],
        'highlights': [{
            'title': 'English item',
            'code': 'CVE-2026-0001',
            'severity': 'High',
            'summary': 'English details',
            'affected': ['English Product'],
            'references': ['https://example.com/advisory'],
            'source_link': 'https://example.com/source',
            'newsletter': {
                'overview': 'English overview',
                'references': ['https://example.com/news'],
            },
        }],
        'template_mode': True,
    }

    translated = translate_report(
        report,
        'template',
        'zh',
        {},
        client=client,
        progress_callback=lambda current, total, message: progress.append((current, total, message)),
    )

    assert len(client.calls) == 3
    assert translated['title'] == '中文 Report'
    assert translated['recommendations'] == ['修補 systems']
    assert translated['highlights'][0]['code'] == 'CVE-2026-0001'
    assert translated['highlights'][0]['references'] == ['https://example.com/advisory']
    assert translated['highlights'][0]['source_link'] == 'https://example.com/source'
    assert progress[-1] == (2, 2, 'Translating item 1/1')


def test_translate_row_fragment_strips_source_urls_from_llm_payload():
    class UrlPreservingClient(FakeClient):
        def complete_text(self, system_prompt, user_prompt, max_output_tokens=None):
            self.calls.append((system_prompt, user_prompt, max_output_tokens))
            assert 'source_urls' not in user_prompt
            payload_start = user_prompt.rfind('\n\n') + 2
            payload = json.loads(user_prompt[payload_start:])
            payload['what_happened'] = '中文說明'
            return json.dumps(payload, ensure_ascii=False), {}

    row = {
        'cve_id': 'CVE-2026-54388',
        'title': 'CVE-2026-54388',
        'what_happened': 'English details',
        'source_urls': ['https://example.com/' + ('a' * 300)],
    }
    translated = _translate_fragment(row, 'zh', UrlPreservingClient(), {})
    assert translated['source_urls'] == row['source_urls']
    assert translated['what_happened'] == '中文說明'


def test_translate_enriched_report_translates_each_row_and_preserves_identifiers():
    client = FakeClient()
    report = {
        'title': 'English Report',
        'executive_summary': {'summary': 'English summary', 'key_findings': ['Patch now']},
        'weekly_risk_trend': {'summary': 'English trend', 'trend_points': ['English point']},
        'vulnerability_detail_table': {
            'rows': [{
                'cve_id': 'CVE-2026-0001',
                'title': 'English title',
                'vendor': 'Acme',
                'product': 'Widget',
                'severity': 'Critical',
                'priority_score': 10,
                'patch_priority': 'High',
                'what_happened': 'English exploit',
                'why_matters': 'English impact',
                'how_to_respond': 'Patch now',
                'source_urls': ['https://example.com/source'],
            }],
        },
        'remediation_playbook': {
            'summary': 'Patch systems',
            'actions': [{'priority': 'High', 'action': 'Patch now', 'cve_ids': ['CVE-2026-0001']}],
        },
        'appendix': {
            'source_references': [{'cve_id': 'CVE-2026-0001', 'urls': ['https://example.com/source']}],
            'metrics': {'total_vulnerabilities': 1},
        },
    }

    translated = translate_report(report, 'enriched_weekly', 'ch', {}, client=client)

    assert len(client.calls) == 5
    assert translated['title'] == '中文 Report'
    assert translated['vulnerability_detail_table']['rows'][0]['cve_id'] == 'CVE-2026-0001'
    assert translated['vulnerability_detail_table']['rows'][0]['source_urls'] == ['https://example.com/source']
    assert translated['remediation_playbook']['actions'][0]['cve_ids'] == ['CVE-2026-0001']
    assert translated['appendix'] == report['appendix']
