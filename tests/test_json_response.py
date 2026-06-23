import pytest

from enriched_report.json_response import extract_json
from enriched_report.llama_client import EnrichedLLMError


def test_extract_json_repairs_trailing_comma():
    parsed = extract_json('{"summary": "Patch first.",}')
    assert parsed['summary'] == 'Patch first.'


def test_extract_json_repairs_nested_trailing_comma():
    parsed = extract_json(
        '{"summary": "Patch first.", "actions": [{"priority": "High", "action": "Upgrade.", "cve_ids": ["CVE-1"],}]}'
    )
    assert parsed['summary'] == 'Patch first.'
    assert parsed['actions'][0]['cve_ids'] == ['CVE-1']


def test_extract_json_unwraps_code_fence():
    parsed = extract_json('```json\n{"summary": "Risk up.", "trend_points": ["One issue."]}\n```')
    assert parsed['trend_points'] == ['One issue.']


def test_extract_json_preserves_non_latin_characters():
    parsed = extract_json('{"summary": "統一碼測試"}')
    assert parsed['summary'] == '統一碼測試'


def test_extract_json_raises_on_empty_response():
    with pytest.raises(EnrichedLLMError, match='empty'):
        extract_json('   ')
