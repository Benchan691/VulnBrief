import pytest

from company_ai_parsers import (
    CompanyAIParseError,
    parse_final_text,
    parse_item_text,
    validate_parsed_final,
    validate_parsed_item,
)
from report_harness import FINAL_SCHEMA, ITEM_SCHEMA


def _sample_item_text(**overrides):
    blocks = {
        'SUMMARY': 'Evidence-based summary.',
        'CODE': 'CVE-2026-1000',
        'SEVERITY': 'Critical',
        'AFFECTED': '- Product A',
        'REFERENCES': '- https://example.com/advisory',
        'RECOMMENDATIONS': '- Apply updates.',
        'TABLE': 'NONE',
    }
    blocks.update(overrides)
    parts = []
    for label in ('SUMMARY', 'CODE', 'SEVERITY', 'AFFECTED', 'REFERENCES', 'RECOMMENDATIONS', 'TABLE'):
        parts.append(f'{label}:\n{blocks[label]}')
    return '\n\n'.join(parts)


def test_parse_item_text_happy_path():
    item = parse_item_text(_sample_item_text())

    assert item['highlight']['summary'] == 'Evidence-based summary.'
    assert item['highlight']['code'] == 'CVE-2026-1000'
    assert item['highlight']['severity'] == 'Critical'
    assert item['highlight']['affected'] == ['Product A']
    assert item['highlight']['references'] == ['https://example.com/advisory']
    assert item['recommendations'] == ['Apply updates.']
    assert 'table' not in item['highlight']


def test_parse_item_text_with_table():
    table_block = (
        'CAPTION: Patch matrix\n'
        'HEADERS: Product | Version | Status\n'
        'Widget | 1.0 | Affected'
    )
    item = parse_item_text(_sample_item_text(TABLE=table_block))

    assert item['highlight']['table'] == {
        'caption': 'Patch matrix',
        'headers': ['Product', 'Version', 'Status'],
        'rows': [['Widget', '1.0', 'Affected']],
    }


def test_parse_item_text_missing_summary_raises():
    text = _sample_item_text()
    text = text.replace('SUMMARY:\nEvidence-based summary.\n\n', '')
    with pytest.raises(CompanyAIParseError, match='SUMMARY'):
        parse_item_text(text)


def test_parse_item_text_invalid_table_raises():
    with pytest.raises(CompanyAIParseError, match='TABLE block requires'):
        parse_item_text(_sample_item_text(TABLE='CAPTION: Only caption'))


def test_parse_final_text_happy_path():
    text = (
        'EXECUTIVE_SUMMARY:\n'
        'Overall risk is elevated.\n\n'
        'TRENDS:\n'
        '- More critical CVEs this week.\n\n'
        'RECOMMENDATIONS:\n'
        '- Patch internet-facing systems.'
    )

    final_data = parse_final_text(text)

    assert final_data['executive_summary'] == 'Overall risk is elevated.'
    assert final_data['trends'] == ['More critical CVEs this week.']
    assert final_data['recommendations'] == ['Patch internet-facing systems.']


def test_parse_final_text_trends_none():
    text = (
        'EXECUTIVE_SUMMARY:\n'
        'Stable week.\n\n'
        'TRENDS:\n'
        'NONE\n\n'
        'RECOMMENDATIONS:\n'
        '- Continue monitoring.'
    )

    final_data = parse_final_text(text)

    assert final_data['trends'] == []


def test_parse_final_text_missing_label_raises():
    with pytest.raises(CompanyAIParseError, match='RECOMMENDATIONS'):
        parse_final_text(
            'EXECUTIVE_SUMMARY:\n'
            'Summary.\n\n'
            'TRENDS:\n'
            '- One trend.'
        )


def test_parsed_item_validates_against_schema():
    item = parse_item_text(_sample_item_text())
    validate_parsed_item(item, ITEM_SCHEMA)


def test_parsed_final_validates_against_schema():
    final_data = parse_final_text(
        'EXECUTIVE_SUMMARY:\n'
        'Summary.\n\n'
        'TRENDS:\n'
        '- Trend.\n\n'
        'RECOMMENDATIONS:\n'
        '- Action.'
    )
    validate_parsed_final(final_data, FINAL_SCHEMA)
