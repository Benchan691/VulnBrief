import json

import pytest

from preprocessing_priorities import (
    background_scan_skipped,
    document_field_value,
    load_preprocessing_priorities,
    resolve_preprocessing_priority,
    review_document_sort_key,
    scan_projection,
    sorted_scan_collections,
)


def _base_config(**overrides):
    config = {
        'RABBITMQ_BACKGROUND_PRIORITY': 2,
        'RABBITMQ_MAX_PRIORITY': 10,
        'PREPROCESSING_PRIORITIES': {
            'default': 1,
            'collections': {
                'cve': 7,
                'zeroday': 9,
            },
            'field_boosts': {
                'severity': {
                    'critical': 3,
                    'high': 2,
                    'medium': 1,
                },
                'status': {
                    'high': 2,
                },
            },
        },
    }
    config.update(overrides)
    return config


def test_load_preprocessing_priorities_normalizes_field_boost_keys(tmp_path):
    path = tmp_path / 'priorities.json'
    path.write_text(json.dumps({
        'default': 1,
        'collections': {'cve': 7},
        'field_boosts': {
            'severity': {'CRITICAL': 3, 'High': 2},
        },
    }), encoding='utf-8')

    loaded = load_preprocessing_priorities(str(path))

    assert loaded['default'] == 1
    assert loaded['collections'] == {'cve': 7}
    assert loaded['background_scan_skip'] == []
    assert loaded['field_boosts']['severity']['critical'] == 3
    assert loaded['field_boosts']['severity']['high'] == 2


def test_load_preprocessing_priorities_normalizes_background_scan_skip(tmp_path):
    path = tmp_path / 'priorities.json'
    path.write_text(json.dumps({
        'background_scan_skip': ['cve', 'cve', ' avd '],
    }), encoding='utf-8')

    loaded = load_preprocessing_priorities(str(path))

    assert loaded['background_scan_skip'] == ['cve', 'avd']


def test_load_preprocessing_priorities_rejects_invalid_background_scan_skip(tmp_path):
    path = tmp_path / 'priorities.json'
    path.write_text(json.dumps({'background_scan_skip': 'cve'}), encoding='utf-8')

    with pytest.raises(ValueError, match='background_scan_skip'):
        load_preprocessing_priorities(str(path))


def test_background_scan_skipped_reads_configured_collections():
    config = _base_config(
        PREPROCESSING_PRIORITIES={
            'default': 1,
            'collections': {},
            'background_scan_skip': ['cve'],
            'field_boosts': {},
        },
    )

    assert background_scan_skipped('cve', config) is True
    assert background_scan_skipped('avd', config) is False


def test_load_preprocessing_priorities_rejects_invalid_schema(tmp_path):
    path = tmp_path / 'priorities.json'
    path.write_text('[]', encoding='utf-8')

    with pytest.raises(ValueError, match='must be a JSON object'):
        load_preprocessing_priorities(str(path))


def test_load_preprocessing_priorities_rejects_missing_file(tmp_path):
    with pytest.raises(ValueError, match='not found'):
        load_preprocessing_priorities(str(tmp_path / 'missing.json'))


def test_document_field_value_reads_top_level_and_nested_details():
    document = {
        'severity': 'HIGH',
        'details': {
            'status': 'ACTIVE',
            'source': {'severity': 'CRITICAL'},
        },
    }

    assert document_field_value(document, 'severity') == 'HIGH'
    assert document_field_value(document, 'status') == 'ACTIVE'
    assert document_field_value(document, 'missing') is None

    nested_only = {'details': {'source': {'severity': 'MEDIUM'}}}
    assert document_field_value(nested_only, 'severity') == 'MEDIUM'


def test_resolve_preprocessing_priority_uses_collection_default_and_boosts():
    config = _base_config()
    document = {'severity': 'HIGH'}

    assert resolve_preprocessing_priority('cnnvd', document, config) == 3
    assert resolve_preprocessing_priority('cve', document, config) == 9


def test_resolve_preprocessing_priority_stacks_multiple_field_boosts():
    config = _base_config()
    document = {'severity': 'critical', 'status': 'high'}

    assert resolve_preprocessing_priority('cve', document, config) == 10


def test_resolve_preprocessing_priority_clamps_to_max_priority():
    config = _base_config()
    document = {'severity': 'critical'}

    assert resolve_preprocessing_priority('zeroday', document, config) == 10


def test_resolve_preprocessing_priority_falls_back_to_background_priority():
    config = _base_config(PREPROCESSING_PRIORITIES={'collections': {}, 'field_boosts': {}})
    document = {'severity': 'HIGH'}

    assert resolve_preprocessing_priority('cnnvd', document, config) == 2


def test_scan_projection_includes_boost_fields():
    projection = scan_projection(_base_config())

    assert projection == {'details': 1, 'severity': 1, 'status': 1}


def test_sorted_scan_collections_orders_by_base_priority():
    config = _base_config()
    names = ['cnnvd', 'zeroday', 'cve', 'avd']

    assert sorted_scan_collections(names, config) == ['zeroday', 'cve', 'cnnvd', 'avd']


def test_review_document_sort_key_prefers_higher_collection_priority():
    config = _base_config()
    newer_low = {
        '_id': 'cnnvd:1',
        'scraped_at': '2026-06-15T00:00:00+00:00',
    }
    older_high = {
        '_id': 'zeroday:1',
        'scraped_at': '2026-06-01T00:00:00+00:00',
    }

    assert review_document_sort_key('zeroday', older_high, config) > review_document_sort_key(
        'cnnvd',
        newer_low,
        config,
    )


def test_review_document_sort_key_falls_back_to_scraped_at():
    config = _base_config()
    newer = {'_id': 'a:2', 'scraped_at': '2026-06-10T00:00:00+00:00'}
    older = {'_id': 'a:1', 'scraped_at': '2026-06-01T00:00:00+00:00'}

    assert review_document_sort_key('cnnvd', newer, config) > review_document_sort_key(
        'cnnvd',
        older,
        config,
    )


def test_review_document_sort_key_applies_field_boosts():
    config = _base_config()
    boosted = {
        '_id': 'cve:1',
        'scraped_at': '2026-06-01T00:00:00+00:00',
        'severity': 'critical',
    }
    unboosted = {
        '_id': 'cve:2',
        'scraped_at': '2026-06-15T00:00:00+00:00',
    }

    assert review_document_sort_key('cve', boosted, config) > review_document_sort_key(
        'cve',
        unboosted,
        config,
    )
