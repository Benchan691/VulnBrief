from datetime import datetime, timezone

import pytest

from subscription_data import build_match_filter, next_cron_run, validate_cron, validate_filters


def test_curated_filter_builds_combined_mongo_match():
    mongo_filter = build_match_filter({
        'search': 'openssl',
        'code': 'CVE-2026',
        'title': '',
        'impact': 'execution',
        'affected': 'server',
        'status': 'High',
        'source': 'hkcert',
        'time_window': 'custom',
        'start': '2026-06-01T00:00+08:00',
        'end': '2026-06-02T00:00+08:00',
    })

    assert '$and' in mongo_filter
    assert any('scraped_at' in clause for clause in mongo_filter['$and'])
    assert len(mongo_filter['$and']) == 7


def test_severity_filter_uses_fixed_choices_and_separate_unknown_switch():
    class FakeDatabase:
        def list_collections(self, filter=None):
            return []

    filters = validate_filters(FakeDatabase(), {'status': 'Critical'})
    assert filters['status'] == 'Critical'
    with pytest.raises(ValueError, match='Severity/status'):
        validate_filters(FakeDatabase(), {'status': 'urgent'})

    legacy_unknown = validate_filters(FakeDatabase(), {'status': 'Unknown'})
    assert legacy_unknown['status'] == ''
    assert legacy_unknown['include_unknown'] is True

    high_with_unknown = build_match_filter({
        **filters,
        'status': 'High',
        'include_unknown': True,
    })
    assert '$or' in high_with_unknown
    assert {'severity': {'$exists': False}} in high_with_unknown['$or']

    known_only = build_match_filter({**filters, 'status': '', 'include_unknown': False})
    assert known_only['severity']['$regex'].startswith('^(?:Critical')


def test_five_field_cron_validation_and_next_run_use_hong_kong_time():
    assert validate_cron('0 9 * * 1') == '0 9 * * 1'
    with pytest.raises(ValueError, match='five-field cron'):
        validate_cron('0 9 * *')

    next_run = next_cron_run(
        '0 9 * * *',
        datetime(2026, 6, 11, 0, 30, tzinfo=timezone.utc),
    )
    assert next_run == datetime(2026, 6, 11, 1, 0, tzinfo=timezone.utc)
