from datetime import datetime, timezone

import pytest

from subscription_data import (
    build_match_filter,
    build_scraped_at_window,
    next_cron_run,
    parse_hong_kong_datetime,
    parse_include_unknown,
    query_profile_matches,
    validate_cron,
    validate_filters,
    validate_profile,
)


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


def test_parse_hong_kong_datetime_accepts_z_suffix_and_naive_local_times():
    assert parse_hong_kong_datetime('2026-06-01T08:30Z').isoformat() == '2026-06-01T16:30:00+08:00'
    assert parse_hong_kong_datetime('2026-06-01T08:30').isoformat() == '2026-06-01T08:30:00+08:00'


def test_build_scraped_at_window_returns_none_for_all():
    assert build_scraped_at_window('all') is None


def test_parse_include_unknown_accepts_common_truthy_values():
    assert parse_include_unknown('true') is True
    assert parse_include_unknown('1') is True
    assert parse_include_unknown(None) is False


def test_five_field_cron_validation_and_next_run_use_hong_kong_time():
    assert validate_cron('0 9 * * 1') == '0 9 * * 1'
    with pytest.raises(ValueError, match='five-field cron'):
        validate_cron('0 9 * *')

    next_run = next_cron_run(
        '0 9 * * *',
        datetime(2026, 6, 11, 0, 30, tzinfo=timezone.utc),
    )
    assert next_run == datetime(2026, 6, 11, 1, 0, tzinfo=timezone.utc)


class FakeDatabase:
    def list_collections(self, filter=None):
        return [
            {'name': 'cve_review', 'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
            {'name': 'avd_review', 'options': {'viewOn': 'avd', 'pipeline': [{'$project': {'title': 1}}]}},
        ]

    def __getitem__(self, name):
        return self

    def aggregate(self, pipeline):
        return iter([])


def test_enriched_weekly_profile_forces_cve_review_only():
    profile = validate_profile(FakeDatabase(), {
        'generation_mode': 'enriched_weekly',
        'filters': {},
    }, 'report')

    assert profile['filters']['collections'] == ['cve_review']

    with pytest.raises(ValueError, match='cve_review'):
        validate_profile(FakeDatabase(), {
            'generation_mode': 'enriched_weekly',
            'filters': {'collections': ['avd_review']},
        }, 'report')


def test_enriched_filters_include_target_fields_threshold_and_scope_limit():
    filters = validate_filters(FakeDatabase(), {
        'target_vendor': 'Acme',
        'target_product': 'Widget',
        'severity_threshold': 'High',
        'report_scope': {'max_count': 3, 'kev_only': True},
    })
    mongo_filter = build_match_filter(filters)

    assert '$and' in mongo_filter
    assert filters['report_scope']['max_count'] == 3
    assert filters['report_scope']['kev_only'] is True
    assert any('classification.best_vendor' in str(clause) for clause in mongo_filter['$and'])
    assert any('classification.best_product' in str(clause) for clause in mongo_filter['$and'])
    assert any('details.cve.kev' in str(clause) for clause in mongo_filter['$and'])

    profile = {'generation_mode': 'enriched_weekly', 'filters': filters}
    assert query_profile_matches(FakeDatabase(), profile, limit=10) == []
