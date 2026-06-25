import pytest

from subscription_data import (
    build_match_filter,
    build_scraped_at_window,
    parse_hong_kong_datetime,
    parse_include_unknown,
    query_profile_matches,
    validate_filters,
    validate_profile,
)


@pytest.fixture(autouse=True)
def patch_review_views(monkeypatch):
    monkeypatch.setattr('subscription_data.review_views', lambda database: {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
        'avd_review': {'options': {'viewOn': 'avd', 'pipeline': [{'$project': {'title': 1}}]}},
    })


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
    assert filters['status'] == ['Critical']
    with pytest.raises(ValueError, match='Severity/status'):
        validate_filters(FakeDatabase(), {'status': 'urgent'})
    with pytest.raises(ValueError, match='Severity/status'):
        validate_filters(FakeDatabase(), {'status': ['Critical', 'Urgent']})

    legacy_unknown = validate_filters(FakeDatabase(), {'status': 'Unknown'})
    assert legacy_unknown['status'] == []
    assert legacy_unknown['include_unknown'] is True

    multi = validate_filters(FakeDatabase(), {'status': ['Critical', 'High', 'Critical']})
    assert multi['status'] == ['Critical', 'High']

    high_with_unknown = build_match_filter({
        **filters,
        'status': ['High'],
        'include_unknown': True,
    })
    assert '$or' in high_with_unknown
    assert {'severity': {'$exists': False}} in high_with_unknown['$or']

    multi_filter = build_match_filter({
        'status': ['Critical', 'High'],
        'include_unknown': False,
        'time_window': 'all',
    })
    assert '$or' in multi_filter
    assert len(multi_filter['$or']) == 2

    known_only = build_match_filter({**filters, 'status': [], 'include_unknown': False})
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


def test_cpe_pairs_use_broad_keyboard_style_search_clauses():
    filters = validate_filters(FakeDatabase(), {
        'cpe_pairs': [{'vendor': 'Red Hat', 'product': 'Enterprise Linux'}],
    })
    mongo_filter = build_match_filter({
        **filters,
        'time_window': 'all',
    })

    assert '$and' in mongo_filter
    clause_text = str(mongo_filter['$and'])
    assert 'classification.best_vendor' in clause_text
    assert 'classification.best_product' in clause_text
    assert 'description' in clause_text
    assert 'Red' in clause_text
    assert 'Hat' in clause_text
    assert 'Enterprise' in clause_text
    assert 'Linux' in clause_text


def test_multiple_cpe_pairs_combine_with_or():
    mongo_filter = build_match_filter({
        'cpe_pairs': [
            {'vendor': 'Red Hat', 'product': 'Enterprise Linux'},
            {'vendor': 'Acme', 'product': 'Widget'},
        ],
        'time_window': 'all',
    })

    assert '$and' in mongo_filter
    cpe_clause = mongo_filter['$and'][0]
    assert '$or' in cpe_clause
    assert len(cpe_clause['$or']) == 2


def test_ensure_sub_account_collection_creates_empty_collection():
    from app import app
    from mongo import get_web_database
    from subscription_data import SUB_ACCOUNT_COLLECTION, ensure_sub_account_collection

    with app.app_context():
        database = get_web_database()
        if SUB_ACCOUNT_COLLECTION in database.list_collection_names():
            database.drop_collection(SUB_ACCOUNT_COLLECTION)

        ensure_sub_account_collection()

        assert SUB_ACCOUNT_COLLECTION in database.list_collection_names()
        assert database[SUB_ACCOUNT_COLLECTION].find_one({}) is None

        database.drop_collection(SUB_ACCOUNT_COLLECTION)
