import pytest

import subscriptions.query
from subscriptions.profiles import (
    build_observed_at_window,
    parse_hong_kong_datetime,
    parse_include_unknown,
    validate_filters,
    validate_profile,
)
from subscriptions.query import (
    build_match_filter,
    count_profile_matches_by_confidence,
    preview_profile_matches,
    query_profile_matches,
)


def _inventory_row(vendor='Acme', product='Widget'):
    return {
        'vendor': vendor,
        'product': product,
        'vendor_aliases': [],
        'product_aliases': [],
    }


@pytest.fixture(autouse=True)
def patch_review_views(monkeypatch):
    views = {
        'cve_review': {'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1}}]}},
        'avd_review': {'options': {'viewOn': 'avd', 'pipeline': [{'$project': {'title': 1}}]}},
    }
    monkeypatch.setattr('subscriptions.profiles.review_views', lambda database: views)
    monkeypatch.setattr('subscriptions.query.review_views', lambda database: views)


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
    assert any('observed_at' in clause for clause in mongo_filter['$and'])
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


def test_build_observed_at_window_returns_none_for_all():
    assert build_observed_at_window('all') is None


def test_parse_include_unknown_accepts_common_truthy_values():
    assert parse_include_unknown('true') is True
    assert parse_include_unknown('1') is True
    assert parse_include_unknown(None) is False


def test_newsletter_profile_preserves_internal_cve_delivery_cutoff():
    profile = validate_profile(FakeDatabase(), {
        'enabled': True,
        'filters': {},
        'cve_delivery_cutoff': '2026-07-23T04:00:00+00:00',
    }, 'newsletter')

    assert profile['cve_delivery_cutoff'] == '2026-07-23T04:00:00+00:00'


def test_newsletter_profile_accepts_vendor_product_inventory_and_clears_keywords():
    profile = validate_profile(FakeDatabase(), {
        'enabled': True,
        'filters': {
            'keywords': ['legacy'],
            'vendor_product_filter': {
                'enabled': True,
                'schema_version': 1,
                'include_possible_matches': True,
                'rows': [_inventory_row('Microsoft', 'Exchange Server')],
            },
        },
    }, 'newsletter')

    assert profile['filters']['keywords'] == []
    inventory = profile['filters']['vendor_product_filter']
    assert inventory['enabled'] is True
    assert inventory['include_possible_matches'] is True
    assert inventory['rows'][0]['vendor'] == 'Microsoft'
    assert inventory['rows'][0]['product'] == 'Exchange Server'


def test_public_subscription_hides_the_internal_cve_delivery_cutoff():
    from subscriptions.routes import _public_subscription

    public = _public_subscription(FakeDatabase(), {
        'email': 'newsletter@example.com',
        'newsletter_profile': {
            'enabled': True,
            'filters': {},
            'cve_delivery_cutoff': '2026-07-23T04:00:00+00:00',
        },
        'report_profile': {'enabled': False, 'filters': {}},
    })

    assert 'cve_delivery_cutoff' not in public['newsletter_profile']


def test_collection_filter_override_limits_cve_matches_to_the_cutoff(monkeypatch):
    class CapturingCollection:
        def __init__(self):
            self.pipelines = []

        def aggregate(self, pipeline):
            self.pipelines.append(pipeline)
            return iter([])

    class CapturingDatabase:
        def __init__(self):
            self.collections = {
                'cve': CapturingCollection(),
                'avd': CapturingCollection(),
            }

        def __getitem__(self, name):
            return self.collections[name]

    views = {
        'cve_review': {
            'options': {
                'viewOn': 'cve',
                'pipeline': [{'$project': {'title': 1}}],
            },
        },
        'avd_review': {
            'options': {
                'viewOn': 'avd',
                'pipeline': [{'$project': {'title': 1}}],
            },
        },
    }
    monkeypatch.setattr('subscriptions.query.review_views', lambda database: views)
    database = CapturingDatabase()
    filters = validate_filters(FakeDatabase(), {'collections': []})
    cutoff = '2026-07-23T04:00:00+00:00'

    query_profile_matches(
        database,
        {'filters': filters},
        limit=None,
        collection_filter_overrides={
            'cve_review': {
                **filters,
                'include_unknown': True,
                'cve_delivery_cutoff': cutoff,
            },
        },
    )

    cve_match = database['cve'].pipelines[0][1]['$match']
    avd_match = database['avd'].pipelines[0][1]['$match']
    from datetime import datetime
    assert cve_match == {'observed_at': {'$gt': datetime.fromisoformat(cutoff)}}
    assert avd_match['severity']['$regex'].startswith('^(?:Critical')


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


def test_enriched_filters_include_vendor_product_inventory_threshold_and_scope_limit():
    filters = validate_filters(FakeDatabase(), {
        'vendor_product_filter': {
            'enabled': True,
            'schema_version': 1,
            'include_possible_matches': False,
            'rows': [{
                'vendor': 'Acme',
                'product': 'Widget',
                'vendor_aliases': [],
                'product_aliases': [],
            }],
        },
        'severity_threshold': 'High',
        'report_scope': {'max_count': 3, 'kev_only': True},
    })
    mongo_filter = build_match_filter(filters)

    assert '$and' in mongo_filter
    assert filters['report_scope']['max_count'] == 3
    assert filters['report_scope']['kev_only'] is True
    assert 'details.affected.product' in str(mongo_filter)
    assert "'product'" in str(mongo_filter)
    assert any('details.kev' in str(clause) for clause in mongo_filter['$and'])

    profile = {'generation_mode': 'enriched_weekly', 'filters': filters}
    assert query_profile_matches(FakeDatabase(), profile, limit=10) == []


def test_report_profile_rejects_new_keywords_but_can_normalize_legacy_records():
    value = {
        'generation_mode': 'enriched_weekly',
        'filters': {'keywords': ['Red Hat']},
    }

    with pytest.raises(ValueError, match='no longer supported'):
        validate_profile(FakeDatabase(), value, 'report')

    legacy = validate_profile(
        FakeDatabase(),
        value,
        'report',
        allow_legacy_report_keywords=True,
    )
    assert legacy['legacy_keyword_filter'] is True
    assert legacy['filters']['keywords'] == ['Red Hat']


def test_keywords_deduplicate_blanks_and_legacy_cpe_pairs_are_ignored():
    filters = validate_filters(FakeDatabase(), {
        'keywords': [' Red Hat ', 'redhat', '', 'Enterprise Linux'],
        'cpe_pairs': [{'product': 'Only Product'}],
    })

    assert filters['keywords'] == ['Red Hat', 'Enterprise Linux']
    assert 'cpe_pairs' not in filters


def test_keywords_use_or_logic_and_case_space_insensitive_regex():
    filters = validate_filters(FakeDatabase(), {
        'keywords': ['Red Hat', 'Enterprise Linux'],
    })
    mongo_filter = build_match_filter({
        **filters,
        'time_window': 'all',
    })

    assert '$and' in mongo_filter
    assert '$or' in mongo_filter['$and'][0]
    assert len(mongo_filter['$and'][0]['$or']) == 2
    clause_text = str(mongo_filter)
    assert 'details.affected.vendor' in clause_text
    assert 'details.affected.product' in clause_text
    assert 'description' in clause_text
    assert 'classification' not in clause_text
    assert 'r\\\\s*e\\\\s*d\\\\s*h\\\\s*a\\\\s*t' in clause_text
    assert 'e\\\\s*n\\\\s*t\\\\s*e\\\\s*r\\\\s*p\\\\s*r\\\\s*i\\\\s*s\\\\s*e' in clause_text


def test_keyword_filter_combines_with_other_filters():
    mongo_filter = build_match_filter({
        'keywords': ['Red Hat', 'Acme'],
        'status': ['High'],
        'time_window': 'all',
    })

    assert '$and' in mongo_filter
    keyword_clause = mongo_filter['$and'][0]
    assert '$or' in keyword_clause
    assert len(keyword_clause['$or']) == 2


def test_inventory_count_and_selection_use_the_same_confidence_classifier():
    documents = [
        {
            '_id': 'confirmed',
            'details': {'affected': [{'vendor': 'Acme', 'product': 'Widget'}]},
        },
        {
            '_id': 'probable',
            'description': 'Security update for Acme Widget deployments.',
        },
        {
            '_id': 'possible',
            'description': 'Security update for Widget deployments.',
        },
        {
            '_id': 'rejected-cross-pair',
            'details': {'affected': [
                {'vendor': 'Acme', 'product': 'Other'},
                {'vendor': 'Other', 'product': 'Widget'},
            ]},
        },
    ]

    class Collection:
        def aggregate(self, pipeline):
            return iter(documents)

    class Database(FakeDatabase):
        def __getitem__(self, name):
            return Collection()

    filters = validate_filters(Database(), {
        'collections': ['cve_review'],
        'include_unknown': True,
        'vendor_product_filter': {
            'enabled': True,
            'schema_version': 1,
            'include_possible_matches': True,
            'rows': [{
                'vendor': 'Acme',
                'product': 'Widget',
                'vendor_aliases': [],
                'product_aliases': [],
            }],
        },
    })
    profile = {'filters': filters}

    counts = count_profile_matches_by_confidence(Database(), profile)
    matches = query_profile_matches(Database(), profile, limit=10)

    assert counts == {
        'count': 3,
        'confirmed_count': 1,
        'probable_count': 1,
        'possible_count': 1,
    }
    assert [item['selection_id'] for item in matches] == [
        'confirmed', 'probable', 'possible',
    ]
    assert [item['vendor_product_match']['confidence'] for item in matches] == [
        'confirmed', 'probable', 'possible',
    ]


def test_inventory_preview_counts_and_samples_in_one_database_scan():
    documents = [
        {
            '_id': f'cve-{index}',
            'details': {'affected': [{'vendor': 'Acme', 'product': 'Widget'}]},
        }
        for index in range(3)
    ]

    class Collection:
        def __init__(self):
            self.aggregate_calls = 0

        def aggregate(self, pipeline):
            self.aggregate_calls += 1
            return iter(documents)

    collection = Collection()

    class Database(FakeDatabase):
        def __getitem__(self, name):
            return collection

    filters = validate_filters(Database(), {
        'collections': ['cve_review'],
        'include_unknown': True,
        'vendor_product_filter': {
            'enabled': True,
            'rows': [_inventory_row()],
        },
    })

    counts, samples = preview_profile_matches(
        Database(), {'filters': filters}, sample_limit=2,
    )

    assert collection.aggregate_calls == 1
    assert counts['count'] == 3
    assert counts['confirmed_count'] == 3
    assert [item['selection_id'] for item in samples] == ['cve-0', 'cve-1']


def test_inventory_projection_keeps_every_supported_top_level_evidence_root(monkeypatch):
    class CapturingCollection:
        def __init__(self):
            self.pipeline = None

        def aggregate(self, pipeline):
            self.pipeline = pipeline
            return iter([])

    collection = CapturingCollection()

    class Database(FakeDatabase):
        def __getitem__(self, name):
            return collection

    filters = validate_filters(Database(), {
        'collections': ['cve_review'],
        'include_unknown': True,
        'vendor_product_filter': {
            'enabled': True,
            'rows': [_inventory_row()],
        },
    })

    query_profile_matches(Database(), {'filters': filters}, limit=10)

    projection = collection.pipeline[0]['$project']
    for field in (
        'containers', 'descriptions', 'systems_affected', 'products', 'impacts',
    ):
        assert projection[field] == 1


def test_enriched_scope_limit_caps_both_confidence_count_and_selection():
    documents = [
        {
            '_id': f'confirmed-{index}',
            'details': {'affected': [{'vendor': 'Acme', 'product': 'Widget'}]},
        }
        for index in range(3)
    ]

    class Collection:
        def aggregate(self, pipeline):
            return iter(documents)

    class Database(FakeDatabase):
        def __getitem__(self, name):
            return Collection()

    filters = validate_filters(Database(), {
        'collections': ['cve_review'],
        'include_unknown': True,
        'report_scope': {'max_count': 2},
        'vendor_product_filter': {
            'enabled': True,
            'rows': [_inventory_row()],
        },
    })
    profile = {'generation_mode': 'enriched_weekly', 'filters': filters}

    counts = count_profile_matches_by_confidence(Database(), profile)
    matches = query_profile_matches(Database(), profile)

    assert counts == {
        'count': 2,
        'confirmed_count': 2,
        'probable_count': 0,
        'possible_count': 0,
    }
    assert [match['selection_id'] for match in matches] == [
        'confirmed-0', 'confirmed-1',
    ]


def test_ensure_sub_account_collection_creates_empty_collection():
    from app import app
    from core.database import get_web_database
    from subscriptions.profiles import SUB_ACCOUNT_COLLECTION, ensure_sub_account_collection

    with app.app_context():
        database = get_web_database()
        if SUB_ACCOUNT_COLLECTION in database.list_collection_names():
            database.drop_collection(SUB_ACCOUNT_COLLECTION)

        ensure_sub_account_collection()

        assert SUB_ACCOUNT_COLLECTION in database.list_collection_names()
        assert database[SUB_ACCOUNT_COLLECTION].find_one({}) is None

        database.drop_collection(SUB_ACCOUNT_COLLECTION)
