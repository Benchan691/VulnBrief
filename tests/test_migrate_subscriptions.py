import pytest

from scripts.migrate_subscriptions import (
    build_profiles,
    build_view_indexes,
    is_already_migrated,
    map_legacy_collections,
    migrate_record,
    resolve_legacy_collection,
)


def _fake_views():
    return {
        'hkcert_review': {'options': {'viewOn': 'hkcert'}},
        'huawei_sa_review': {'options': {'viewOn': 'huawei_sa'}},
        'ransomwarelive_review': {'options': {'viewOn': 'ransomwarelive'}},
    }


class FakeDatabase:
    def list_collections(self, filter=None):
        return []


@pytest.fixture()
def indexes():
    return build_view_indexes(_fake_views(), '_review')


def test_resolve_hkcert_to_review_view(indexes):
    by_source, by_name = indexes
    assert resolve_legacy_collection('hkcert', by_source, by_name, '_review') == 'hkcert_review'


def test_resolve_huawei_alias(indexes):
    by_source, by_name = indexes
    assert resolve_legacy_collection('huawei', by_source, by_name, '_review') == 'huawei_sa_review'


def test_resolve_ransome_alias(indexes):
    by_source, by_name = indexes
    assert resolve_legacy_collection('ransome', by_source, by_name, '_review') == 'ransomwarelive_review'


def test_unknown_collection_returns_none(indexes):
    by_source, by_name = indexes
    assert resolve_legacy_collection('huawei_warning', by_source, by_name, '_review') is None


def test_map_legacy_collections_deduplicates_and_warns(indexes):
    by_source, by_name = indexes
    mapped, warnings = map_legacy_collections(
        ['hkcert', 'hkcert', 'huawei_warning'],
        by_source,
        by_name,
        '_review',
    )
    assert mapped == ['hkcert_review']
    assert warnings == ['huawei_warning']


def test_build_profiles_disables_report_and_maps_newsletter_enabled(monkeypatch):
    monkeypatch.setattr(
        'subscription_data.review_views',
        lambda database: _fake_views(),
    )
    database = FakeDatabase()
    newsletter_profile, report_profile = build_profiles(database, {
        'enabled': False,
    }, ['hkcert_review'])

    assert newsletter_profile['enabled'] is False
    assert newsletter_profile['filters']['collections'] == ['hkcert_review']
    assert report_profile['enabled'] is False
    assert report_profile['filters']['collections'] == ['hkcert_review']
    assert report_profile['generation_mode'] == 'template'
    assert report_profile['report_language'] == 'en'


def test_migrate_record_builds_expected_document(indexes, monkeypatch):
    monkeypatch.setattr(
        'subscription_data.review_views',
        lambda database: _fake_views(),
    )
    by_source, by_name = indexes
    record = migrate_record(FakeDatabase(), {
        'email': 'user@example.com',
        'team': 'SOC',
        'enabled': True,
        'subscriptions': ['hkcert', 'huawei', 'ransome', 'missing'],
    }, by_source, by_name, '_review')

    assert record['email'] == 'user@example.com'
    assert record['team'] == 'SOC'
    assert record['newsletter_profile']['enabled'] is True
    assert record['newsletter_profile']['filters']['collections'] == [
        'hkcert_review',
        'huawei_sa_review',
        'ransomwarelive_review',
    ]
    assert record['report_profile']['enabled'] is False
    assert record['warnings'] == ['missing']


def test_is_already_migrated():
    assert is_already_migrated({
        'newsletter_profile': {'enabled': True, 'filters': {}},
        'report_profile': {'enabled': False, 'filters': {}},
    })
    assert not is_already_migrated({'subscriptions': ['hkcert']})
    assert not is_already_migrated({'newsletter_profile': {'enabled': True}})
