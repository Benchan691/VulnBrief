from io import BytesIO

import pytest
from pymongo.errors import ServerSelectionTimeoutError
from zoneinfo import ZoneInfo

from app import app
from subscriptions.profiles import SUB_ACCOUNT_COLLECTION
from core.database import get_web_database


HONG_KONG = ZoneInfo('Asia/Hong_Kong')
TEST_EMAIL = 'subscriptions-test@example.com'


@pytest.fixture()
def client(monkeypatch):
    class FakeMailer:
        def __init__(self, config):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def send_email(self, receiver, email):
            pass

    monkeypatch.setattr('subscriptions.routes.Mailer', FakeMailer)
    app.config.update(TESTING=True)
    with app.app_context():
        get_web_database()[SUB_ACCOUNT_COLLECTION].delete_many({'email': TEST_EMAIL})
    client = app.test_client()
    yield client
    with app.app_context():
        get_web_database()[SUB_ACCOUNT_COLLECTION].delete_many({'email': TEST_EMAIL})


def authenticate(client):
    with client.session_transaction() as session:
        session['username'] = 'test-user'


def _mock_run_database(monkeypatch, documents_by_source):
    from core.database import get_vulnerabilities_database

    database = get_vulnerabilities_database()

    class FakeCursor:
        def __init__(self, documents):
            self.documents = documents

        def sort(self, *args, **kwargs):
            return self

        def __iter__(self):
            return iter(self.documents)

    class FakeCollection:
        def __init__(self, documents):
            self.documents = documents

        def aggregate(self, pipeline):
            return FakeCursor(self.documents)

    class WrappingDatabase:
        def __getattr__(self, name):
            return getattr(database, name)

        def __getitem__(self, name):
            if name in documents_by_source:
                return FakeCollection(documents_by_source[name])
            return database[name]

    monkeypatch.setattr(
        'subscriptions.routes.get_vulnerabilities_database',
        lambda: WrappingDatabase(),
    )


def test_subscriptions_requires_authentication(client):
    assert client.get('/subscriptions').status_code == 302
    assert client.get('/api/subscriptions').status_code == 401
    assert client.post('/api/subscriptions', json={}).status_code == 401
    assert client.get('/api/subscriptions/vendor-product-template.csv').status_code == 401
    assert client.post('/api/subscriptions/vendor-product-import').status_code == 401
    assert client.get('/api/subscriptions/schema').status_code == 401
    assert client.post('/api/subscriptions/preview', json={}).status_code == 401


def test_subscription_schema_describes_live_public_configuration(client, monkeypatch):
    authenticate(client)
    monkeypatch.setattr(
        'subscriptions.profiles.review_views',
        lambda database: {'cve_review': {}, 'avd_review': {}},
    )

    response = client.get('/api/subscriptions/schema')

    assert response.status_code == 200
    schema = response.get_json()
    assert schema['schema_version'] == 1
    assert schema['review_collections'] == ['avd_review', 'cve_review']
    assert schema['allowed_values']['generation_mode'] == ['enriched_weekly', 'template']
    assert schema['allowed_values']['severity'] == ['Critical', 'High', 'Low', 'Medium']
    assert schema['vendor_product_filter']['row_fields'] == [
        'vendor', 'product', 'vendor_aliases', 'product_aliases',
    ]
    assert schema['vendor_product_filter']['limits']['max_rows'] == 500
    serialized = str(schema)
    for internal in (
        'delivery_cursor', 'cve_delivery_cutoff', 'next_run_at',
        'schedule_claim_owner', 'schedule_claim_until',
    ):
        assert internal not in serialized


def test_subscription_preview_normalizes_without_writing_or_sending(client, monkeypatch):
    authenticate(client)
    monkeypatch.setattr(
        'subscriptions.profiles.review_views',
        lambda database: {'cve_review': {}},
    )

    class UnexpectedMailer:
        def __init__(self, config):
            raise AssertionError('preview must not construct a mailer')

    monkeypatch.setattr('subscriptions.routes.Mailer', UnexpectedMailer)
    before = get_web_database()[SUB_ACCOUNT_COLLECTION].count_documents({'email': TEST_EMAIL})
    response = client.post('/api/subscriptions/preview', json={
        'mode': 'create',
        'email': TEST_EMAIL,
        'newsletter_profile': {
            'enabled': True,
            'filters': {'collections': ['cve_review'], 'severity_threshold': 'High'},
        },
        'report_profile': {
            'generation_mode': 'template',
            'filters': {'collections': ['cve_review']},
        },
    })

    assert response.status_code == 200
    preview = response.get_json()
    assert preview['valid'] is True
    assert preview['normalized_profiles']['newsletter_profile']['filters']['severity_threshold'] == 'High'
    assert preview['normalized_profiles']['report_profile']['report_language'] == 'en'
    assert preview['applied_defaults']
    assert get_web_database()[SUB_ACCOUNT_COLLECTION].count_documents({'email': TEST_EMAIL}) == before


def test_subscription_preview_update_preserves_existing_profiles_without_writing(client, monkeypatch):
    authenticate(client)
    monkeypatch.setattr(
        'subscriptions.profiles.review_views',
        lambda database: {'cve_review': {}},
    )
    created = client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'newsletter_profile': {'enabled': True, 'filters': {'collections': ['cve_review']}},
        'report_profile': {'enabled': True, 'filters': {'collections': ['cve_review']}},
    })
    assert created.status_code == 201
    collection = get_web_database()[SUB_ACCOUNT_COLLECTION]
    before = collection.find_one({'email': TEST_EMAIL})

    response = client.post('/api/subscriptions/preview', json={
        'mode': 'update',
        'email': TEST_EMAIL,
    })

    assert response.status_code == 200
    preview = response.get_json()
    assert preview['email'] == TEST_EMAIL
    assert preview['normalized_profiles']['newsletter_profile']['filters']['collections'] == ['cve_review']
    assert preview['normalized_profiles']['report_profile']['filters']['collections'] == ['cve_review']
    after = collection.find_one({'email': TEST_EMAIL})
    assert after == before


@pytest.mark.parametrize('profile', [
    {'filters': {'collections': ['not-a-live-review']}},
    {'filters': {'severity_threshold': 'Urgent'}},
    {'filters': {'time_window': 'custom', 'start': '2026-01-02', 'end': '2026-01-01'}},
])
def test_subscription_preview_returns_sanitized_validation_errors(client, monkeypatch, profile):
    authenticate(client)
    monkeypatch.setattr(
        'subscriptions.profiles.review_views',
        lambda database: {'cve_review': {}},
    )

    response = client.post('/api/subscriptions/preview', json={
        'mode': 'create',
        'report_profile': profile,
    })

    assert response.status_code == 400
    assert set(response.get_json()) == {'error'}
    assert '<html' not in response.get_json()['error'].lower()


def test_subscriptions_crud_validates_review_views(client):
    authenticate(client)

    page = client.get('/subscriptions')
    assert page.status_code == 200
    assert b'/static/js/shared/collection-picker.js' in page.data
    assert b'/static/js/subscriptions/index.js' in page.data
    assert b'id="page-config"' in page.data
    assert b'vendorProductImportUrl' in page.data
    assert b'vendorProductTemplateUrl' in page.data

    invalid = client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'subscriptions': ['avd'],
    })
    assert invalid.status_code == 400

    created = client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'subscriptions': ['avd_review', 'hkcert_review'],
    })
    assert created.status_code == 201

    subscriptions = client.get('/api/subscriptions').get_json()['data']
    created_record = next(item for item in subscriptions if item['email'] == TEST_EMAIL)
    assert created_record['email'] == TEST_EMAIL
    assert created_record['team'] == 'Test'
    assert created_record['newsletter_profile']['enabled'] is False
    assert created_record['report_profile']['filters']['collections'] == [
        'avd_review', 'hkcert_review',
    ]

    updated = client.put(f'/api/subscriptions/{TEST_EMAIL}', json={
        'subscriptions': ['cve_review'],
    })
    assert updated.status_code == 200

    assert client.delete(f'/api/subscriptions/{TEST_EMAIL}').status_code == 200


def test_new_subscription_sends_confirmation_email(client, monkeypatch):
    authenticate(client)
    sent = {}

    class FakeMailer:
        def __init__(self, config):
            assert config['SUBSCRIPTION_CONFIRMATION_CANCEL_URL'] == 'https://example.com/cancel'

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def send_email(self, receiver, email):
            sent['receiver'] = receiver
            sent['email'] = email

    monkeypatch.setattr('subscriptions.routes.Mailer', FakeMailer)
    monkeypatch.setitem(
        app.config, 'SUBSCRIPTION_CONFIRMATION_CANCEL_URL', 'https://example.com/cancel',
    )

    response = client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'newsletter_profile': {
            'enabled': True,
            'filters': {'collections': ['avd_review'], 'keywords': ['Apache']},
        },
        'report_profile': {
            'enabled': True,
            'filters': {'collections': ['hkcert_review'], 'severity_threshold': 'High'},
        },
    })

    assert response.status_code == 201
    assert sent['receiver'] == TEST_EMAIL
    assert sent['email']['subject'] == 'Subscription confirmed'
    assert 'Newsletter Feed: enabled' in sent['email']['text']
    assert 'Collections: avd_review' in sent['email']['text']
    assert 'Keywords: Apache' in sent['email']['text']
    assert 'Minimum severity: High' in sent['email']['text']
    assert 'Security Portal' in sent['email']['html']
    assert 'badge-confirmed' in sent['email']['html']
    assert 'Manage or cancel subscription' in sent['email']['html']
    assert 'https://example.com/cancel' in sent['email']['html']


def test_subscription_update_sends_branded_change_notification(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'subscriptions': ['avd_review'],
    }).status_code == 201
    sent = {}

    class RecordingMailer:
        def __init__(self, config):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def send_email(self, receiver, email):
            sent['receiver'] = receiver
            sent['email'] = email

    monkeypatch.setattr('subscriptions.routes.Mailer', RecordingMailer)
    monkeypatch.setitem(
        app.config, 'SUBSCRIPTION_CONFIRMATION_CANCEL_URL', 'https://example.com/cancel',
    )

    response = client.put(f'/api/subscriptions/{TEST_EMAIL}', json={
        'newsletter_profile': {
            'enabled': True,
            'filters': {'collections': ['avd_review'], 'keywords': ['Apache']},
        },
    })

    assert response.status_code == 200
    assert sent['receiver'] == TEST_EMAIL
    assert sent['email']['subject'] == 'Subscription updated'
    assert 'What changed:' in sent['email']['text']
    assert '- Newsletter Feed status' in sent['email']['text']
    assert '- Newsletter Feed filters' in sent['email']['text']
    assert 'Current subscription details:' in sent['email']['text']
    assert 'badge-updated' in sent['email']['html']
    assert 'Manage or cancel subscription' in sent['email']['html']


def test_subscription_edit_preserves_hidden_cve_delivery_cutoff(client):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'newsletter_profile': {
            'enabled': True,
            'filters': {'collections': ['cve_review']},
        },
    }).status_code == 201

    cutoff = '2026-07-23T04:00:00+00:00'
    with app.app_context():
        get_web_database()[SUB_ACCOUNT_COLLECTION].update_one(
            {'email': TEST_EMAIL},
            {'$set': {'newsletter_profile.cve_delivery_cutoff': cutoff}},
        )

    public = next(item for item in client.get('/api/subscriptions').get_json()['data'] if item['email'] == TEST_EMAIL)
    assert 'cve_delivery_cutoff' not in public['newsletter_profile']

    response = client.put(f'/api/subscriptions/{TEST_EMAIL}', json={
        'newsletter_profile': {
            'enabled': True,
            'filters': {'collections': ['cve_review'], 'keywords': ['Apache']},
        },
    })

    assert response.status_code == 200
    with app.app_context():
        stored = get_web_database()[SUB_ACCOUNT_COLLECTION].find_one({'email': TEST_EMAIL})
    assert stored['newsletter_profile']['cve_delivery_cutoff'] == cutoff


def test_unchanged_subscription_update_does_not_send_email(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'subscriptions': ['avd_review'],
    }).status_code == 201
    sent = []

    class RecordingMailer:
        def __init__(self, config):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def send_email(self, receiver, email):
            sent.append((receiver, email))

    monkeypatch.setattr('subscriptions.routes.Mailer', RecordingMailer)

    response = client.put(f'/api/subscriptions/{TEST_EMAIL}', json={'team': 'Test'})

    assert response.status_code == 200
    assert sent == []


def test_existing_report_keywords_are_preserved_until_csv_replaces_them(client):
    authenticate(client)
    with app.app_context():
        get_web_database()[SUB_ACCOUNT_COLLECTION].insert_one({
            'email': TEST_EMAIL,
            'team': 'Legacy',
            'newsletter_profile': {'enabled': False, 'filters': {}},
            'report_profile': {
                'enabled': True,
                'generation_mode': 'enriched_weekly',
                'filters': {'keywords': ['Red Hat']},
            },
        })

    public = next(
        item for item in client.get('/api/subscriptions').get_json()['data']
        if item['email'] == TEST_EMAIL
    )
    assert public['report_profile']['legacy_keyword_filter'] is True

    unchanged = client.put(f'/api/subscriptions/{TEST_EMAIL}', json={'team': 'Renamed'})
    assert unchanged.status_code == 200
    with app.app_context():
        stored = get_web_database()[SUB_ACCOUNT_COLLECTION].find_one({'email': TEST_EMAIL})
    assert stored['report_profile']['filters']['keywords'] == ['Red Hat']

    report = public['report_profile']
    report_without_replacement = {
        **report,
        'filters': {
            **report['filters'],
            'keywords': [],
        },
    }
    rejected = client.put(f'/api/subscriptions/{TEST_EMAIL}', json={
        'report_profile': report_without_replacement,
    })
    assert rejected.status_code == 400
    assert 'cannot be removed from an active profile' in rejected.get_json()['error']

    report['filters']['vendor_product_filter'] = {
        'enabled': True,
        'schema_version': 1,
        'include_possible_matches': False,
        'rows': [{
            'vendor': 'Red Hat',
            'product': 'Enterprise Linux',
            'vendor_aliases': [],
            'product_aliases': ['RHEL'],
        }],
    }
    replaced = client.put(f'/api/subscriptions/{TEST_EMAIL}', json={
        'report_profile': report,
    })
    assert replaced.status_code == 200
    with app.app_context():
        stored = get_web_database()[SUB_ACCOUNT_COLLECTION].find_one({'email': TEST_EMAIL})
    assert stored['report_profile']['filters']['keywords'] == []
    assert stored['report_profile']['filters']['vendor_product_filter']['enabled'] is True


def test_subscription_cancellation_sends_branded_confirmation(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'subscriptions': ['avd_review'],
    }).status_code == 201
    sent = {}

    class RecordingMailer:
        def __init__(self, config):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def send_email(self, receiver, email):
            sent['receiver'] = receiver
            sent['email'] = email

    monkeypatch.setattr('subscriptions.routes.Mailer', RecordingMailer)

    response = client.delete(f'/api/subscriptions/{TEST_EMAIL}')

    assert response.status_code == 200
    assert sent['receiver'] == TEST_EMAIL
    assert sent['email']['subject'] == 'Subscription cancelled'
    assert 'Future Security Portal newsletter and report deliveries have stopped.' in sent['email']['text']
    assert 'badge-cancelled' in sent['email']['html']
    assert 'Manage or cancel subscription' not in sent['email']['html']


def test_update_and_cancellation_keep_changes_when_notification_email_fails(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'subscriptions': ['avd_review'],
    }).status_code == 201

    class FailingMailer:
        def __init__(self, config):
            pass

        def __enter__(self):
            raise OSError('SMTP unavailable')

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr('subscriptions.routes.Mailer', FailingMailer)

    updated = client.put(f'/api/subscriptions/{TEST_EMAIL}', json={'team': 'Updated team'})
    assert updated.status_code == 503
    assert updated.get_json()['error'] == (
        'Subscription was updated, but the notification email could not be sent.'
    )
    with app.app_context():
        stored = get_web_database()[SUB_ACCOUNT_COLLECTION].find_one({'email': TEST_EMAIL})
    assert stored['team'] == 'Updated team'

    cancelled = client.delete(f'/api/subscriptions/{TEST_EMAIL}')
    assert cancelled.status_code == 503
    assert cancelled.get_json()['error'] == (
        'Subscription was cancelled, but the notification email could not be sent.'
    )
    with app.app_context():
        assert get_web_database()[SUB_ACCOUNT_COLLECTION].find_one({'email': TEST_EMAIL}) is None


def test_new_subscription_keeps_record_when_confirmation_email_fails(client, monkeypatch):
    authenticate(client)

    class FailingMailer:
        def __init__(self, config):
            pass

        def __enter__(self):
            raise OSError('SMTP unavailable')

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr('subscriptions.routes.Mailer', FailingMailer)

    response = client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'subscriptions': ['avd_review'],
    })

    assert response.status_code == 503
    assert response.get_json()['error'] == (
        'Subscription was saved, but the confirmation email could not be sent.'
    )
    with app.app_context():
        stored = get_web_database()[SUB_ACCOUNT_COLLECTION].find_one({'email': TEST_EMAIL})
    assert stored is not None


def test_subscription_report_preview_returns_count_and_top_cves(client, monkeypatch):
    authenticate(client)

    monkeypatch.setattr(
        'subscriptions.routes.preview_profile_matches',
        lambda database, profile, sample_limit: ({
            'count': 3,
            'confirmed_count': 2,
            'probable_count': 1,
            'possible_count': 0,
        }, [
            {
                'collection': 'cve_review',
                'source_collection': 'cve',
                'selection_id': '1',
                'vendor_product_match': {
                    'confidence': 'confirmed',
                    'matched_vendor': 'Acme',
                    'matched_product': 'Widget',
                    'row_number': 2,
                    'evidence': {
                        'type': 'structured_pair',
                        'source': 'details.affected[0]',
                        'vendor': 'Acme',
                        'product': 'Widget',
                    },
                },
                'document': {
                    'code': 'CVE-2026-0001',
                    'severity': 'Critical',
                    'details': {'cve': {'description': 'Active exploitation with remote code execution'}},
                },
            },
            {
                'collection': 'cve_review',
                'source_collection': 'cve',
                'selection_id': '2',
                'document': {
                    'code': 'CVE-2026-0002',
                    'severity': 'High',
                    'details': {'cve': {'description': 'Proof of concept exploit'}},
                },
            },
            {
                'collection': 'cve_review',
                'source_collection': 'cve',
                'selection_id': '3',
                'document': {
                    'code': 'CVE-2026-0003',
                    'severity': 'Medium',
                    'details': {'cve': {'description': 'Moderate impact'}},
                },
            },
        ]),
    )

    response = client.post('/api/subscriptions/report-preview', json={
        'report_profile': {
            'enabled': True,
            'generation_mode': 'enriched_weekly',
            'report_language': 'en',
            'filters': {
                'vendor_product_filter': {
                    'enabled': True,
                    'rows': [{
                        'vendor': 'Acme',
                        'product': 'Widget',
                        'vendor_aliases': [],
                        'product_aliases': [],
                    }],
                },
            },
        },
    })

    assert response.status_code == 200
    body = response.get_json()
    assert body['count'] == 3
    assert body['confirmed_count'] == 2
    assert body['probable_count'] == 1
    assert body['possible_count'] == 0
    assert body['vendor_product_filter_enabled'] is True
    assert body['match_examples'][0]['confidence'] == 'confirmed'
    assert body['match_examples'][0]['evidence']['source'] == 'details.affected[0]'
    assert body['top_cves'][0] == 'CVE-2026-0001'
    assert len(body['top_cves']) == 3


def test_subscription_report_preview_rejects_invalid_profile(client):
    authenticate(client)

    response = client.post('/api/subscriptions/report-preview', json={
        'report_profile': {
            'enabled': True,
            'filters': {'status': 'Urgent'},
        },
    })

    assert response.status_code == 400
    assert response.get_json()['error'].startswith('Severity/status must be')


def test_subscription_report_preview_returns_json_for_unexpected_error(client, monkeypatch):
    authenticate(client)
    def fail_preview(*args, **kwargs):
        raise RuntimeError('Preview exploded')

    monkeypatch.setattr('subscriptions.routes.preview_profile_matches', fail_preview)

    response = client.post('/api/subscriptions/report-preview', json={
        'report_profile': {
            'enabled': True,
            'generation_mode': 'enriched_weekly',
            'report_language': 'en',
            'filters': {},
        },
    })

    assert response.status_code == 500
    assert response.get_json()['error'] == 'Preview exploded'


def test_subscriptions_run_daily_window_selects_matching_source_documents(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'subscriptions': ['avd_review', 'hkcert_review'],
    }).status_code == 201

    _mock_run_database(monkeypatch, {
        'avd': [{'_id': 'avd-1'}],
        'hkcert': [{'_id': 'hk-1'}],
    })
    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/run', json={'window': 'daily'})

    assert response.status_code == 200
    body = response.get_json()
    assert body['count'] > 0
    assert all(item['collection'] in {'avd_review', 'hkcert_review'} for item in body['selections'])


def test_subscriptions_run_week_window(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'subscriptions': ['avd_review'],
    }).status_code == 201

    _mock_run_database(monkeypatch, {'avd': [{'_id': 'avd-week'}]})
    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/run', json={'window': 'week'})
    assert response.status_code == 200
    assert response.get_json()['count'] > 0


def test_subscriptions_run_custom_window(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'subscriptions': ['avd_review'],
    }).status_code == 201

    _mock_run_database(monkeypatch, {'avd': [{'_id': 'avd-custom'}]})
    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/run', json={
        'window': 'custom',
        'start': '2026-06-05T00:00',
        'end': '2026-06-06T12:00',
    })
    assert response.status_code == 200
    assert response.get_json()['count'] > 0


def test_subscriptions_run_rejects_invalid_window_and_handles_database_failure(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'subscriptions': [],
    }).status_code == 201

    invalid = client.post(f'/api/subscriptions/{TEST_EMAIL}/run', json={
        'window': 'custom',
        'start': '2026-06-06T12:00',
        'end': '2026-06-06T08:00',
    })
    assert invalid.status_code == 400

    def unavailable_database():
        raise ServerSelectionTimeoutError('unavailable')

    monkeypatch.setattr('subscriptions.routes.get_vulnerabilities_database', unavailable_database)
    failed = client.post(f'/api/subscriptions/{TEST_EMAIL}/run', json={'window': 'daily'})
    assert failed.status_code == 503


def test_disabled_report_profile_cannot_run(client):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'report_profile': {'enabled': False, 'filters': {}},
    }).status_code == 201

    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/run', json={})
    assert response.status_code == 400
    assert response.get_json()['error'] == 'Report profile is disabled.'


def test_send_subscription_statistic_emails_delivery_counts(client, monkeypatch):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'newsletter_profile': {'enabled': True, 'filters': {'collections': ['avd_review']}},
        'report_profile': {'enabled': True},
    }).status_code == 201

    with app.app_context():
        get_web_database()['newsletter_deliveries'].delete_many({'email': TEST_EMAIL})
        get_web_database()['newsletter_deliveries'].insert_many([
            {
                'email': TEST_EMAIL,
                'database': 'vulnerabilities',
                'source_collection': 'avd',
                'selection_id': 'avd:1',
                'title': 'One',
                'sent_at': '2026-07-01T00:00:00+00:00',
            },
            {
                'email': TEST_EMAIL,
                'database': 'vulnerabilities',
                'source_collection': 'avd',
                'selection_id': 'avd:2',
                'title': 'Two',
                'sent_at': '2026-07-02T00:00:00+00:00',
            },
            {
                'email': TEST_EMAIL,
                'database': 'vulnerabilities',
                'source_collection': 'hkcert',
                'selection_id': 'hkcert:1',
                'title': 'Three',
                'sent_at': '2026-07-03T00:00:00+00:00',
            },
        ])

    sent = {}

    class FakeMailer:
        def __init__(self, config):
            self.config = config

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def send_email(self, receiver, email):
            sent.update({
                'to': receiver,
                'subject': email['subject'],
                'html': email['html'],
            })

    monkeypatch.setattr('subscriptions.routes.Mailer', FakeMailer)

    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/send-statistic')
    assert response.status_code == 200
    body = response.get_json()
    assert body['message'] == 'Newsletter statistics email sent.'
    assert body['statistics']['total'] == 3
    assert body['statistics']['databases'] == ['vulnerabilities']
    assert sent['to'] == TEST_EMAIL
    assert sent['subject'] == 'Newsletter delivery statistics'
    assert 'Total newsletters sent' in sent['html']
    assert 'metric-value' in sent['html']
    assert 'Security Portal' in sent['html']
    assert 'avd' in sent['html']
    assert 'hkcert' in sent['html']

    with app.app_context():
        get_web_database()['newsletter_deliveries'].delete_many({'email': TEST_EMAIL})


def test_send_subscription_statistic_requires_newsletter_enabled(client):
    authenticate(client)
    assert client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'newsletter_profile': {'enabled': False},
        'report_profile': {'enabled': True},
    }).status_code == 201

    response = client.post(f'/api/subscriptions/{TEST_EMAIL}/send-statistic')
    assert response.status_code == 400
    assert response.get_json()['error'] == 'Newsletter feed is disabled for this subscription.'


def test_subscription_rejects_invalid_severity_choice(client):
    authenticate(client)
    response = client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'report_profile': {
            'enabled': True,
            'filters': {'status': 'Urgent'},
        },
    })
    assert response.status_code == 400
    assert response.get_json()['error'].startswith('Severity/status must be')


def test_vendor_product_template_and_import_endpoints(client):
    authenticate(client)

    template = client.get('/api/subscriptions/vendor-product-template.csv')
    assert template.status_code == 200
    assert template.headers['Content-Disposition'].startswith('attachment;')
    assert template.headers['Content-Type'] == 'text/csv; charset=utf-8'
    assert template.data.startswith(b'vendor,product,vendor_aliases,product_aliases')

    imported = client.post(
        '/api/subscriptions/vendor-product-import',
        data={
            'file': (
                BytesIO(
                    b'vendor,product,vendor_aliases,product_aliases\n'
                    b'Microsoft,Exchange Server,Microsoft Corporation,Exchange\n'
                ),
                'inventory.csv',
            ),
        },
        content_type='multipart/form-data',
    )

    assert imported.status_code == 200
    inventory = imported.get_json()['vendor_product_filter']
    assert inventory['enabled'] is True
    assert inventory['rows'][0]['vendor'] == 'Microsoft'
    assert inventory['rows'][0]['product'] == 'Exchange Server'


def test_report_profile_accepts_schedule_and_vendor_product_inventory(client):
    authenticate(client)
    vendor_product_filter = {
        'enabled': True,
        'schema_version': 1,
        'include_possible_matches': False,
        'rows': [{
            'vendor': 'Red Hat',
            'product': 'Enterprise Linux',
            'vendor_aliases': ['RedHat'],
            'product_aliases': ['RHEL'],
        }],
    }
    response = client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'report_profile': {
            'enabled': True,
            'generation_mode': 'enriched_weekly',
            'report_language': 'zh',
            'schedule_enabled': True,
            'schedule_weekday': 'fri',
            'schedule_time': '14:30',
            'filters': {
                'vendor_product_filter': vendor_product_filter,
            },
        },
    })

    assert response.status_code == 201
    item = next(item for item in client.get('/api/subscriptions').get_json()['data'] if item['email'] == TEST_EMAIL)
    assert item['report_profile']['schedule_enabled'] is True
    assert item['report_profile']['schedule_weekday'] == 'fri'
    assert item['report_profile']['schedule_time'] == '14:30'
    assert item['report_profile']['next_run_at']
    assert item['report_profile']['filters']['keywords'] == []
    stored_inventory = item['report_profile']['filters']['vendor_product_filter']
    assert stored_inventory['enabled'] is True
    assert stored_inventory['include_possible_matches'] is False
    assert stored_inventory['rows'][0] == {
        **vendor_product_filter['rows'][0],
        'row_number': 2,
    }


def test_newsletter_profile_accepts_monthly_statistic_schedule(client):
    authenticate(client)
    response = client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'newsletter_profile': {
            'enabled': True,
            'statistic_schedule_enabled': True,
            'filters': {'collections': ['avd_review']},
        },
        'report_profile': {'enabled': True},
    })

    assert response.status_code == 201
    item = next(item for item in client.get('/api/subscriptions').get_json()['data'] if item['email'] == TEST_EMAIL)
    assert item['newsletter_profile']['statistic_schedule_enabled'] is True
    assert item['newsletter_profile']['statistic_next_run_at']


def test_newsletter_profile_accepts_vendor_product_inventory(client):
    authenticate(client)
    vendor_product_filter = {
        'enabled': True,
        'schema_version': 1,
        'include_possible_matches': True,
        'rows': [{
            'vendor': 'Red Hat',
            'product': 'Enterprise Linux',
            'vendor_aliases': ['RedHat'],
            'product_aliases': ['RHEL'],
        }],
    }
    response = client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'newsletter_profile': {
            'enabled': True,
            'filters': {
                'collections': ['cve_review'],
                'vendor_product_filter': vendor_product_filter,
            },
        },
        'report_profile': {'enabled': False},
    })

    assert response.status_code == 201
    item = next(item for item in client.get('/api/subscriptions').get_json()['data'] if item['email'] == TEST_EMAIL)
    assert item['newsletter_profile']['filters']['keywords'] == []
    stored_inventory = item['newsletter_profile']['filters']['vendor_product_filter']
    assert stored_inventory['enabled'] is True
    assert stored_inventory['include_possible_matches'] is True
    assert stored_inventory['rows'][0] == {
        **vendor_product_filter['rows'][0],
        'row_number': 2,
    }

    updated = client.put(f'/api/subscriptions/{TEST_EMAIL}', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'newsletter_profile': {
            'enabled': True,
            'filters': {
                'collections': ['cve_review'],
                'vendor_product_filter': {
                    **vendor_product_filter,
                    'include_possible_matches': False,
                },
            },
        },
        'report_profile': {'enabled': False},
    })
    assert updated.status_code == 200
    item = next(item for item in client.get('/api/subscriptions').get_json()['data'] if item['email'] == TEST_EMAIL)
    assert item['newsletter_profile']['filters']['vendor_product_filter']['include_possible_matches'] is False


def test_report_profile_rejects_invalid_schedule_and_legacy_keywords(client):
    authenticate(client)
    bad_schedule = client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'report_profile': {'schedule_enabled': True, 'schedule_weekday': 'funday'},
    })
    assert bad_schedule.status_code == 400

    bad_keywords = client.post('/api/subscriptions', json={
        'email': TEST_EMAIL,
        'team': 'Test',
        'report_profile': {'filters': {'keywords': ['redhat']}},
    })
    assert bad_keywords.status_code == 400
    assert 'no longer supported' in bad_keywords.get_json()['error']
