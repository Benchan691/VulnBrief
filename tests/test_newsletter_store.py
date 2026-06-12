from pathlib import Path

from app import app
from mongo import get_local_mongo_client
from newsletter_store import (
    SOURCE_TEMPLATE_KEYS,
    _record_id,
    get_newsletter_collection,
    normalize_newsletter,
    render_newsletter,
    sync_newsletters,
    template_key_for_source,
)


def test_generic_newsletter_has_required_sections_and_sanitizes_source_html():
    document = {
        'title': 'Example Advisory',
        'details': {
            'example': {
                'description': '<p>Safe overview</p><script>alert(1)</script>',
                'impacts': ['Remote Code Execution'],
                'affected_products': ['Example Product'],
                'recommendations': ['Apply the update.'],
                'references': ['https://example.com/reference'],
                'related_links': ['https://example.com/related'],
            },
        },
    }
    with app.app_context():
        html, normalized = render_newsletter(document, 'example')

    assert normalized['template_key'] == 'generic'
    assert '<script>' not in html
    assert 'alert(1)' in html
    for section in (
        'Overview:', 'Severity:', 'Affected system:', 'Recommendations:',
        'References:', 'Related Links:',
    ):
        assert section in html
    assert 'Impacts:' not in html


def test_every_active_source_has_a_dedicated_template():
    for source in SOURCE_TEMPLATE_KEYS:
        assert template_key_for_source(source) == source
        assert Path(
            app.root_path, app.template_folder, 'newsletter', f'generated_{source}.html',
        ).is_file()


def test_hkcert_newsletter_omits_empty_table():
    document = {
        'title': 'HKCERT Advisory',
        'details': {
            'hkcert': {
                'summary': 'Summary',
                'risk_level': 'High Risk',
                'impact': ['Remote Code Execution'],
                'systems_affected': ['Product A'],
                'table': [],
            },
        },
    }
    normalized = normalize_newsletter(document, 'hkcert')

    assert normalized['template_key'] == 'hkcert'
    assert normalized['table'] is None
    assert normalized['severity'] == ['High Risk']
    assert normalized['impacts'] == ['Remote Code Execution']

    with app.app_context():
        html, _ = render_newsletter(document, 'hkcert')
    assert 'Severity:' in html
    assert 'Impacts:' in html


def test_hkcert_newsletter_renders_non_empty_table():
    document = {
        'details': {
            'hkcert': {
                'table': [{'Vulnerable Product': 'Product A', 'Risk Level': 'High'}],
            },
        },
    }
    with app.app_context():
        html, normalized = render_newsletter(document, 'hkcert')

    assert normalized['table']['rows'] == [['Product A', 'High']]
    assert '<table>' in html
    assert 'Product A' in html


def test_source_specific_newsletter_fields_use_semantic_values():
    cases = [
        (
            'cisco',
            {
                'title': 'Cisco Advisory',
                'status': 'Interim',
                'severity': 'High',
                'details': {'cisco': {'sir': 'High', 'product_names': ['Router']}},
            },
            ['High'],
            ['Router'],
        ),
        (
            'paloalto',
            {
                'title': 'Palo Alto Advisory',
                'severity': 'High',
                'details': {
                    'paloalto': {
                        'severity': 'HIGH',
                        'products': ['Cortex XSOAR'],
                        'impact': [{'id': 'CAPEC-475', 'name': 'Signature Spoofing'}],
                    },
                },
            },
            ['High'],
            ['Cortex XSOAR'],
        ),
        (
            'avd',
            {
                'title': 'AVD Advisory',
                'severity': 'High',
                'details': {
                    'avd': {
                        'affected_software': [{
                            'vendor': 'apache',
                            'product': 'activemq',
                            'version': '*',
                            'impact': 'Up to 5.19.7',
                        }],
                    },
                },
            },
            ['High'],
            ['apache activemq * Up to 5.19.7'],
        ),
    ]

    for source, document, severity, affected in cases:
        normalized = normalize_newsletter(document, source)
        assert normalized['severity'] == severity
        assert normalized['impacts'] == []
        assert normalized['affected'] == affected


def test_source_specific_newsletter_sections_and_references():
    huawei = normalize_newsletter({
        'title': 'Huawei Advisory',
        'status': 'NEW',
        'severity': 'Critical',
        'details': {'huawei_sa': {'severity': 'Critical'}},
        'source': {'detail_url': 'https://example.test/huawei'},
    }, 'huawei_sa')
    assert huawei['severity'] == ['Critical']
    assert huawei['impacts'] == []
    assert not huawei['show_affected']

    infosec = normalize_newsletter({
        'details': {'infosec': {'affected_systems': ['System A']}},
        'source': {'detail_url': 'https://example.test/infosec'},
    }, 'infosec')
    assert infosec['affected'] == ['System A']
    assert infosec['references'] == ['https://example.test/infosec']

    hkcert = normalize_newsletter({
        'details': {'hkcert': {}},
        'source': {'detail_url': 'https://www.hkcert.org/security-bulletin/example'},
    }, 'hkcert')
    assert hkcert['references'] == ['https://www.hkcert.org/security-bulletin/example']


def test_cnvd_title_juniper_affected_table_and_zeroday_hidden_sections():
    cnvd = normalize_newsletter({
        'title': 'Mozilla Firefox存在未明漏洞（CNVD-2026-2...',
        'details': {
            'cnvd': {
                'title': '相关漏洞',
                'raw_fields': {
                    '厂商补丁': 'Mozilla Firefox存在未明漏洞（CNVD-2026-23640）的补丁',
                },
            },
        },
    }, 'cnvd')
    assert cnvd['title'] == 'Mozilla Firefox存在未明漏洞（CNVD-2026-23640）'

    juniper = normalize_newsletter({
        'details': {
            'juniper': {
                'raw_tables': [[['Product', 'Status'], ['Junos OS', 'Affected']]],
            },
        },
    }, 'juniper')
    assert juniper['affected_table'] == {
        'headers': ['Product', 'Status'],
        'rows': [['Junos OS', 'Affected']],
    }

    with app.app_context():
        html, zeroday = render_newsletter({
            'details': {'zeroday': {'vulnerable_component': 'Component A'}},
        }, 'zeroday')
    assert not zeroday['show_severity']
    assert not zeroday['show_affected']
    assert 'Severity:' not in html
    assert 'Affected system:' not in html


def test_chinese_source_templates_use_chinese_language_and_labels():
    for source in ('cnvd', 'cnnvd', 'huawei_sa', 'qianxin'):
        with app.app_context():
            html, normalized = render_newsletter({
                'title': '漏洞通报',
                'severity': 'High',
                'details': {source: {'summary': '漏洞摘要'}},
            }, source)

        assert normalized['language'] == 'zh-Hans'
        assert '<html lang="zh-Hans">' in html
        assert '概述：' in html
        assert '严重程度：' in html
        assert '建议：' in html


def test_similar_source_shapes_are_mapped_without_flattening_metadata():
    cve = normalize_newsletter({
        'title': 'CVE-2026-1000',
        'severity': 'High',
        'details': {
            'cve': {
                'title': 'Example vulnerability',
                'descriptions': [{'lang': 'en', 'value': 'Useful description'}],
                'affected_products': ['Example Product < 2.0'],
                'references': [{'url': 'https://example.test/cve'}],
            },
        },
    }, 'cve')
    assert cve['title'] == 'Example vulnerability'
    assert str(cve['overview']) == 'Useful description'
    assert cve['affected'] == ['Example Product < 2.0']

    github = normalize_newsletter({
        'severity': 'Medium',
        'details': {
            'github_advisory': {
                'vulnerabilities': [{
                    'package': {'ecosystem': 'npm', 'name': 'example'},
                    'vulnerable_version_range': '< 2.0',
                    'first_patched_version': '2.0',
                }],
            },
        },
    }, 'github_advisory')
    assert github['affected'] == ['npm:example < 2.0']
    assert github['recommendations'] == ['2.0']


def test_generated_newsletter_route_renders_latest_source_and_removes_legacy_html(monkeypatch):
    client = app.test_client()
    with client.session_transaction() as session:
        session['username'] = 'test-user'
    source = {
        '_id': 'avd:live',
        'title': 'Latest source title',
        'details': {'avd': {'summary': 'Latest source summary'}},
    }
    record_id = _record_id('avd', source['_id'])
    with app.app_context():
        collection = get_newsletter_collection()
        collection.insert_one({
            '_id': record_id,
            'source_collection': 'avd',
            'selection_id': source['_id'],
            'html': '<p>stale</p>',
        })
    monkeypatch.setattr('routes.newsletter.get_vulnerabilities_database', lambda: object())
    monkeypatch.setattr(
        'routes.newsletter.resolve_vulnerability_document',
        lambda database, collection, selection_id: source,
    )
    try:
        response = client.get(f'/generated-newsletters/{record_id}')
        assert response.status_code == 200
        assert b'Latest source summary' in response.data
        assert b'stale' not in response.data
        with app.app_context():
            assert 'html' not in get_newsletter_collection().find_one({'_id': record_id})
    finally:
        with app.app_context():
            get_newsletter_collection().delete_one({'_id': record_id})


def test_generated_newsletter_route_rejects_legacy_record_without_source_metadata():
    client = app.test_client()
    with client.session_transaction() as session:
        session['username'] = 'test-user'
    with app.app_context():
        collection = get_newsletter_collection()
        collection.insert_one({'_id': 'legacy-newsletter'})
    try:
        response = client.get('/generated-newsletters/legacy-newsletter')
        assert response.status_code == 422
        assert response.get_json()['error'] == 'Generated newsletter is missing source metadata.'
    finally:
        with app.app_context():
            get_newsletter_collection().delete_one({'_id': 'legacy-newsletter'})


def test_newsletter_sync_updates_changed_sources_and_removes_unmatched_records(monkeypatch):
    source_name = 'newsletter_sync_test'
    email = 'newsletter-sync-test@example.com'
    with app.app_context():
        local = get_local_mongo_client()['newsletter_sync_test_local']
        local.drop_collection('subscriptions')
        local.drop_collection('generated_newsletters')
        source = {
            '_id': f'{source_name}:1',
            'title': 'Initial title',
            'status': 'High',
            'scraped_at': '2026-06-11T00:00:00+00:00',
            'source': {'provider': source_name},
            'details': {source_name: {'summary': 'Initial summary'}},
        }
        matches = [{
            'collection': f'{source_name}_review',
            'source_collection': source_name,
            'selection_id': source['_id'],
        }]
        monkeypatch.setattr('newsletter_store.get_web_database', lambda: local)
        monkeypatch.setattr('newsletter_store.get_vulnerabilities_database', lambda: object())
        monkeypatch.setattr('newsletter_store.normalize_subscription', lambda database, value: value)
        monkeypatch.setattr(
            'newsletter_store.query_profile_matches',
            lambda database, profile, limit=None: matches,
        )
        monkeypatch.setattr(
            'newsletter_store.resolve_vulnerability_document',
            lambda database, collection, selection_id: dict(source),
        )
        local['subscriptions'].insert_one({
            'email': email,
            'team': 'Test',
            'newsletter_profile': {
                'enabled': True,
                'filters': {'collections': [f'{source_name}_review']},
            },
            'report_profile': {'enabled': False, 'filters': {}},
        })
        try:
            assert sync_newsletters()['tracked'] == 1
            first = get_newsletter_collection().find_one({'subscription_emails': email})
            assert 'html' not in first
            assert first['title'] == 'Initial title'
            get_newsletter_collection().update_one(
                {'_id': first['_id']},
                {'$set': {'html': '<p>legacy</p>', 'html_path': 'legacy.html'}},
            )

            source['details'][source_name]['summary'] = 'Updated summary'
            source['title'] = 'Updated title'
            assert sync_newsletters()['tracked'] == 1
            updated = get_newsletter_collection().find_one({'_id': first['_id']})
            assert updated['source_fingerprint'] != first['source_fingerprint']
            assert updated['title'] == 'Updated title'
            assert 'html' not in updated
            assert 'html_path' not in updated

            local['subscriptions'].delete_one({'email': email})
            assert sync_newsletters()['tracked'] == 0
            assert get_newsletter_collection().find_one({'_id': first['_id']}) is None
        finally:
            get_local_mongo_client().drop_database('newsletter_sync_test_local')
