from app import app
from newsletters.feed import _record_id, filter_newsletter_feed
from newsletters.normalizer import (
    SOURCE_TEMPLATE_KEYS,
    normalize_newsletter,
    render_newsletter,
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
        'Source collection:', 'Overview:', 'Severity:', 'Affected system:', 'Recommendations:',
        'References:', 'Related Links:',
    ):
        assert section in html
    assert 'Impacts:' not in html


def test_every_active_source_has_a_dedicated_template():
    for source in SOURCE_TEMPLATE_KEYS:
        assert template_key_for_source(source) == source


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


def test_newsletter_normalizes_bare_cve_codes() -> None:
    normalized = normalize_newsletter(
        {
            'details': {
                'hkcert': {
                    'vulnerability_identifiers': [{'cve_id': 'CVE-2026-2000'}],
                },
            },
            'cve_codes': ['2026-1000', 'CVE-2026-2000'],
        },
        'hkcert',
    )

    assert normalized['cves'] == ['CVE-2026-2000', 'CVE-2026-1000']


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

    cnvd_without_patch = normalize_newsletter({
        'title': 'Tenda JD12L缓冲区溢出漏洞',
        'details': {
            'cnvd': {
                'title': 'Tenda JD12L缓冲区溢出漏洞',
                'raw_fields': {'厂商补丁': '(无补丁信息)'},
            },
        },
    }, 'cnvd')
    assert cnvd_without_patch['title'] == 'Tenda JD12L缓冲区溢出漏洞'

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


def test_cve_v5_cna_fields_populate_the_newsletter():
    newsletter = normalize_newsletter({
        'title': 'CVE-2026-8616',
        'details': {
            'cve': {
                'containers': {
                    'cna': {
                        'title': 'Fense Proxy & VPN Blocker vulnerability',
                        'descriptions': [{'lang': 'en', 'value': 'Missing authorization permits unauthenticated option deletion.'}],
                        'affected': [{
                            'vendor': 'devozon',
                            'product': 'Fense Proxy & VPN Blocker',
                            'versions': [{'version': '0', 'lessThanOrEqual': '3.0.1'}],
                        }],
                        'references': [{'url': 'https://example.test/advisory'}],
                    },
                },
            },
        },
    }, 'cve')

    assert newsletter['title'] == 'Fense Proxy & VPN Blocker vulnerability'
    assert str(newsletter['overview']) == 'Missing authorization permits unauthenticated option deletion.'
    assert newsletter['affected'] == ['devozon Fense Proxy & VPN Blocker <= 3.0.1']
    assert newsletter['references'] == ['https://example.test/advisory']


def test_nested_source_fields_populate_generic_newsletters():
    newsletter = normalize_newsletter({
        'details': {
            'msrc': {
                'advisory': {
                    'description': 'A remote attacker can disclose information.',
                    'affected_products': ['Windows Media Player'],
                    'recommendation': 'Install the security update.',
                    'references': ['https://example.test/msrc'],
                },
            },
        },
    }, 'msrc')

    assert str(newsletter['overview']) == 'A remote attacker can disclose information.'
    assert newsletter['affected'] == ['Windows Media Player']
    assert newsletter['recommendations'] == ['Install the security update.']
    assert newsletter['references'] == ['https://example.test/msrc']
    assert newsletter['collection'] == 'msrc'


def test_generated_newsletter_preview_route_renders_latest_source(monkeypatch):
    client = app.test_client()
    with client.session_transaction() as session:
        session['username'] = 'test-user'
    source = {
        '_id': 'avd:live',
        'title': 'Latest source title',
        'details': {'avd': {'summary': 'Latest source summary'}},
    }
    monkeypatch.setattr('newsletters.routes.get_vulnerabilities_database', lambda: object())
    monkeypatch.setattr(
        'newsletters.routes.resolve_vulnerability_document',
        lambda database, collection, selection_id: source,
    )
    response = client.get('/generated-newsletters/avd/avd:live/preview')
    assert response.status_code == 200
    assert b'Latest source summary' in response.data


def test_generated_newsletter_preview_route_returns_404_when_source_missing(monkeypatch):
    client = app.test_client()
    with client.session_transaction() as session:
        session['username'] = 'test-user'
    monkeypatch.setattr('newsletters.routes.get_vulnerabilities_database', lambda: object())
    monkeypatch.setattr(
        'newsletters.routes.resolve_vulnerability_document',
        lambda database, collection, selection_id: None,
    )
    response = client.get('/generated-newsletters/avd/missing/preview')
    assert response.status_code == 404
    assert response.get_json()['error'] == 'Newsletter source document not found.'


def test_filter_newsletter_feed_builds_live_results_from_atlas_matches(monkeypatch):
    source = {
        '_id': 'avd-1',
        'title': 'Live Advisory',
        'scraped_at': '2026-06-15T12:00:00+00:00',
        'details': {'avd': {'summary': 'Live summary'}},
    }

    def fake_query(database, profile, limit=None, include_documents=False):
        match = {
            'collection': 'avd_review',
            'source_collection': 'avd',
            'selection_id': 'avd-1',
        }
        if include_documents:
            match['document'] = source
        return [match]

    monkeypatch.setattr('newsletters.feed.query_profile_matches', fake_query)
    monkeypatch.setattr('newsletters.feed.validate_filters', lambda database, value: value or {})
    monkeypatch.setattr('newsletters.feed.resolve_vulnerability_document', lambda *args: source)

    items, count = filter_newsletter_feed(None, 'test@example.com', {})
    assert count == 1
    assert len(items) == 1
    assert items[0]['title'] == 'Live Advisory'
    assert items[0]['source_collection'] == 'avd'
    assert items[0]['selection_id'] == 'avd-1'
    assert items[0]['id'] == _record_id('avd', 'avd-1')
    assert items[0]['generated_at'] == '2026-06-15T12:00:00+00:00'

    items, count = filter_newsletter_feed(None, 'test@example.com', {'keyword': 'live summary'})
    assert count == 1
    assert len(items) == 1

    items, count = filter_newsletter_feed(None, 'test@example.com', {'keyword': 'unrelated'})
    assert count == 0
    assert items == []


def test_filter_newsletter_feed_uses_the_raw_source_document(monkeypatch):
    raw_source = {
        '_id': 'msrc-1',
        'title': 'Windows Media Information Disclosure Vulnerability',
        'details': {'msrc': {'description': 'Source-only overview text.'}},
    }
    monkeypatch.setattr(
        'newsletters.feed.query_profile_matches',
        lambda *args, **kwargs: [{
            'source_collection': 'msrc',
            'selection_id': 'msrc-1',
            'document': {'title': 'View projection without details'},
        }],
    )
    monkeypatch.setattr('newsletters.feed.validate_filters', lambda database, value: value or {})
    monkeypatch.setattr('newsletters.feed.resolve_vulnerability_document', lambda *args: raw_source)

    items, count = filter_newsletter_feed(None, 'test@example.com', {'keyword': 'source-only'})

    assert count == 1
    assert items[0]['title'] == 'Windows Media Information Disclosure Vulnerability'
