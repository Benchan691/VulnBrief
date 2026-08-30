from app import app
from newsletters.normalizer import (
    SOURCE_TEMPLATE_KEYS,
    extract_cvss_string,
    normalize_newsletter,
    render_newsletter,
    template_key_for_source,
)


def test_cvss_string_is_extracted_from_common_source_shapes():
    document = {
        'details': {
            'metrics': {
                'cvss_v31': [{
                    'cvssData': {
                        'version': '3.1',
                        'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                        'baseScore': 9.8,
                        'baseSeverity': 'CRITICAL',
                    },
                }],
            },
        },
    }

    assert extract_cvss_string(document, document['details']) == (
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 CRITICAL)'
    )
    assert normalize_newsletter(document, 'cve')['cvss']
    with app.app_context():
        html, _ = render_newsletter(document, 'cve', {
            'sources': {'cve': {'fields': ['title', 'cvss']}},
        })
    assert 'CVSS:' in html
    assert '9.8 CRITICAL' in html


def test_cvss_field_is_omitted_when_source_does_not_provide_cvss():
    normalized = normalize_newsletter({'details': {'summary': 'No score'}}, 'cve')

    assert normalized['cvss'] == ''


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


def test_github_advisory_renders_markdown_and_safe_images_for_email():
    document = {
        'title': 'Gogs Mirror Settings bypass',
        'details': {
            'github_advisory': {
                'description': '''## Summary

This is **important** and [tracked](https://github.com/gogs/gogs).

* First step
* `SaveAddress`

![Migration validation](https://github.com/user-attachments/assets/secure-image)
<img src="https://github.com/user-attachments/assets/raw-image" alt="Raw image" width="1200" height="755" onerror="alert(1)">
<img src="http://example.test/insecure-image" alt="Insecure">
<img src="file:///etc/passwd" alt="Local">
<script>alert(1)</script>''',
            },
        },
    }

    with app.app_context():
        html, normalized = render_newsletter(document, 'github_advisory')

    assert normalized['template_key'] == 'github_advisory'
    assert '<h2>Summary</h2>' in html
    assert '<strong>important</strong>' in html
    assert '<a href="https://github.com/gogs/gogs">tracked</a>' in html
    assert '<li>First step</li>' in html
    assert '<code>SaveAddress</code>' in html
    assert '![Migration validation]' not in html
    assert 'https://github.com/user-attachments/assets/secure-image' in html
    assert 'https://github.com/user-attachments/assets/raw-image' in html
    assert 'alt="Raw image"' in html
    assert 'width="1200"' in html
    assert 'height="755"' in html
    assert 'onerror=' not in html
    assert 'http://example.test/insecure-image' not in html
    assert 'file:///etc/passwd' not in html
    assert '<script>' not in html
    assert 'alert(1)' not in html
    assert '.indent img { max-width: 100%; height: auto; }' in html


def test_non_github_newsletters_do_not_render_markdown_or_images():
    newsletter = normalize_newsletter({
        'details': {
            'descriptions': [{'lang': 'en', 'value': '**Literal Markdown** ![image](https://example.test/image.png)'}],
        },
    }, 'cve')

    assert str(newsletter['overview']) == '**Literal Markdown** ![image](https://example.test/image.png)'


def test_every_active_source_has_a_dedicated_template():
    for source in SOURCE_TEMPLATE_KEYS:
        assert template_key_for_source(source) == source


def test_zimbra_patch_newsletter_includes_fixes_packages_and_references():
    normalized = normalize_newsletter({
        'title': 'Zimbra 10.1.20 Patch Release',
        'details': {
            'security_fixes': ['Fixed command injection.'],
            'fixed_issues': {'Zimbra Collaboration': ['Fixed mail redirects.']},
            'packages': {'zimbra-patch': '10.1.20.1783418035-2'},
            'reference_links': ['https://wiki.zimbra.com/wiki/Zimbra_Releases/10.1.20'],
        },
    }, 'zimbra')

    assert normalized['template_key'] == 'zimbra'
    assert normalized['recommendations'] == [
        'Fixed command injection.',
        'Zimbra Collaboration: Fixed mail redirects.',
    ]
    assert normalized['affected'] == ['zimbra-patch: 10.1.20.1783418035-2']
    assert normalized['references'] == ['https://wiki.zimbra.com/wiki/Zimbra_Releases/10.1.20']


def test_zimbra_renderer_preserves_source_sections_and_escapes_text():
    document = {
        'title': 'Zimbra 10.1.20 Patch Release',
        'details': {
            'title': 'Zimbra Daffodil (v10.1.20) Patch Release',
            'security_fixes': ['Fixed <script>alert(1)</script>.'],
            'fixed_issues': {'Licensing': ['Fixed license reset.']},
            'packages': {'zimbra-patch': '10.1.20.1783418035-2'},
            'patch_installation_url': 'https://wiki.zimbra.com/patch_installation',
            'open_source_repo_url': 'https://github.com/Zimbra/zm-build',
            'reference_links': ['https://wiki.zimbra.com/wiki/Zimbra_Releases/10.1.20'],
        },
    }

    with app.app_context():
        html, normalized = render_newsletter(document, 'zimbra')

    assert normalized['title'] == 'Zimbra 10.1.20 Patch Release'
    assert normalized['subtitle'] == 'Zimbra Daffodil (v10.1.20) Patch Release'
    assert html.index('Zimbra 10.1.20 Patch Release') < html.index('Security Fixes')
    assert html.index('Security Fixes') < html.index('Fixed Issues')
    assert html.index('Fixed Issues') < html.index('Packages')
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in html
    assert '<script>alert(1)</script>' not in html


def test_hpe_renderer_extracts_bulletin_fields_and_omits_raw_dump():
    document = {
        'title': 'HPESBNW05125 rev.1 - HPE Networking Security Bulletin',
        'severity': 'Critical',
        'published_at': '2026-08-24T16:00:00Z',
        'updated_at': '2026-08-28T09:48:11Z',
        'source': {
            'url': 'https://support.hpe.com/security-bulletins',
            'detail_url': 'https://support.hpe.com/document/hpesbnw05125en_us',
        },
        'details': {
            'bulletin_id': 'HPESBNW05125',
            'doc_display_url': 'https://support.hpe.com/document/hpesbnw05125en_us',
            'document_subtype': 'Security Bulletin',
            'document_version': '1',
            'potential_security_impact': 'Remote: Access Restriction Bypass',
            'source': 'Hewlett Packard Enterprise, HPE Product Security Response Team',
            'summary': 'HPESBNW05125 rev.1 - HPE Networking Security Bulletin',
            'references': 'References:\nPSRT112813',
            'supported_software_versions': 'Aruba CX 9300 Switch Series N/A\nAruba Fabric Composer N/A',
            'background': (
                'BACKGROUND\n'
                'Information on CVSS is documented in HPE\n'
                'Customer Notice.\n\n'
                'A second background paragraph remains separate.'
            ),
            'resolution': 'RESOLUTION\nUpgrade the affected devices.',
            'history': 'HISTORY\nVersion:1 (rev.1) - Initial release',
            'cvss_text': (
                'VULNERABILITY SUMMARY\n'
                'A <script>alert(1)</script> issue affects HPE networking\n'
                'products and requires an update.\n'
                'On September 1st, 2026 (Pacific Time) HPE Networking will be\n'
                'publishing the related advisory.\n'
                'These advisories will be reviewed before release.\n'
                'HPE Networking product lines have received enhanced testing for\n'
                'security vulnerabilities.\n'
                'References:\nPSRT112813\n'
                'SUPPORTED SOFTWARE VERSIONS\nAruba CX 9300 Switch Series N/A'
            ),
            'reference_links': [
                'https://www.hpe.com/info/report-security-vulnerability',
                'http://unsafe.example/reference',
            ],
        },
    }

    normalized = normalize_newsletter(document, 'hpe')

    assert normalized['template_key'] == 'hpe'
    assert normalized['cvss'] == ''
    assert normalized['bulletin_id'] == 'HPESBNW05125'
    assert normalized['vulnerability_summary'].startswith('A <script>')
    assert normalized['vulnerability_summary_paragraphs'] == [
        'A <script>alert(1)</script> issue affects HPE networking products and requires an update.',
        'On September 1st, 2026 (Pacific Time) HPE Networking will be publishing the related advisory.',
        'These advisories will be reviewed before release.',
        'HPE Networking product lines have received enhanced testing for security vulnerabilities.',
    ]
    assert normalized['background_paragraphs'] == [
        'Information on CVSS is documented in HPE Customer Notice.',
        'A second background paragraph remains separate.',
    ]
    assert normalized['supported_versions'] == [
        'Aruba CX 9300 Switch Series N/A',
        'Aruba Fabric Composer N/A',
    ]
    assert normalized['reference_ids'] == ['PSRT112813']
    assert normalized['references'] == [
        'https://support.hpe.com/document/hpesbnw05125en_us',
        'https://www.hpe.com/info/report-security-vulnerability',
    ]
    assert normalized['related_links'] == ['https://support.hpe.com/security-bulletins']

    with app.app_context():
        html, _ = render_newsletter(document, 'hpe', {
            'common': {'extra': 'Extra <b>notice</b>', 'footer': 'Footer'},
        })

    assert 'Security Bulletin' in html
    assert 'Potential Security Impact' in html
    assert 'Supported Software Versions' in html
    assert 'Background' in html
    assert 'Resolution' in html
    assert 'History' in html
    assert html.index('Bulletin Information') < html.index('Vulnerability Summary')
    assert html.index('Vulnerability Summary') < html.index('Supported Software Versions')
    assert html.index('Supported Software Versions') < html.index('Background')
    assert html.index('products and requires an update.') < html.index('On September 1st')
    assert html.index('On September 1st') < html.index('These advisories will')
    assert html.index('These advisories will') < html.index('HPE Networking product lines')
    assert 'white-space: pre-line' not in html
    assert 'max-width' not in html
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in html
    assert '<script>alert(1)</script>' not in html
    assert 'unsafe.example' not in html
    assert 'cvss_text' not in html
    assert '<b>notice</b>' in html
    assert 'Footer' in html


def test_hpe_renderer_omits_empty_source_sections():
    document = {
        'title': 'HPE Advisory',
        'details': {
            'cvss_text': 'VULNERABILITY SUMMARY\nOnly the summary is available.',
        },
    }

    with app.app_context():
        html, normalized = render_newsletter(document, 'hpe')

    assert normalized['vulnerability_summary_paragraphs'] == ['Only the summary is available.']
    for section in (
        'Supported Software Versions', 'Background', 'Resolution', 'History',
        'References', 'Reference Links',
    ):
        assert section not in html


def test_hkcert_newsletter_omits_empty_table():
    document = {
        'title': 'HKCERT Advisory',
        'details': {
            'summary': 'Summary',
            'risk_level': 'High Risk',
            'impact': ['Remote Code Execution'],
            'systems_affected': ['Product A'],
            'table': [],
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
                'vulnerability_identifiers': [{'cve_id': 'CVE-2026-2000'}],
            },
            'cve_ids': ['CVE-2026-1000', 'CVE-2026-2000'],
        },
        'hkcert',
    )

    assert normalized['cves'] == ['CVE-2026-2000', 'CVE-2026-1000']


def test_hkcert_newsletter_renders_non_empty_table():
    document = {
        'details': {
            'table': [{'Vulnerable Product': 'Product A', 'Risk Level': 'High'}],
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
                'severity': 'High',
                'details': {'sir': 'High', 'product_names': ['Router']},
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
                    'severity': 'HIGH',
                    'products': ['Cortex XSOAR'],
                    'impact': [{'id': 'CAPEC-475', 'name': 'Signature Spoofing'}],
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
                    'affected_software': [{
                        'vendor': 'apache',
                        'product': 'activemq',
                        'version': '*',
                        'impact': 'Up to 5.19.7',
                    }],
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


def test_fortiguard_newsletter_uses_affected_products_table():
    document = {
        'title': 'FortiGuard Advisory',
        'severity': 'High',
        'details': {
            'summary': 'Broken access control',
            'affected_products': [{
                'version': 'FortiWeb 8.0',
                'affected': '8.0.0 through 8.0.2',
                'solution': 'Upgrade to 8.0.3 or above',
            }],
            'cvrf_url': 'https://www.fortiguard.com/psirt/cvrf/FG-IR-26-158',
            'csaf_url': 'https://example.test/csaf.json',
        },
    }
    normalized = normalize_newsletter(document, 'fortiguard')

    assert normalized['severity'] == ['High']
    assert normalized['affected'] == []
    assert normalized['recommendations'] == []
    assert not normalized['show_recommendations']
    assert normalized['affected_table'] == {
        'headers': ['Version', 'Affected', 'Solution'],
        'rows': [['FortiWeb 8.0', '8.0.0 through 8.0.2', 'Upgrade to 8.0.3 or above']],
    }

    with app.app_context():
        html, rendered = render_newsletter(document, 'fortiguard')

    assert rendered['affected_table']['rows'][0][0] == 'FortiWeb 8.0'
    assert '<table>' in html
    assert 'FortiWeb 8.0' in html
    assert 'Upgrade to 8.0.3 or above' in html
    assert 'Recommendations:' not in html
    assert 'Affected system:' in html


def test_source_specific_newsletter_sections_and_references():
    huawei = normalize_newsletter({
        'title': 'Huawei Advisory',
        'change_type': 'new',
        'severity': 'Critical',
        'details': {'severity': 'Critical'},
        'source': {'detail_url': 'https://example.test/huawei'},
    }, 'huawei_sa')
    assert huawei['severity'] == ['Critical']
    assert huawei['impacts'] == []
    assert not huawei['show_affected']

    infosec = normalize_newsletter({
        'details': {'affected_systems': ['System A']},
        'source': {'detail_url': 'https://example.test/infosec'},
    }, 'infosec')
    assert infosec['affected'] == ['System A']
    assert infosec['references'] == ['https://example.test/infosec']

    hkcert = normalize_newsletter({
        'details': {},
        'source': {'detail_url': 'https://www.hkcert.org/security-bulletin/example'},
    }, 'hkcert')
    assert hkcert['references'] == ['https://www.hkcert.org/security-bulletin/example']


def test_cnvd_title_juniper_affected_table_and_zeroday_hidden_sections():
    cnvd = normalize_newsletter({
        'title': 'Mozilla Firefox存在未明漏洞（CNVD-2026-2...',
        'details': {
            'title': '相关漏洞',
            'raw_fields': {
                '厂商补丁': 'Mozilla Firefox存在未明漏洞（CNVD-2026-23640）的补丁',
            },
        },
    }, 'cnvd')
    assert cnvd['title'] == 'Mozilla Firefox存在未明漏洞（CNVD-2026-23640）'

    cnvd_without_patch = normalize_newsletter({
        'title': 'Tenda JD12L缓冲区溢出漏洞',
        'details': {
            'title': 'Tenda JD12L缓冲区溢出漏洞',
            'raw_fields': {'厂商补丁': '(无补丁信息)'},
        },
    }, 'cnvd')
    assert cnvd_without_patch['title'] == 'Tenda JD12L缓冲区溢出漏洞'

    juniper = normalize_newsletter({
        'details': {
            'raw_tables': [[['Product', 'Status'], ['Junos OS', 'Affected']]],
        },
    }, 'juniper')
    assert juniper['affected_table'] == {
        'headers': ['Product', 'Status'],
        'rows': [['Junos OS', 'Affected']],
    }

    with app.app_context():
        html, zeroday = render_newsletter({
            'details': {'vulnerable_component': 'Component A'},
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
                'details': {'summary': '漏洞摘要'},
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
            'descriptions': [{'lang': 'en', 'value': 'Useful description'}],
            'affected': [{
                'vendor': 'Example Vendor',
                'product': 'Example Product',
                'versions': [{'lessThan': '2.0'}],
            }],
            'references': [{'url': 'https://example.test/cve'}],
        },
    }, 'cve')
    assert cve['title'] == 'CVE-2026-1000'
    assert str(cve['overview']) == 'Useful description'
    assert cve['affected'] == ['Example Vendor Example Product < 2.0']
    assert cve['references'] == ['https://example.test/cve']

    github = normalize_newsletter({
        'severity': 'Medium',
        'details': {
            'vulnerabilities': [{
                'package': {'ecosystem': 'npm', 'name': 'example'},
                'vulnerable_version_range': '< 2.0',
                'first_patched_version': '2.0',
            }],
        },
    }, 'github_advisory')
    assert github['affected'] == ['npm:example < 2.0']
    assert github['recommendations'] == ['2.0']


def test_cve_details_fields_populate_the_newsletter():
    newsletter = normalize_newsletter({
        'title': 'CVE-2026-8616',
        'details': {
            'descriptions': [{'lang': 'en', 'value': 'Missing authorization permits unauthenticated option deletion.'}],
            'affected': [{
                'vendor': 'devozon',
                'product': 'Fense Proxy & VPN Blocker',
                'versions': [{'version': '0', 'lessThanOrEqual': '3.0.1'}],
            }],
            'references': [{'url': 'https://example.test/advisory'}],
        },
    }, 'cve')

    assert newsletter['title'] == 'CVE-2026-8616'
    assert str(newsletter['overview']) == 'Missing authorization permits unauthenticated option deletion.'
    assert newsletter['affected'] == ['devozon Fense Proxy & VPN Blocker <= 3.0.1']
    assert newsletter['references'] == ['https://example.test/advisory']


def test_cve_newsletter_title_keeps_meaningful_titles_and_normalizes_fallbacks():
    meaningful = normalize_newsletter({
        'code': 'CVE-2026-8616',
        'title': 'Fense Proxy & VPN Blocker missing authorization',
    }, 'cve')
    generic = normalize_newsletter({
        'code': 'CVE-2026-8616',
        'title': 'CVE-2026-8616 Record',
        'details': {
            'descriptions': [{
                'lang': 'en',
                'value': 'This description must not be appended to the title.',
            }],
        },
    }, 'cve')
    missing = normalize_newsletter({
        'code': 'CVE-2026-8617',
        'details': {
            'cve': {
                'descriptions': [{
                    'lang': 'en',
                    'value': 'A missing title still falls back to the CVE ID only.',
                }],
            },
        },
    }, 'cve')

    assert meaningful['title'] == 'Fense Proxy & VPN Blocker missing authorization'
    assert generic['title'] == 'CVE-2026-8616'
    assert missing['title'] == 'CVE-2026-8617'


def test_cve_empty_affected_data_is_rendered_as_not_specified():
    document = {
        'title': 'CVE-2026-0001',
        'details': {'cve': {'affected': []}},
    }
    with app.app_context():
        html, newsletter = render_newsletter(document, 'cve')

    assert newsletter['affected'] == []
    assert '<li>Not specified</li>' in html


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
