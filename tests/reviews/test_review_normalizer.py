from reviews.normalizer import extract_document_cve_id, normalize_cve_id, normalize_cve_record_document


def test_normalize_cve_id_accepts_common_storage_formats():
    assert normalize_cve_id('2026-12206') == 'CVE-2026-12206'
    assert normalize_cve_id('CVE-2026-12206') == 'CVE-2026-12206'
    assert normalize_cve_id('cve:2026-12206') == 'CVE-2026-12206'
    assert normalize_cve_id(['2026-12206', 'CVE-2026-9999']) == 'CVE-2026-12206'


def test_extract_document_cve_id_prefers_cve_collection_code():
    assert extract_document_cve_id({
        'code': '2026-12007',
        'cve_ids': ['CVE-2026-12000', 'CVE-2026-12001'],
    }) == 'CVE-2026-12007'


def test_normalize_cve_record_document_maps_v2_detail_fields():
    document = {
        '_id': 'cve:2025-32392',
        'code': '2025-32392',
        'title': 'AutoGPT has a DoS vulnerability in LoopVideoBlock',
        'severity': 'High',
        'published_at': '2026-06-18T16:08:18.904Z',
        'details': {
            'descriptions': [
                {'lang': 'en', 'value': 'AutoGPT workflow automation platform vulnerability.'},
            ],
            'affected': [
                {'vendor': 'Significant-Gravitas', 'product': 'AutoGPT'},
            ],
            'references': [
                {'url': 'https://github.com/example/advisories/GHSA-1234'},
            ],
        },
    }

    normalized = normalize_cve_record_document(document)

    assert normalized['code'] == '2025-32392'
    assert normalized['title'].startswith('AutoGPT')
    assert 'workflow automation' in normalized['description']
    assert normalized['severity'] == 'High'
    assert normalized['vendor'] == 'Significant-Gravitas'
    assert normalized['product'] == 'AutoGPT'
    assert 'classification' not in normalized


def test_normalize_cve_record_document_uses_direct_affected_vendor_product():
    document = {
        '_id': 'cve:2026-0001',
        'code': '2026-0001',
        'title': 'CVE-2026-0001',
        'details': {'affected': [{'vendor': 'Acme', 'product': 'Widget'}]},
    }

    normalized = normalize_cve_record_document(document)

    assert normalized['title'] == 'CVE-2026-0001'
    assert 'classification' not in normalized
    assert normalized.get('vendor') == 'Acme'
    assert normalized.get('product') == 'Widget'


def test_normalize_cve_record_document_promotes_direct_details_description():
    document = {
        '_id': '2',
        'code': 'CVE-2026-1000',
        'title': 'Nested details CVE',
        'details': {'description': 'Remote code execution in widget.'},
    }

    normalized = normalize_cve_record_document(document)

    assert normalized['description'] == 'Remote code execution in widget.'
    assert normalized['summary'] == 'Remote code execution in widget.'


def test_promote_cve_display_fields_uses_nvd_descriptions_and_affected_vendor_product():
    from reviews.normalizer import promote_cve_display_fields

    document = {
        'code': '2026-42411',
        'description': 'CWE-288 Authentication Bypass Using an Alternate Path or Channel',
        'summary': 'CWE-288 Authentication Bypass Using an Alternate Path or Channel',
        'details': {
            'affected': [{'vendor': 'XServer', 'product': 'CloudSecure WP Security'}],
            'descriptions': [{
                'lang': 'en',
                'value': 'Unauthenticated Broken Authentication in CloudSecure WP Security <= 1.4.7 versions.',
            }],
        },
        'title': 'CVE-2026-42411',
    }

    promoted = promote_cve_display_fields(document)

    assert 'Broken Authentication' in promoted['description']
    assert promoted['vendor'] == 'XServer'
    assert promoted['product'] == 'CloudSecure WP Security'


def test_promote_cve_display_fields_uses_top_level_details_descriptions():
    from reviews.normalizer import promote_cve_display_fields

    document = {
        'code': '2026-9857',
        'title': 'CVE-2026-9857',
        'details': {
            'source_identifier': 'Wordfence',
            'descriptions': [{
                'lang': 'en',
                'value': 'The Invoice123 plugin for WordPress is vulnerable to authorization bypass.',
            }],
            'weaknesses': [{
                'descriptions': [{'lang': 'en', 'description': 'CWE-862 Missing Authorization'}],
            }],
        },
    }

    promoted = promote_cve_display_fields(document)

    assert 'authorization bypass' in promoted['description']
    assert promoted['summary'] == promoted['description']


def test_promote_cve_display_fields_uses_details_description_string():
    from reviews.normalizer import promote_cve_display_fields

    document = {
        'code': '2026-42588',
        'title': 'Apache ActiveMQ jolokia',
        'details': {
            'description': 'Apache ActiveMQ Jolokia remote code execution vulnerability.',
        },
    }

    promoted = promote_cve_display_fields(document)

    assert 'Jolokia' in promoted['description']
