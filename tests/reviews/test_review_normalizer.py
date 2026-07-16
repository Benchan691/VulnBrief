from reviews.normalizer import extract_document_cve_id, normalize_cve_id, normalize_cve_record_document


def test_normalize_cve_id_accepts_common_storage_formats():
    assert normalize_cve_id('2026-12206') == 'CVE-2026-12206'
    assert normalize_cve_id('CVE-2026-12206') == 'CVE-2026-12206'
    assert normalize_cve_id('cve:2026-12206') == 'CVE-2026-12206'
    assert normalize_cve_id(['2026-12206', 'CVE-2026-9999']) == 'CVE-2026-12206'


def test_extract_document_cve_id_prefers_code_before_cve_codes():
    assert extract_document_cve_id({
        'code': '2026-12007',
        'cve_codes': ['2026-12000', '2026-12001'],
    }) == 'CVE-2026-12007'


def test_normalize_cve_record_document_maps_cna_fields():
    document = {
        '_id': '6a3424134ab03604f78c2d10',
        'cveMetadata': {
            'cveId': 'CVE-2025-32392',
            'datePublished': '2026-06-18T16:08:18.904Z',
        },
        'containers': {
            'cna': {
                'title': 'AutoGPT has a DoS vulnerability in LoopVideoBlock',
                'descriptions': [
                    {'lang': 'en', 'value': 'AutoGPT workflow automation platform vulnerability.'},
                ],
                'metrics': [
                    {'cvssV4_0': {'baseSeverity': 'HIGH', 'baseScore': 8.7}},
                ],
                'affected': [
                    {'vendor': 'Significant-Gravitas', 'product': 'AutoGPT'},
                ],
                'references': [
                    {'url': 'https://github.com/example/advisories/GHSA-1234'},
                ],
            },
        },
    }

    normalized = normalize_cve_record_document(document)

    assert normalized['code'] == 'CVE-2025-32392'
    assert normalized['cve'] == 'CVE-2025-32392'
    assert normalized['title'] == 'CVE-2025-32392'
    assert 'AutoGPT' in normalized['advisory_title']
    assert 'workflow automation' in normalized['description']
    assert normalized['severity'] == 'HIGH'
    assert normalized['impacts'] == 'HIGH'
    assert normalized['vendor'] == 'Significant-Gravitas'
    assert normalized['product'] == 'AutoGPT'
    assert 'classification' not in normalized
    assert normalized['affected'] == ['Significant-Gravitas AutoGPT']
    assert normalized['related_link'] == ['https://github.com/example/advisories/GHSA-1234']


def test_normalize_cve_record_document_uses_cna_vendor_product():
    document = {
        '_id': '1',
        'cveMetadata': {'cveId': 'CVE-2026-0001'},
        'containers': {
            'cna': {
                'affected': [{'vendor': 'Acme', 'product': 'Widget'}],
            },
        },
    }

    normalized = normalize_cve_record_document(document)

    assert normalized['title'] == 'CVE-2026-0001'
    assert 'classification' not in normalized
    assert normalized.get('vendor') == 'Acme'
    assert normalized.get('product') == 'Widget'


def test_normalize_cve_record_document_promotes_nested_details_description():
    document = {
        '_id': '2',
        'code': 'CVE-2026-1000',
        'title': 'Nested details CVE',
        'details': {'cve': {'description': 'Remote code execution in widget.'}},
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
            'cve': {
                'affected': [{'vendor': 'XServer', 'product': 'CloudSecure WP Security'}],
                'descriptions': [{
                    'lang': 'en',
                    'value': 'Unauthenticated Broken Authentication in CloudSecure WP Security <= 1.4.7 versions.',
                }],
            },
        },
        'title': 'CVE-2026-42411',
    }

    promoted = promote_cve_display_fields(document)

    assert 'Broken Authentication' in promoted['description']
    assert promoted['vendor'] == 'XServer'
    assert promoted['product'] == 'CloudSecure WP Security'
