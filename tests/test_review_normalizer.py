from review_data import normalize_cve_record_document


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
    assert normalized['classification']['vendor'] == 'Significant-Gravitas'
    assert normalized['affected'] == ['Significant-Gravitas AutoGPT']
    assert normalized['related_link'] == ['https://github.com/example/advisories/GHSA-1234']


def test_normalize_cve_record_document_unclassified_shows_dash_fields():
    document = {
        '_id': '1',
        'cveMetadata': {'cveId': 'CVE-2026-0001'},
        'classification': {'status': 'unclassified'},
        'containers': {
            'cna': {
                'affected': [{'vendor': 'Ignored', 'product': 'Ignored'}],
            },
        },
    }

    normalized = normalize_cve_record_document(document)

    assert normalized['title'] == 'CVE-2026-0001'
    assert normalized['classification']['status'] == 'unclassified'
    assert 'vendor' not in normalized or not normalized.get('vendor')
