from enriched_report.verifier import python_verify, replace_unsupported_claims


def test_python_verify_flags_unknown_urls_and_duplicate_rows():
    cards = [{
        'cve_id': 'CVE-2026-6000',
        'priority_score': 70,
        'patch_priority': 'High',
        'source_references': ['https://example.com/source'],
    }]
    report = {
        'vulnerability_detail_table': {
            'rows': [
                {
                    'cve_id': 'CVE-2026-6000',
                    'priority_score': 70,
                    'patch_priority': 'High',
                    'source_urls': ['https://unknown.example'],
                },
                {
                    'cve_id': 'CVE-2026-6000',
                    'priority_score': 70,
                    'patch_priority': 'High',
                    'source_urls': ['https://example.com/source'],
                },
            ],
        },
    }

    issues = python_verify(report, cards, {'total_vulnerabilities': 1}, [])

    assert any('Duplicate CVE row' in issue for issue in issues)
    assert any('Unknown source URL' in issue for issue in issues)


def test_replace_unsupported_claims_replaces_exact_text():
    report = {'executive_summary': {'summary': 'Unsupported claim appears here.'}}

    updated = replace_unsupported_claims(report, ['Unsupported claim'])

    assert updated['executive_summary']['summary'] == (
        'Not confirmed from available sources. appears here.'
    )

