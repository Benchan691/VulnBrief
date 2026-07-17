from reports.enriched.reference_urls import (
    canonical_catalog_reference_url,
    filter_reference_urls,
    is_cve_specific_catalog_url,
    is_generic_reference_url,
    is_low_value_reference_url,
)


def test_is_generic_reference_url_flags_catalog_homepages():
    cve_id = 'CVE-2026-14439'
    assert is_generic_reference_url('https://nvd.nist.gov/', cve_id)
    assert is_generic_reference_url('https://nvd.nist.gov/vuln', cve_id)
    assert is_generic_reference_url('https://www.cve.org/', cve_id)
    assert is_generic_reference_url('https://www.cve.org/About/Overview', cve_id)
    assert is_generic_reference_url('https://github.com/CVEProject/cvelistV5', cve_id)
    assert is_generic_reference_url('https://app.opencve.io/', cve_id)


def test_is_generic_reference_url_keeps_cve_specific_pages():
    cve_id = 'CVE-2026-14439'
    nvd = 'https://nvd.nist.gov/vuln/detail/CVE-2026-14439'
    cve_record = 'https://www.cve.org/CVERecord?id=CVE-2026-14439'
    vendor = 'https://www.altium.com/platform/security-compliance/security-advisories'

    assert not is_generic_reference_url(nvd, cve_id)
    assert not is_generic_reference_url(cve_record, cve_id)
    assert not is_generic_reference_url(vendor, cve_id)
    assert is_cve_specific_catalog_url(nvd, cve_id)
    assert is_cve_specific_catalog_url(cve_record, cve_id)


def test_filter_reference_urls_drops_generic_and_keeps_specific():
    cve_id = 'CVE-2026-4000'
    refs = [
        'https://nvd.nist.gov/',
        'https://nvd.nist.gov/vuln',
        'https://nvd.nist.gov/vuln/detail/CVE-2026-4000',
        'https://www.cve.org/About/Overview',
        'https://www.cve.org/CVERecord?id=CVE-2026-4000',
        'https://acme.example/advisory',
    ]
    filtered = filter_reference_urls(refs, cve_id)
    assert set(filtered) == {
        'https://nvd.nist.gov/vuln/detail/CVE-2026-4000',
        'https://www.cve.org/CVERecord?id=CVE-2026-4000',
        'https://acme.example/advisory',
    }


def test_filter_reference_urls_drops_wikipedia_and_duplicate_vendor_advisories():
    cve_id = 'CVE-2026-50100'
    refs = [
        'https://www.ricoh.com/products/security/vulnerabilities/vul?id=ricoh-2025-000002',
        'https://jp.ricoh.com/security/products/vulnerabilities/vul?id=ricoh-2025-000002',
        'https://www.konicaminolta.jp/business/support/important/260615_01_01.html',
        'https://jvn.jp/en/jp/JVN55319858/',
        'https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures',
        'https://nvd.nist.gov/vuln/detail/CVE-2026-50100',
        'https://www.cve.org/CVERecord?id=CVE-2026-50100',
    ]
    filtered = filter_reference_urls(refs, cve_id, vendor_domain='ricoh.com')
    assert 'https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures' not in filtered
    assert 'https://jp.ricoh.com/security/products/vulnerabilities/vul?id=ricoh-2025-000002' not in filtered
    assert 'https://www.ricoh.com/products/security/vulnerabilities/vul?id=ricoh-2025-000002' in filtered
    assert 'https://jvn.jp/en/jp/JVN55319858/' in filtered
    assert 'https://www.konicaminolta.jp/business/support/important/260615_01_01.html' in filtered
    assert 'https://nvd.nist.gov/vuln/detail/CVE-2026-50100' in filtered
    assert 'https://www.cve.org/CVERecord?id=CVE-2026-50100' in filtered


def test_filter_reference_urls_drops_prose_and_non_urls():
    cve_id = 'CVE-2026-50100'
    refs = [
        'The official reference for this entry is the CVE database website at https://www.cve.org/.',
        'https://nvd.nist.gov/vuln/detail/CVE-2026-50100',
        'not a url',
    ]
    filtered = filter_reference_urls(refs, cve_id)
    assert filtered == ['https://nvd.nist.gov/vuln/detail/CVE-2026-50100']


def test_is_low_value_reference_url_flags_wikipedia_without_cve():
    cve_id = 'CVE-2026-50100'
    assert is_low_value_reference_url(
        'https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures',
        cve_id,
    )
    assert not is_low_value_reference_url(
        'https://en.wikipedia.org/wiki/CVE-2026-50100',
        cve_id,
    )


def test_canonical_catalog_reference_url_rewrites_generic_nvd_and_cve_org():
    cve_id = 'CVE-2026-14439'
    assert canonical_catalog_reference_url('https://nvd.nist.gov/vuln', cve_id) == (
        'https://nvd.nist.gov/vuln/detail/CVE-2026-14439'
    )
    assert canonical_catalog_reference_url('https://www.cve.org/', cve_id) == (
        'https://www.cve.org/CVERecord?id=CVE-2026-14439'
    )
    assert canonical_catalog_reference_url('https://github.com/CVEProject/cvelistV5', cve_id) == ''

