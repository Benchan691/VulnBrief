import re
from urllib.parse import parse_qs, urlparse


_CATALOG_HOSTS = frozenset({
    'nvd.nist.gov',
    'www.nvd.nist.gov',
    'cve.org',
    'www.cve.org',
    'cve.mitre.org',
    'www.cve.mitre.org',
    'github.com',
    'www.github.com',
    'opencve.io',
    'www.opencve.io',
})


def _host(url):
    host = (urlparse(url or '').hostname or '').lower()
    if host.endswith('.opencve.io') or host == 'opencve.io':
        return 'opencve.io'
    return host


def _path(url):
    path = (urlparse(url or '').path or '/').rstrip('/')
    return path or '/'


def _cve_in_url(url, cve_id):
    if not url or not cve_id:
        return False
    haystack = url.upper()
    cve_upper = cve_id.upper()
    if cve_upper in haystack:
        return True
    bare = cve_upper.removeprefix('CVE-')
    return bare in haystack


def is_cve_specific_catalog_url(url, cve_id=None):
    host = _host(url)
    path = _path(url).lower()
    if host in {'nvd.nist.gov', 'www.nvd.nist.gov'}:
        if '/vuln/detail/' in path:
            return not cve_id or _cve_in_url(url, cve_id)
        return False
    if host in {'cve.org', 'www.cve.org'}:
        if '/cverecord' in path:
            query = parse_qs(urlparse(url).query)
            record_id = (query.get('id') or [''])[0]
            return not cve_id or record_id.upper() == cve_id.upper()
        return False
    if host in {'cve.mitre.org', 'www.cve.mitre.org'}:
        return _cve_in_url(url, cve_id) if cve_id else bool(re.search(r'CVE-\d{4}-\d+', url, re.I))
    if host in {'github.com', 'www.github.com'} and 'cvelist' in path:
        return False
    if host in {'opencve.io', 'www.opencve.io'}:
        return _cve_in_url(url, cve_id) if cve_id else path not in {'/', ''}
    return True


def is_generic_reference_url(url, cve_id=None):
    text = (url or '').strip()
    if not text:
        return True
    host = _host(text)
    if host not in _CATALOG_HOSTS:
        return False
    if _cve_in_url(text, cve_id):
        return False
    return not is_cve_specific_catalog_url(text, cve_id)


def is_low_value_reference_url(url, cve_id=None):
    text = (url or '').strip()
    if not text:
        return True
    host = _host(text)
    if host.endswith('wikipedia.org') or host.endswith('wikidata.org'):
        return not _cve_in_url(text, cve_id)
    return False


def canonical_catalog_reference_url(url, cve_id=None):
    text = (url or '').strip()
    if not text:
        return ''
    if not is_generic_reference_url(text, cve_id):
        return text
    if not cve_id:
        return ''
    host = _host(text)
    if host in {'nvd.nist.gov', 'www.nvd.nist.gov'}:
        return f'https://nvd.nist.gov/vuln/detail/{cve_id.upper()}'
    if host in {'cve.org', 'www.cve.org'}:
        return f'https://www.cve.org/CVERecord?id={cve_id.upper()}'
    return ''


def _reference_identity_key(url):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    for param in ('id', 'vul', 'vuln', 'advisory', 'cve', 'docid'):
        values = query.get(param) or []
        if values and str(values[0]).strip():
            return ('query', param.lower(), str(values[0]).strip().lower())
    jvn_match = re.search(r'/(JVN\d+)', parsed.path, re.I)
    if jvn_match:
        return ('jvn', jvn_match.group(1).upper())
    return ('url', parsed.netloc.lower(), parsed.path.rstrip('/').lower())


def _reference_priority(url, vendor_domain=''):
    host = (urlparse(url).hostname or '').lower()
    score = 0
    vendor = (vendor_domain or '').lower().lstrip('www.')
    if vendor and (host == vendor or host.endswith(f'.{vendor}')):
        score += 100
    if host.startswith('www.'):
        score += 5
    if re.match(r'^(jp|cn|kr|de|fr|uk)\.', host):
        score -= 10
    if 'jvn.jp' in host:
        score += 80
    if host in {'nvd.nist.gov', 'www.nvd.nist.gov', 'cve.org', 'www.cve.org'}:
        score += 60
    return score


def is_http_url(url):
    text = (url or '').strip()
    if not text or ' ' in text:
        return False
    parsed = urlparse(text)
    return parsed.scheme in {'http', 'https'} and bool(parsed.netloc)


def filter_reference_urls(urls, cve_id=None, vendor_domain=''):
    best_by_key = {}
    for url in urls or []:
        text = str(url or '').strip()
        if not text or not is_http_url(text):
            continue
        canonical = canonical_catalog_reference_url(text, cve_id)
        if not canonical or not is_http_url(canonical) or is_low_value_reference_url(canonical, cve_id):
            continue
        key = _reference_identity_key(canonical)
        score = _reference_priority(canonical, vendor_domain)
        current = best_by_key.get(key)
        if current is None or score > current[0]:
            best_by_key[key] = (score, canonical)
    ordered = sorted(best_by_key.values(), key=lambda item: item[0], reverse=True)
    return [url for _, url in ordered]
