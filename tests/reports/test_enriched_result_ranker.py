from reports.enriched.result_ranker import rank_results_for_run


class FakeCollection:
    def __init__(self, documents=None):
        self.documents = list(documents or [])

    def find(self, query):
        return [doc for doc in self.documents if doc.get('run_id') == query.get('run_id')]

    def delete_many(self, query):
        self.documents = [doc for doc in self.documents if doc.get('run_id') != query.get('run_id')]

    def insert_many(self, documents):
        self.documents.extend(documents)


class FakeDatabase(dict):
    def __getitem__(self, name):
        if name not in self:
            self[name] = FakeCollection()
        return dict.__getitem__(self, name)


def test_rank_results_dedupes_and_prioritizes_vendor_sources():
    database = FakeDatabase({
        'candidate_vulnerability_items': FakeCollection([{
            'run_id': 'run',
            'candidate_id': 'candidate',
            'cve_id': 'CVE-2026-3000',
            'vendor': 'Acme',
            'product': 'Widget',
            'vendor_official_domain': 'acme.example',
        }]),
        'search_enrichment_results': FakeCollection([
            {
                'run_id': 'run',
                'candidate_id': 'candidate',
                'cve_id': 'CVE-2026-3000',
                'task_type': 'enrichment',
                'url': 'https://blog.example/post',
                'title': 'CVE-2026-3000 Acme Widget analysis',
                'snippet': 'CVE-2026-3000 affects Acme Widget.',
                'page_content': 'CVE-2026-3000 affects Acme Widget.',
                'content_hash': 'blog',
            },
            {
                'run_id': 'run',
                'candidate_id': 'candidate',
                'cve_id': 'CVE-2026-3000',
                'task_type': 'enrichment',
                'url': 'https://acme.example/advisory',
                'title': 'Acme advisory CVE-2026-3000',
                'snippet': 'CVE-2026-3000 affects Acme Widget.',
                'page_content': 'CVE-2026-3000 affects Acme Widget.',
                'content_hash': 'vendor',
            },
            {
                'run_id': 'run',
                'candidate_id': 'candidate',
                'cve_id': 'CVE-2026-3000',
                'task_type': 'enrichment',
                'url': 'https://acme.example/advisory/',
                'title': 'Duplicate URL',
                'snippet': 'CVE-2026-3000 affects Acme Widget.',
                'page_content': 'CVE-2026-3000 affects Acme Widget.',
                'content_hash': 'vendor-duplicate',
            },
            {
                'run_id': 'run',
                'candidate_id': 'candidate',
                'cve_id': 'CVE-2026-3000',
                'task_type': 'enrichment',
                'url': 'https://irrelevant.example',
                'title': 'Unrelated',
                'snippet': 'No matching identifier.',
                'page_content': 'No matching identifier.',
                'content_hash': 'irrelevant',
            },
        ]),
    })

    ranked = rank_results_for_run(database, 'run', top_n=2)

    assert [item['url'] for item in ranked] == [
        'https://acme.example/advisory',
        'https://blog.example/post',
    ]
    assert database['filtered_enrichment_results'].documents == ranked


def test_rank_results_excludes_generic_catalog_and_seeds_candidate_refs():
    database = FakeDatabase({
        'candidate_vulnerability_items': FakeCollection([{
            'run_id': 'run',
            'candidate_id': 'candidate',
            'cve_id': 'CVE-2026-50100',
            'vendor': 'Ricoh Company, Ltd.',
            'product': 'Multiple printer drivers',
            'title': 'Ricoh printer driver privilege escalation',
            'summary': (
                'Multiple printer drivers provided by Ricoh Company, Ltd. contain a '
                'privilege escalation vulnerability.'
            ),
            'references': [
                'https://www.ricoh.com/products/security/vulnerabilities/vul?id=ricoh-2025-000002',
                'https://jvn.jp/en/jp/JVN55319858/',
            ],
        }]),
        'search_enrichment_results': FakeCollection([
            {
                'run_id': 'run',
                'candidate_id': 'candidate',
                'cve_id': 'CVE-2026-50100',
                'task_type': 'enrichment',
                'url': 'https://nvd.nist.gov/vuln',
                'title': 'NVD - Vulnerabilities',
                'snippet': 'CVE defines a vulnerability as a weakness',
                'page_content': 'CVE defines a vulnerability as a weakness',
                'content_hash': 'nvd-home',
            },
            {
                'run_id': 'run',
                'candidate_id': 'candidate',
                'cve_id': 'CVE-2026-50100',
                'task_type': 'enrichment',
                'url': 'https://app.opencve.io/',
                'title': 'OpenCVE',
                'snippet': 'OpenCVE dashboard',
                'page_content': 'OpenCVE dashboard',
                'content_hash': 'opencve-home',
            },
        ]),
    })

    ranked = rank_results_for_run(database, 'run', top_n=4)
    ranked_urls = [item['url'] for item in ranked]

    assert 'https://nvd.nist.gov/vuln' not in ranked_urls
    assert 'https://app.opencve.io/' not in ranked_urls
    assert 'https://www.ricoh.com/products/security/vulnerabilities/vul?id=ricoh-2025-000002' in ranked_urls
    assert 'https://jvn.jp/en/jp/JVN55319858/' in ranked_urls

