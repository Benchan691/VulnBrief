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


def test_rank_results_keeps_tavily_pages_ahead_of_candidate_reference_seeds():
    database = FakeDatabase({
        'candidate_vulnerability_items': FakeCollection([{
            'run_id': 'run',
            'candidate_id': 'candidate',
            'cve_id': 'CVE-2026-50101',
            'vendor': 'Acme',
            'product': 'Widget',
            'summary': 'Acme Widget contains a vulnerability.',
            'references': [
                'https://acme.example/reference-one',
                'https://acme.example/reference-two',
            ],
        }]),
        'search_enrichment_results': FakeCollection([
            {
                'run_id': 'run',
                'candidate_id': 'candidate',
                'cve_id': 'CVE-2026-50101',
                'task_type': 'enrichment',
                'url': 'https://nvd.nist.gov/vuln/detail/CVE-2026-50101',
                'title': 'CVE-2026-50101 detail',
                'snippet': 'CVE-2026-50101 has a high CVSS score.',
                'page_content': 'CVE-2026-50101 has a high CVSS score.',
                'content_hash': 'nvd-detail',
            },
            {
                'run_id': 'run',
                'candidate_id': 'candidate',
                'cve_id': 'CVE-2026-50101',
                'task_type': 'enrichment',
                'url': 'https://research.example/CVE-2026-50101',
                'title': 'CVE-2026-50101 exploitation analysis',
                'snippet': 'CVE-2026-50101 can allow remote code execution.',
                'page_content': 'CVE-2026-50101 can allow remote code execution.',
                'content_hash': 'research',
            },
        ]),
    })

    ranked = rank_results_for_run(database, 'run', top_n=2)

    assert [item['source_type'] for item in ranked] == ['nvd_mitre', 'research_blog']
    assert all(item['source_type'] != 'candidate_reference' for item in ranked)


def test_rank_results_rejects_unrelated_page_with_task_stamped_cve_id():
    database = FakeDatabase({
        'candidate_vulnerability_items': FakeCollection([{
            'run_id': 'run',
            'candidate_id': 'candidate',
            'cve_id': 'CVE-2026-50102',
            'vendor': 'Acme',
            'product': 'Widget',
        }]),
        'search_enrichment_results': FakeCollection([{
            'run_id': 'run',
            'candidate_id': 'candidate',
            'cve_id': 'CVE-2026-50102',
            'task_type': 'enrichment',
            'url': 'https://unrelated.example/article',
            'title': 'Unrelated article',
            'snippet': 'This page discusses a different product.',
            'page_content': 'This page discusses a different product.',
            'content_hash': 'unrelated',
        }]),
    })

    assert rank_results_for_run(database, 'run', top_n=2) == []
