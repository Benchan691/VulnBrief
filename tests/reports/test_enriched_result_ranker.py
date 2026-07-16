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
                'task_type': 'what_happened',
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
                'task_type': 'what_happened',
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
                'task_type': 'what_happened',
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
                'task_type': 'what_happened',
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

