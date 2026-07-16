from reports.enriched.card_merger import merge_vulnerability_cards


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


def test_merge_vulnerability_cards_prefers_high_confidence_and_records_conflicts():
    database = FakeDatabase({
        'candidate_vulnerability_items': FakeCollection([{
            'run_id': 'run',
            'candidate_id': 'candidate',
            'cve_id': 'CVE-2026-4000',
            'vendor': 'Acme',
            'product': 'Widget',
            'title': 'Acme Widget issue',
            'severity': 'High',
            'summary': 'Candidate summary.',
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2026-4000'],
        }]),
        'source_evidence_cards': FakeCollection([
            {
                'run_id': 'run',
                'candidate_id': 'candidate',
                'cve_id': 'CVE-2026-4000',
                'task_type': 'how_to_respond',
                'source_url': 'https://acme.example/advisory',
                'confidence': 'high',
                'how_to_respond': 'Upgrade to 2.0.',
                'fixed_versions': ['2.0'],
                'references': ['https://acme.example/advisory'],
            },
            {
                'run_id': 'run',
                'candidate_id': 'candidate',
                'cve_id': 'CVE-2026-4000',
                'task_type': 'how_to_respond',
                'source_url': 'https://blog.example',
                'confidence': 'medium',
                'how_to_respond': 'Upgrade to 2.1.',
                'fixed_versions': ['2.1'],
                'references': ['https://blog.example'],
            },
        ]),
    })

    cards = merge_vulnerability_cards(database, 'run')

    assert cards[0]['how_to_respond'] == 'Upgrade to 2.0.'
    assert 'Sources report different fixed versions.' in cards[0]['conflicts']
    assert 'https://acme.example/advisory' in cards[0]['source_references']

