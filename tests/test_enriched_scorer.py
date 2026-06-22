from enriched_report.scorer import score_cards_and_metrics


class FakeCollection:
    def __init__(self, documents=None):
        self.documents = list(documents or [])

    def find(self, query):
        return [doc for doc in self.documents if doc.get('run_id') == query.get('run_id')]

    def delete_many(self, query):
        self.documents = [doc for doc in self.documents if doc.get('run_id') != query.get('run_id')]

    def insert_one(self, document):
        self.documents.append(document)

    def replace_one(self, query, document):
        for index, existing in enumerate(self.documents):
            if existing.get('_id') == query.get('_id'):
                self.documents[index] = document
                return
        self.documents.append(document)


class FakeDatabase(dict):
    def __getitem__(self, name):
        if name not in self:
            self[name] = FakeCollection()
        return dict.__getitem__(self, name)


def test_score_cards_and_metrics_assigns_priority_and_aggregates():
    database = FakeDatabase({
        'vulnerability_cards': FakeCollection([{
            '_id': 'card-1',
            'run_id': 'run',
            'candidate_id': 'candidate',
            'cve_id': 'CVE-2026-5000',
            'title': 'Critical issue',
            'severity': 'Critical',
            'what_happened': 'Remote code execution.',
            'why_matters': 'Internet-facing remote code execution.',
            'how_to_respond': 'Patch now.',
            'priority_score': 0,
            'patch_priority': 'Unscored',
            'missing_fields': [],
            'conflicts': [],
            'source_references': ['https://example.com'],
            'cisa_kev': True,
            'epss': 0.9,
            'exploit_status': 'exploited in the wild',
        }]),
    })

    cards, metrics = score_cards_and_metrics(database, 'run')

    assert cards[0]['patch_priority'] == 'Critical'
    assert cards[0]['priority_score'] >= 80
    assert metrics['severity_counts']['Critical'] == 1
    assert metrics['top_remediation_items'][0]['cve_id'] == 'CVE-2026-5000'

