from review_data import resolve_vulnerability_document


class FakeCollection:
    def __init__(self, documents):
        self.documents = documents

    def find_one(self, query, projection=None):
        for document in self.documents:
            if all(document.get(key) == value for key, value in query.items()):
                if projection is None:
                    return dict(document)
                return {
                    key: document[key]
                    for key in projection
                    if key in document
                }
        return None


class FakeDatabase:
    def __init__(self, collections):
        self.collections = collections

    def __getitem__(self, name):
        return self.collections[name]


def test_resolve_vulnerability_document_by_prefixed_id():
    database = FakeDatabase({
        'avd': FakeCollection([
            {'_id': 'avd:2026-42588', 'code': '2026-42588', 'details': {'avd': {}}},
        ]),
    })
    document = resolve_vulnerability_document(database, 'avd', 'avd:2026-42588')
    assert document['_id'] == 'avd:2026-42588'


def test_resolve_vulnerability_document_by_bare_code():
    database = FakeDatabase({
        'avd': FakeCollection([
            {'_id': 'avd:2026-42588', 'code': '2026-42588', 'details': {'avd': {}}},
        ]),
    })
    document = resolve_vulnerability_document(database, 'avd', '2026-42588')
    assert document['_id'] == 'avd:2026-42588'


def test_resolve_vulnerability_document_by_cve_code():
    database = FakeDatabase({
        'cnnvd': FakeCollection([
            {
                '_id': 'cnnvd:202606-1876',
                'code': '202606-1876',
                'cve_code': '2026-11475',
                'details': {'cnnvd': {}},
            },
        ]),
    })
    document = resolve_vulnerability_document(database, 'cnnvd', '2026-11475')
    assert document['_id'] == 'cnnvd:202606-1876'


def test_resolve_vulnerability_document_returns_none_when_missing():
    database = FakeDatabase({'avd': FakeCollection([])})
    assert resolve_vulnerability_document(database, 'avd', 'avd:missing') is None
