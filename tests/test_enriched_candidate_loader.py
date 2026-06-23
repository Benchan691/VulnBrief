from enriched_report.candidate_loader import (
    dedupe_candidates,
    load_candidates_from_inputs,
    normalize_candidate,
    query_cve_candidates,
)
from review_data import extract_document_cve_id


class FakeCursor:
    def __init__(self, documents):
        self.documents = documents

    def __iter__(self):
        return iter(self.documents)


class FakeCollection:
    def __init__(self, name, documents):
        self.name = name
        self.documents = documents
        self.aggregate_calls = []

    def aggregate(self, pipeline):
        self.aggregate_calls.append(pipeline)
        return FakeCursor(self.documents)


class FakeDatabase:
    def __init__(self, documents):
        self.collections = {'cve': FakeCollection('cve', documents)}

    def list_collections(self, filter=None):
        return [
            {'name': 'cve_review', 'options': {'viewOn': 'cve', 'pipeline': [{'$project': {'title': 1, 'code': 1}}]}},
            {'name': 'avd_review', 'options': {'viewOn': 'avd', 'pipeline': [{'$project': {'title': 1}}]}},
        ]

    def __getitem__(self, name):
        return self.collections[name]


def test_query_cve_candidates_uses_cve_only_and_keeps_most_complete_duplicate():
    database = FakeDatabase([
        {
            '_id': 'cve:thin',
            'code': 'CVE-2026-1000',
            'title': 'Thin duplicate',
            'details': {'cve': {}},
        },
        {
            '_id': 'cve:rich',
            'code': 'CVE-2026-1000',
            'title': 'Rich duplicate',
            'severity': 'High',
            'classification': {'best_vendor': 'Acme', 'best_product': 'Widget'},
            'details': {'cve': {'description': 'Detailed CVE record.', 'affected_products': [{'vendor': 'Acme'}]}},
            'source': {'detail_url': 'https://acme.example/CVE-2026-1000'},
        },
    ])

    candidates = query_cve_candidates(
        database,
        {'collections': ['avd_review'], 'time_window': 'all', 'include_unknown': True},
    )

    assert database['cve'].aggregate_calls
    assert len(candidates) == 1
    assert candidates[0]['cve_id'] == 'CVE-2026-1000'
    assert candidates[0]['title'] == 'Rich duplicate'
    assert candidates[0]['source_collection'] == 'cve'


def test_load_candidates_from_inputs_supports_cve_json_5_documents():
    from bson import ObjectId

    class FakeCveCollection:
        def find_one(self, query, projection=None):
            object_id = ObjectId('6a34241d4ab03604f78c2d5a')
            if query.get('_id') in {str(object_id), object_id}:
                return {
                    '_id': object_id,
                    'cveMetadata': {'cveId': 'CVE-2026-56012', 'datePublished': '2026-01-01'},
                    'containers': {
                        'cna': {
                            'title': 'WordPress plugin issue',
                            'descriptions': [{'value': 'SQL injection in plugin.'}],
                            'affected': [{'vendor': 'Acme', 'product': 'Plugin'}],
                            'metrics': [{'cvssV3_1': {'baseSeverity': 'HIGH'}}],
                        },
                    },
                }
            return None

    class FakeVulnerabilityDatabase:
        def __getitem__(self, name):
            assert name == 'cve'
            return FakeCveCollection()

    candidates = load_candidates_from_inputs(
        'run-1',
        FakeVulnerabilityDatabase(),
        {'candidate_vulnerability_items': type('C', (), {'delete_many': lambda *args, **kwargs: None, 'insert_many': lambda *args, **kwargs: None})()},
        [{'source_collection': 'cve', 'selection_id': '6a34241d4ab03604f78c2d5a'}],
    )

    assert len(candidates) == 1
    assert candidates[0]['cve_id'] == 'CVE-2026-56012'
    assert candidates[0]['severity'] == 'HIGH'
    assert candidates[0]['vendor'] == 'Acme'


def test_normalize_candidate_uses_nested_details_description_for_summary():
    candidate = normalize_candidate(
        {
            'code': 'CVE-2026-1000',
            'title': 'Nested details CVE',
            'details': {'cve': {'description': 'Detailed CVE record.'}},
        },
        'run-1',
        0,
    )

    assert candidate['summary'] == 'Detailed CVE record.'


def test_normalize_candidate_accepts_bare_code_and_cve_document_id():
    by_code = normalize_candidate({'code': '2026-12206', 'title': 'Plugin issue'}, 'run-1', 0)
    by_id = normalize_candidate({'_id': 'cve:2026-12206', 'title': 'Plugin issue'}, 'run-1', 1)
    by_title = normalize_candidate({'title': 'CVE-2026-12206'}, 'run-1', 2)

    assert by_code['cve_id'] == 'CVE-2026-12206'
    assert by_id['cve_id'] == 'CVE-2026-12206'
    assert by_title['cve_id'] == 'CVE-2026-12206'


def test_extract_document_cve_id_prefers_document_code_over_shared_cve_codes():
    document = {
        'code': '2026-12007',
        '_id': 'cve:2026-12007',
        'title': 'CVE-2026-12007',
        'cve_codes': ['2026-12000', '2026-12001', '2026-12007'],
    }

    assert extract_document_cve_id(document) == 'CVE-2026-12007'


def test_dedupe_keeps_distinct_cves_when_cve_codes_lists_overlap():
    from enriched_report.search_tasks import build_search_tasks

    shared_codes = ['2026-12000', '2026-12001', '2026-12002']
    docs = [
        {
            '_id': f'cve:2026-{12000 + index}',
            'code': f'2026-{12000 + index}',
            'title': f'CVE-2026-{12000 + index}',
            'cve_codes': shared_codes,
            'details': {'cve': {'descriptions': [{'value': f'Description {index}.'}]}},
        }
        for index in range(3)
    ]
    candidates = dedupe_candidates([
        normalize_candidate(document, 'run-1', index)
        for index, document in enumerate(docs)
    ])

    assert len(candidates) == 3
    assert len(build_search_tasks('run-1', candidates)) == 54


def test_dedupe_keeps_distinct_cves_with_shared_catalog_source_url():
    from enriched_report.search_tasks import build_search_tasks

    shared_url = 'https://github.com/CVEProject/cvelistV5'
    docs = [
        {
            '_id': f'cve:{code}',
            'code': code,
            'title': f'CVE-{code}',
            'cve_codes': [code],
            'source_url': shared_url,
            'details': {'cve': {'descriptions': [{'value': f'Description for {code}.'}]}},
        }
        for code in ['2024-0456', '2026-54231', '2026-53430']
    ]
    candidates = dedupe_candidates([
        normalize_candidate(document, 'run-1', index)
        for index, document in enumerate(docs)
    ])

    assert len(candidates) == 3
    assert len(build_search_tasks('run-1', candidates)) == 54
