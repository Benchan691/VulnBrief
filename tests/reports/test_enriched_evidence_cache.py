import json

import pytest

from app import app
from reports.enriched.evidence_cache import (
    evidence_cache_key,
    lookup_cached_payload,
    purge_evidence_cache,
    store_cached_payload,
)
from reports.enriched.evidence_extractor import (
    _normalize_card,
    _parse_json_response,
    _prompt,
    _unwrap_card_payload,
    extract_evidence_cards,
)
from reports.enriched.llama_client import EnrichedLLMError


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    return app.test_client()


class FakeCacheCollection:
    def __init__(self):
        self.docs = {}

    def find_one(self, query):
        return self.docs.get(query.get('cache_key'))

    def update_one(self, query, update, upsert=False):
        key = query.get('cache_key')
        existing = self.docs.get(key, {})
        if upsert and key not in self.docs:
            existing = dict(update.get('$setOnInsert') or {})
        existing.update(update.get('$set') or {})
        if '$inc' in update:
            for field, amount in update['$inc'].items():
                existing[field] = existing.get(field, 0) + amount
        self.docs[key] = existing
        return None

    def delete_many(self, query):
        if query:
            return type('Result', (), {'deleted_count': 0})()
        count = len(self.docs)
        self.docs = {}
        return type('Result', (), {'deleted_count': count})()


class FakeCollection:
    def __init__(self, documents):
        self.documents = list(documents)

    def find(self, query):
        run_id = query.get('run_id')
        return [doc for doc in self.documents if doc.get('run_id') == run_id]

    def delete_many(self, query):
        run_id = query.get('run_id')
        self.documents = [doc for doc in self.documents if doc.get('run_id') != run_id]
        return None

    def insert_many(self, documents):
        self.documents.extend(documents)


class FakeDatabase:
    def __init__(self, collections):
        self.collections = collections

    def __getitem__(self, name):
        return self.collections[name]


class FakeLlamaClient:
    evidence_max_output_tokens = 1024
    calls = 0

    def complete_text(self, *args, **kwargs):
        type(self).calls += 1
        return json.dumps({
            'what_happened': 'Fresh extraction.',
            'why_matters': 'Risk.',
            'how_to_respond': 'Upgrade.',
            'confidence': 'medium',
        }), {}


def test_evidence_cache_key_is_stable_for_same_source():
    key_a = evidence_cache_key(
        'CVE-2026-1000',
        'enrichment',
        'https://example.com/advisory/',
        'abc123',
        '1',
    )
    key_b = evidence_cache_key(
        'cve-2026-1000',
        'enrichment',
        'https://example.com/advisory',
        'abc123',
        '1',
    )
    assert key_a == key_b


def test_store_and_lookup_cached_payload():
    database = FakeDatabase({'source_evidence_cache': FakeCacheCollection()})
    result = {
        'cve_id': 'CVE-2026-1000',
        'task_type': 'enrichment',
        'url': 'https://example.com/advisory',
        'content_hash': 'hash-1',
    }
    card = _normalize_card({
        'confidence': 'high',
        'what_happened': 'Cached fact.',
        'why_matters': 'Risk.',
        'how_to_respond': 'Upgrade.',
        'references': ['https://example.com/advisory'],
    }, {
        **result,
        'run_id': 'run-a',
        'candidate_id': 'candidate-a',
    })

    store_cached_payload(database, result, card, '1')
    payload = lookup_cached_payload(database, result, '1')

    assert payload['what_happened'] == 'Cached fact.'
    assert database['source_evidence_cache'].docs[
        evidence_cache_key('CVE-2026-1000', 'enrichment', result['url'], 'hash-1', '1')
    ]['hit_count'] == 1


def test_purge_evidence_cache_deletes_all_entries():
    database = FakeDatabase({'source_evidence_cache': FakeCacheCollection()})
    result = {
        'cve_id': 'CVE-2026-1000',
        'task_type': 'enrichment',
        'url': 'https://example.com/advisory',
        'content_hash': 'hash-1',
    }
    card = _normalize_card({
        'confidence': 'high',
        'what_happened': 'Cached fact.',
        'why_matters': 'Risk.',
        'how_to_respond': 'Upgrade.',
        'references': ['https://example.com/advisory'],
    }, {
        **result,
        'run_id': 'run-a',
        'candidate_id': 'candidate-a',
    })
    store_cached_payload(database, result, card, '1')
    assert len(database['source_evidence_cache'].docs) == 1

    deleted_count = purge_evidence_cache(database)

    assert deleted_count == 1
    assert database['source_evidence_cache'].docs == {}


def test_extract_evidence_cards_reuses_cache_on_second_run():
    FakeLlamaClient.calls = 0
    cache = FakeCacheCollection()
    evidence = FakeCollection([])
    database = FakeDatabase({
        'source_evidence_cache': cache,
        'source_evidence_cards': evidence,
        'candidate_vulnerability_items': FakeCollection([{
            'run_id': 'run-1',
            'candidate_id': 'candidate-1',
            'cve_id': 'CVE-2026-1000',
            'vendor': 'Acme',
            'product': 'Widget',
            'title': 'Acme Widget',
        }]),
        'filtered_enrichment_results': FakeCollection([{
            'run_id': 'run-1',
            'candidate_id': 'candidate-1',
            'cve_id': 'CVE-2026-1000',
            'task_type': 'enrichment',
            'url': 'https://example.com/advisory',
            'content_hash': 'hash-1',
            'page_content': 'Advisory text.',
        }]),
    })
    config = {
        'ENRICHED_LLM_PAGE_CHARS': 12000,
        'ENRICHED_EVIDENCE_CACHE_ENABLED': True,
        'ENRICHED_EVIDENCE_CACHE_VERSION': '3',
    }

    first = extract_evidence_cards(database, 'run-1', config, FakeLlamaClient())
    assert len(first) == 1
    assert first[0]['what_happened'] == 'Fresh extraction.'
    assert FakeLlamaClient.calls == 1

    database.collections['source_evidence_cards'] = FakeCollection([])
    database.collections['filtered_enrichment_results'] = FakeCollection([{
        'run_id': 'run-2',
        'candidate_id': 'candidate-2',
        'cve_id': 'CVE-2026-1000',
        'task_type': 'enrichment',
        'url': 'https://example.com/advisory',
        'content_hash': 'hash-1',
        'page_content': 'Advisory text.',
    }])
    database.collections['candidate_vulnerability_items'] = FakeCollection([{
        'run_id': 'run-2',
        'candidate_id': 'candidate-2',
        'cve_id': 'CVE-2026-1000',
        'vendor': 'Acme',
        'product': 'Widget',
        'title': 'Acme Widget',
    }])

    second = extract_evidence_cards(database, 'run-2', config, FakeLlamaClient())
    assert len(second) == 1
    assert second[0]['what_happened'] == 'Fresh extraction.'
    assert second[0]['run_id'] == 'run-2'
    assert second[0]['candidate_id'] == 'candidate-2'
    assert FakeLlamaClient.calls == 1


def test_prompt_omits_snippet_when_page_content_present():
    result = {
        'run_id': 'r1',
        'candidate_id': 'c1',
        'cve_id': 'CVE-2026-46847',
        'task_type': 'enrichment',
        'url': 'https://example.com',
        'title': 'Advisory',
        'snippet': 'S' * 3000,
        'page_content': 'P' * 6000,
    }
    candidate = {'cve_id': 'CVE-2026-46847', 'vendor': 'Acme', 'product': 'W', 'title': 'T'}
    system, user_json = _prompt(result, candidate, 4500)
    user = json.loads(user_json)
    assert 'valid JSON' in system
    assert 'what_happened' in system
    assert 'example_response' not in user
    assert len(user['source']['page_content']) == 4500
    assert 'snippet' not in user['source']


def test_parse_json_response_returns_all_fields():
    parsed = _parse_json_response(json.dumps({
        'what_happened': 'Confirmed issue.',
        'why_matters': 'High risk.',
        'how_to_respond': 'Patch now.',
        'confidence': 'high',
    }))
    assert parsed['what_happened'] == 'Confirmed issue.'
    assert parsed['why_matters'] == 'High risk.'
    assert parsed['how_to_respond'] == 'Patch now.'
    assert parsed['confidence'] == 'high'


def test_parse_json_response_treats_invalid_json_as_empty():
    assert _parse_json_response('not json') == {}
    assert _parse_json_response('') == {}


def test_unwrap_card_payload_reads_nested_required_output():
    raw = {
        'required_output': {
            'what_happened': 'Confirmed issue.',
            'confidence': 'high',
        },
    }
    assert _unwrap_card_payload(raw)['what_happened'] == 'Confirmed issue.'


def test_normalize_card_coerces_not_confirmed_cisa_kev_to_null():
    result = {
        'run_id': 'run-1',
        'candidate_id': 'candidate-1',
        'cve_id': 'CVE-2026-1000',
        'task_type': 'enrichment',
        'url': 'https://example.com/advisory',
    }
    card = _normalize_card({'cisa_kev': 'Not confirmed', 'confidence': 'low'}, result)
    assert card['cisa_kev'] is None


def test_normalize_card_preserves_boolean_cisa_kev():
    result = {
        'run_id': 'run-1',
        'candidate_id': 'candidate-1',
        'cve_id': 'CVE-2026-1000',
        'task_type': 'enrichment',
        'url': 'https://example.com/advisory',
    }
    card = _normalize_card({'cisa_kev': True, 'confidence': 'high'}, result)
    assert card['cisa_kev'] is True


def test_extract_evidence_cards_continues_after_llm_failure():
    FakeLlamaClient.calls = 0
    FakeLlamaClient.fail_once = True

    class FailingLlamaClient(FakeLlamaClient):
        def complete_text(self, *args, **kwargs):
            type(self).calls += 1
            if getattr(type(self), 'fail_once', False):
                type(self).fail_once = False
                raise EnrichedLLMError('llama-server returned an empty response.')
            return json.dumps({
                'what_happened': None,
                'why_matters': 'Recovered.',
                'how_to_respond': None,
                'confidence': 'medium',
            }), {}

    database = FakeDatabase({
        'source_evidence_cache': FakeCacheCollection(),
        'source_evidence_cards': FakeCollection([]),
        'candidate_vulnerability_items': FakeCollection([{
            'run_id': 'run-1',
            'candidate_id': 'candidate-1',
            'cve_id': 'CVE-2026-1000',
            'vendor': 'Acme',
            'product': 'Widget',
            'title': 'Acme Widget',
        }]),
        'filtered_enrichment_results': FakeCollection([
            {
                'run_id': 'run-1',
                'candidate_id': 'candidate-1',
                'cve_id': 'CVE-2026-1000',
                'task_type': 'enrichment',
                'url': 'https://example.com/one',
                'content_hash': 'hash-1',
                'page_content': 'Advisory one.',
            },
            {
                'run_id': 'run-1',
                'candidate_id': 'candidate-1',
                'cve_id': 'CVE-2026-1000',
                'task_type': 'enrichment',
                'url': 'https://example.com/two',
                'content_hash': 'hash-2',
                'page_content': 'Advisory two.',
            },
        ]),
    })
    config = {
        'ENRICHED_LLM_PAGE_CHARS': 12000,
        'ENRICHED_EVIDENCE_CACHE_ENABLED': False,
    }

    cards = extract_evidence_cards(database, 'run-1', config, FailingLlamaClient())
    assert len(cards) == 2
    assert cards[0]['what_happened'] is None
    assert cards[1]['why_matters'] == 'Recovered.'
    assert FailingLlamaClient.calls == 2


def test_purge_evidence_cache_route(client, monkeypatch):
    with client.session_transaction() as session:
        session['username'] = 'test-user'

    cache = FakeCacheCollection()
    database = FakeDatabase({'source_evidence_cache': cache})
    result = {
        'cve_id': 'CVE-2026-1000',
        'task_type': 'enrichment',
        'url': 'https://example.com/advisory',
        'content_hash': 'hash-1',
    }
    card = _normalize_card({
        'confidence': 'high',
        'what_happened': 'Cached fact.',
        'why_matters': 'Risk.',
        'how_to_respond': 'Upgrade.',
        'references': ['https://example.com/advisory'],
    }, {
        **result,
        'run_id': 'run-a',
        'candidate_id': 'candidate-a',
    })
    store_cached_payload(database, result, card, '1')
    monkeypatch.setattr('reports.routes.get_web_database', lambda: database)

    response = client.post('/api/reports/evidence-cache/purge')

    assert response.status_code == 200
    assert response.get_json()['deleted_count'] == 1
    assert cache.docs == {}
