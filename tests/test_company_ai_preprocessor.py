from datetime import timedelta

import importlib

from app import app
from bootstrap import configure_application
from company_ai_preprocessor import (
    _claim_task,
    _clear_queues,
    _complete_task,
    _gpu_queue_declare,
    _now,
    _process_company_task,
    _route_task,
    _routed_queue_declare,
    _release_processing_task,
    _requeue_task,
    _reset_processing_for_owner,
    _shutdown_worker,
    enqueue_final_summary,
    enqueue_report_items,
    enqueue_summary,
    store_completed_summary,
    summary_content_hash,
    wait_for_summaries,
)
from mongo import get_vulnerabilities_database


TEST_COLLECTION = 'company_ai_preprocessor_test'


def _source():
    return get_vulnerabilities_database()[TEST_COLLECTION]


def test_content_hash_changes_with_language_details_and_cache_version_not_model():
    config = dict(app.config)
    details = {'source': {'description': 'one'}}
    original = summary_content_hash(details, 'en', config)

    assert summary_content_hash(details, 'zh', config) != original
    assert summary_content_hash({'source': {'description': 'two'}}, 'en', config) != original
    config['COMPANY_AI_MODEL'] = 'different-model'
    assert summary_content_hash(details, 'en', config) == original
    config['PREPROCESSING_CACHE_VERSION'] = '2'
    assert summary_content_hash(details, 'en', config) != original


def test_enqueue_summary_republishes_pending_after_queue_clear(monkeypatch):
    published = []
    monkeypatch.setattr(
        'company_ai_preprocessor._publish',
        lambda task, priority, config, channel=None: published.append(task),
    )
    with app.app_context():
        source = _source()
        source.delete_many({})
        source.insert_one({'_id': 'fresh', 'details': {'source': {'description': 'evidence'}}})
        try:
            reference, queued = enqueue_summary(
                {'source': {'description': 'evidence'}},
                'en',
                app.config,
                app.config['RABBITMQ_BACKGROUND_PRIORITY'],
                TEST_COLLECTION,
                'fresh',
            )
            again, queued_again = enqueue_summary(
                {'source': {'description': 'evidence'}},
                'en',
                app.config,
                app.config['RABBITMQ_BACKGROUND_PRIORITY'],
                TEST_COLLECTION,
                'fresh',
            )

            assert queued is True
            assert queued_again is True
            assert reference == again
            assert len(published) == 2
        finally:
            source.drop()


def test_enqueue_summary_republishes_stale_pending(monkeypatch):
    published = []
    monkeypatch.setattr(
        'company_ai_preprocessor._publish',
        lambda task, priority, config, channel=None: published.append(task),
    )
    with app.app_context():
        source = _source()
        source.delete_many({})
        source.insert_one({'_id': 'stale', 'details': {'source': {'description': 'evidence'}}})
        try:
            enqueue_summary(
                {'source': {'description': 'evidence'}},
                'en',
                app.config,
                app.config['RABBITMQ_BACKGROUND_PRIORITY'],
                TEST_COLLECTION,
                'stale',
            )
            source.update_one(
                {'_id': 'stale'},
                {'$set': {
                    'html_json.en.updated_at': _now() - timedelta(
                        seconds=app.config['COMPANY_AI_STALE_PROCESSING_SECONDS'] + 1,
                    ),
                }},
            )
            _, queued_again = enqueue_summary(
                {'source': {'description': 'evidence'}},
                'en',
                app.config,
                app.config['RABBITMQ_BACKGROUND_PRIORITY'],
                TEST_COLLECTION,
                'stale',
            )

            assert queued_again is True
            assert len(published) == 2
        finally:
            source.drop()


def test_completed_summary_is_stored_on_source_and_reused(monkeypatch):
    published = []
    monkeypatch.setattr(
        'company_ai_preprocessor._publish',
        lambda task, priority, config, channel=None: published.append((task, priority)),
    )
    with app.app_context():
        source = _source()
        source.delete_many({})
        source.insert_one({'_id': 'item-1', 'details': {'source': {'description': 'evidence'}}})
        try:
            reference, queued = enqueue_summary(
                {'source': {'description': 'evidence'}},
                'en',
                app.config,
                app.config['RABBITMQ_BACKGROUND_PRIORITY'],
                TEST_COLLECTION,
                'item-1',
            )
            source.update_one(
                {'_id': 'item-1'},
                {'$set': {
                    'html_json.en.status': 'completed',
                    'html_json.en.result': {
                        'highlight': {'title': 'Cached', 'summary': 'Summary'},
                        'recommendations': [],
                    },
                }},
            )
            reused, queued_again = enqueue_summary(
                {'source': {'description': 'evidence'}},
                'en',
                app.config,
                app.config['RABBITMQ_REPORT_PRIORITY'],
                TEST_COLLECTION,
                'item-1',
            )

            document = source.find_one({'_id': 'item-1'})
            assert queued is True
            assert queued_again is False
            assert reference == reused
            assert document['html_json']['en']['result']['highlight']['title'] == 'Cached'
            assert len(published) == 1
        finally:
            source.drop()


def test_report_items_publish_at_report_priority_and_preserve_wait_order(monkeypatch):
    priorities = []

    class FakeConnection:
        is_open = True

        def channel(self):
            return FakeChannel()

        def close(self):
            return None

    class FakeChannel:
        def confirm_delivery(self):
            return None

    monkeypatch.setattr(
        'company_ai_preprocessor.pika.BlockingConnection',
        lambda parameters: FakeConnection(),
    )
    monkeypatch.setattr('company_ai_preprocessor._queue_declare', lambda channel, config: None)
    monkeypatch.setattr(
        'company_ai_preprocessor._publish',
        lambda task, priority, config, channel=None: priorities.append(priority),
    )
    with app.app_context():
        source = _source()
        source.delete_many({})
        source.insert_many([
            {'_id': 'priority-1', 'details': {'source': {'description': 'first'}}},
            {'_id': 'priority-2', 'details': {'source': {'description': 'second'}}},
        ])
        try:
            references = enqueue_report_items([
                {
                    'details': {'source': {'description': 'first'}},
                    'source_collection': TEST_COLLECTION,
                    'source_id': 'priority-1',
                },
                {
                    'details': {'source': {'description': 'second'}},
                    'source_collection': TEST_COLLECTION,
                    'source_id': 'priority-2',
                },
            ], 'en', app.config)
            source.update_one(
                {'_id': 'priority-2'},
                {'$set': {'html_json.en.status': 'completed', 'html_json.en.result': {'order': 2}}},
            )
            source.update_one(
                {'_id': 'priority-1'},
                {'$set': {'html_json.en.status': 'completed', 'html_json.en.result': {'order': 1}}},
            )

            assert priorities == [app.config['RABBITMQ_REPORT_PRIORITY']] * 2
            assert wait_for_summaries(references, 1) == [{'order': 1}, {'order': 2}]
        finally:
            source.drop()


def test_uploaded_items_and_final_summaries_use_shared_atlas_tasks(monkeypatch):
    published = []
    monkeypatch.setattr(
        'company_ai_preprocessor._publish',
        lambda task, priority, config, channel=None: published.append(task),
    )
    with app.app_context():
        collection = get_vulnerabilities_database()[app.config['AI_TASK_COLLECTION']]
        collection.delete_many({'source_key': {'$regex': '^upload:'}})
        try:
            item_reference, queued = enqueue_summary(
                {'source': {'description': 'uploaded evidence'}},
                'en',
                app.config,
                app.config['RABBITMQ_REPORT_PRIORITY'],
            )
            final_reference = enqueue_final_summary(
                [{'highlight': {'summary': 'Summary'}, 'recommendations': []}],
                'en',
                app.config,
            )

            item = collection.find_one({'_id': item_reference['task_id']})
            final = collection.find_one({'_id': final_reference['task_id']})
            assert queued is True
            assert item_reference['storage'] == 'shared'
            assert item['task_type'] == 'item'
            assert item['payload']['source']['description'] == 'uploaded evidence'
            assert final['task_type'] == 'final'
            assert final['payload']['item_results'][0]['highlight']['summary'] == 'Summary'
            assert all('details' not in task and 'payload' not in task for task in published)
        finally:
            collection.delete_many({'source_key': {'$regex': '^upload:'}})


def test_source_claim_is_atomic_and_stale_processing_can_be_recovered(monkeypatch):
    monkeypatch.setattr('company_ai_preprocessor._publish', lambda *args, **kwargs: None)
    with app.app_context():
        source = _source()
        source.delete_many({})
        source.insert_one({'_id': 'claim', 'details': {'source': {'description': 'claim'}}})
        try:
            reference, _ = enqueue_summary(
                {'source': {'description': 'claim'}},
                'en',
                app.config,
                app.config['RABBITMQ_BACKGROUND_PRIORITY'],
                TEST_COLLECTION,
                'claim',
            )
            task = {**reference, 'content_hash': source.find_one({'_id': 'claim'})[
                'html_json'
            ]['en']['content_hash']}
            first = _claim_task(task, 'worker-1', app.config)
            duplicate = _claim_task(task, 'worker-2', app.config)
            source.update_one(
                {'_id': 'claim'},
                {'$set': {
                    'html_json.en.processing_started_at': _now() - timedelta(
                        seconds=app.config['COMPANY_AI_STALE_PROCESSING_SECONDS'] + 1,
                    ),
                }},
            )
            recovered = _claim_task(task, 'worker-2', app.config)
            _complete_task(task, 'worker-2', {'highlight': {'title': 'Done', 'summary': 'Done'}})

            document = source.find_one({'_id': 'claim'})
            assert first['processing_owner'] == 'worker-1'
            assert duplicate is None
            assert recovered['processing_owner'] == 'worker-2'
            assert recovered['attempts'] == 2
            assert document['html_json']['en']['status'] == 'completed'
            assert document['html_json']['en']['result']['highlight']['title'] == 'Done'
        finally:
            source.drop()


def test_store_completed_summary_marks_source_entry_completed(monkeypatch):
    monkeypatch.setattr('company_ai_preprocessor._publish', lambda *args, **kwargs: None)
    with app.app_context():
        source = _source()
        source.delete_many({})
        source.insert_one({'_id': 'store-1', 'details': {'source': {'description': 'evidence'}}})
        try:
            reference, _ = enqueue_summary(
                {'source': {'description': 'evidence'}},
                'en',
                app.config,
                app.config['RABBITMQ_BACKGROUND_PRIORITY'],
                TEST_COLLECTION,
                'store-1',
            )
            result = {
                'highlight': {'title': 'Company AI', 'summary': 'Summary'},
                'recommendations': [],
            }
            assert store_completed_summary(reference, result) is True
            document = source.find_one({'_id': 'store-1'})
            entry = document['html_json']['en']
            assert entry['status'] == 'completed'
            assert entry['result'] == result
            assert entry['provider'] == 'company_ai'
        finally:
            source.drop()


def test_store_completed_summary_skips_when_content_hash_changed(monkeypatch):
    monkeypatch.setattr('company_ai_preprocessor._publish', lambda *args, **kwargs: None)
    with app.app_context():
        source = _source()
        source.delete_many({})
        source.insert_one({'_id': 'store-2', 'details': {'source': {'description': 'evidence'}}})
        try:
            reference, _ = enqueue_summary(
                {'source': {'description': 'evidence'}},
                'en',
                app.config,
                app.config['RABBITMQ_BACKGROUND_PRIORITY'],
                TEST_COLLECTION,
                'store-2',
            )
            source.update_one(
                {'_id': 'store-2'},
                {'$set': {'html_json.en.content_hash': 'stale-hash'}},
            )
            assert store_completed_summary(reference, {'highlight': {}, 'recommendations': []}) is False
            assert source.find_one({'_id': 'store-2'})['html_json']['en']['status'] == 'pending'
        finally:
            source.drop()


def test_completed_reference_is_acked_without_generate_item_data(monkeypatch):
    generated = []
    published = []
    acked = []

    class FakeChannel:
        delivery_tag = 1

        def basic_qos(self, **kwargs):
            return None

        def basic_ack(self, delivery_tag):
            acked.append(delivery_tag)

    monkeypatch.setattr('company_ai_preprocessor._publish', lambda *args, **kwargs: published.append(args))
    monkeypatch.setattr(
        'company_ai_preprocessor.generate_item_data',
        lambda *args, **kwargs: generated.append(args) or ({'highlight': {}, 'recommendations': []}, {}),
    )
    with app.app_context():
        source = _source()
        source.delete_many({})
        source.insert_one({'_id': 'done', 'details': {'source': {'description': 'done'}}})
        try:
            reference, _ = enqueue_summary(
                {'source': {'description': 'done'}},
                'en',
                app.config,
                app.config['RABBITMQ_BACKGROUND_PRIORITY'],
                TEST_COLLECTION,
                'done',
            )
            store_completed_summary(reference, {
                'highlight': {'title': 'Done', 'summary': 'Done'},
                'recommendations': [],
            })
            task = {**reference, 'content_hash': reference['content_hash']}
            claimed = _claim_task(task, 'worker-1', app.config)
            assert claimed is None
            assert generated == []
            FakeChannel().basic_ack(1)
            assert acked == [1]
        finally:
            source.drop()


def test_worker_failure_requeues_task_to_background_priority(monkeypatch):
    republished = []

    class FakeChannel:
        pass

    monkeypatch.setattr(
        'company_ai_preprocessor._publish_to_queue',
        lambda task, priority, config, queue_name, channel=None: republished.append(
            (task, priority, queue_name)
        ),
    )
    retry_config = {**dict(app.config), 'COMPANY_AI_ENABLED': True}
    with app.app_context():
        source = _source()
        source.delete_many({})
        source.insert_one({'_id': 'retry', 'details': {'source': {'description': 'retry'}}})
        try:
            reference, _ = enqueue_summary(
                {'source': {'description': 'retry'}},
                'en',
                app.config,
                app.config['RABBITMQ_BACKGROUND_PRIORITY'],
                TEST_COLLECTION,
                'retry',
            )
            task = {**reference, 'content_hash': reference['content_hash']}
            claimed = _claim_task(task, 'worker-1', app.config)
            _requeue_task(
                task,
                'worker-1',
                ValueError('temporary failure'),
                retry_config,
                FakeChannel(),
                claimed,
            )
            document = source.find_one({'_id': 'retry'})
            entry = document['html_json']['en']
            assert entry['status'] == 'pending'
            assert entry['error'] == 'temporary failure'
            assert republished[-1][1] == retry_config['RABBITMQ_BACKGROUND_PRIORITY']
            assert republished[-1][0]['source_id'] == 'retry'
            assert republished[-1][2] == app.config['RABBITMQ_COMPANY_QUEUE']
        finally:
            source.drop()


def test_company_task_opens_primes_processes_and_closes_one_chat(monkeypatch):
    events = []
    result = {'highlight': {'summary': 'done'}, 'recommendations': []}

    class FakeProvider:
        def __init__(self, config):
            events.append('create-provider')

        def create_room(self):
            events.append('open-and-prime')

        def delete_room(self):
            events.append('close')

    monkeypatch.setattr('company_ai_preprocessor.CompanyAIProvider', FakeProvider)
    monkeypatch.setattr(
        'company_ai_preprocessor._task_details',
        lambda task, config: {'description': 'evidence'},
    )
    monkeypatch.setattr(
        'company_ai_preprocessor.summary_content_hash',
        lambda details, language, config: 'hash',
    )
    monkeypatch.setattr(
        'company_ai_preprocessor.generate_item_data',
        lambda provider, details, source_key, language, retries: (
            events.append('process') or result,
            {},
        ),
    )
    monkeypatch.setattr(
        'company_ai_preprocessor._complete_task',
        lambda task, owner, value, provider: events.append(('store', provider, value)),
    )
    task = {'content_hash': 'hash', 'language': 'en'}
    assert _process_company_task(task, {'source_key': 'source'}, 'owner', dict(app.config)) == result
    assert events == [
        'create-provider',
        'open-and-prime',
        'process',
        ('store', 'company_ai', result),
        'close',
    ]


def test_company_worker_processes_final_summary_task(monkeypatch):
    events = []
    result = {'title': 'Cybersecurity Report', 'executive_summary': 'done',
              'trends': [], 'recommendations': []}

    class FakeProvider:
        def __init__(self, config):
            pass

        def create_room(self, prime_prompt=None):
            events.append(('open', prime_prompt))

        def delete_room(self):
            events.append('close')

    monkeypatch.setattr('company_ai_preprocessor.CompanyAIProvider', FakeProvider)
    monkeypatch.setattr(
        'company_ai_preprocessor._task_details',
        lambda task, config: {'item_results': [{'highlight': {'summary': 'item'}}]},
    )
    monkeypatch.setattr(
        'company_ai_preprocessor.summary_content_hash',
        lambda details, language, config: 'hash',
    )
    monkeypatch.setattr(
        'company_ai_preprocessor.generate_final_data',
        lambda provider, items, language, retries, config: (result, {}),
    )
    monkeypatch.setattr(
        'company_ai_preprocessor._complete_task',
        lambda task, owner, value, provider: events.append(('store', provider, value)),
    )
    task = {'task_type': 'final', 'content_hash': 'hash', 'language': 'en'}
    assert _process_company_task(task, {'source_key': 'final'}, 'owner', dict(app.config)) == result
    assert events == [('open', ''), ('store', 'company_ai', result), 'close']


def test_reset_processing_for_owner_resets_source_entry_to_pending(monkeypatch):
    monkeypatch.setattr('company_ai_preprocessor._publish', lambda *args, **kwargs: None)
    with app.app_context():
        source = _source()
        source.delete_many({})
        source.insert_one({'_id': 'reset', 'details': {'source': {'description': 'reset'}}})
        try:
            reference, _ = enqueue_summary(
                {'source': {'description': 'reset'}},
                'en',
                app.config,
                app.config['RABBITMQ_BACKGROUND_PRIORITY'],
                TEST_COLLECTION,
                'reset',
            )
            task = {**reference, 'content_hash': reference['content_hash']}
            _claim_task(task, 'worker-reset', app.config)
            _reset_processing_for_owner('worker-reset')
            entry = source.find_one({'_id': 'reset'})['html_json']['en']
            assert entry['status'] == 'pending'
            assert 'processing_owner' not in entry
            assert 'processing_started_at' not in entry
        finally:
            source.drop()


def test_release_processing_task_republishes_to_background_priority(monkeypatch):
    republished = []
    monkeypatch.setattr(
        'company_ai_preprocessor._publish_to_queue',
        lambda task, priority, config, queue_name, channel=None: republished.append(
            (task, priority, queue_name)
        ),
    )
    release_config = {
        **dict(app.config),
        'COMPANY_AI_ENABLED': True,
        'GPU_ENABLED': False,
    }
    with app.app_context():
        source = _source()
        source.delete_many({})
        source.insert_one({'_id': 'release', 'details': {'source': {'description': 'release'}}})
        try:
            reference, _ = enqueue_summary(
                {'source': {'description': 'release'}},
                'en',
                app.config,
                app.config['RABBITMQ_BACKGROUND_PRIORITY'],
                TEST_COLLECTION,
                'release',
            )
            task = {**reference, 'content_hash': reference['content_hash']}
            _claim_task(task, 'worker-release', app.config)
            _release_processing_task(task, 'worker-release', release_config)
            entry = source.find_one({'_id': 'release'})['html_json']['en']
            assert entry['status'] == 'pending'
            assert republished[-1][1] == app.config['RABBITMQ_BACKGROUND_PRIORITY']
            assert republished[-1][0]['source_id'] == 'release'
        finally:
            source.drop()


def test_shutdown_worker_deletes_room_resets_processing_and_acks(monkeypatch):
    republished = []
    deleted = []
    acked = []

    class FakeChannel:
        delivery_tag = 7

        def basic_ack(self, delivery_tag):
            acked.append(delivery_tag)

    class FakeProvider:
        def delete_room(self):
            deleted.append('delete')

    monkeypatch.setattr(
        'company_ai_preprocessor._publish_to_queue',
        lambda task, priority, config, queue_name, channel=None: republished.append(
            (task, priority, queue_name)
        ),
    )
    shutdown_config = {
        **dict(app.config),
        'COMPANY_AI_ENABLED': True,
        'GPU_ENABLED': False,
    }
    with app.app_context():
        source = _source()
        source.delete_many({})
        source.insert_one({'_id': 'shutdown', 'details': {'source': {'description': 'shutdown'}}})
        try:
            reference, _ = enqueue_summary(
                {'source': {'description': 'shutdown'}},
                'en',
                app.config,
                app.config['RABBITMQ_BACKGROUND_PRIORITY'],
                TEST_COLLECTION,
                'shutdown',
            )
            task = {**reference, 'content_hash': reference['content_hash']}
            _claim_task(task, 'worker-shutdown', app.config)
            method = type('Method', (), {'delivery_tag': 7})()
            _shutdown_worker(
                'worker-shutdown',
                FakeProvider(),
                shutdown_config,
                FakeChannel(),
                active_task=task,
                active_method=method,
            )
            entry = source.find_one({'_id': 'shutdown'})['html_json']['en']
            assert entry['status'] == 'pending'
            assert deleted == ['delete']
            assert acked == [7]
            assert republished[-1][0]['source_id'] == 'shutdown'
        finally:
            source.drop()


def test_preprocessor_module_does_not_import_flask_app():
    loaded = importlib.import_module('company_ai_preprocessor')
    assert 'app' not in loaded.__dict__
    standalone_config = configure_application()
    assert standalone_config['COMPANY_AI_PARALLEL_CHATS'] >= 1


def test_router_sends_source_and_shared_tasks_to_gpu_until_backlog_limit(monkeypatch):
    routed = []

    class QueueStatus:
        method = type('Method', (), {'message_count': 0})()

    class FakeChannel:
        def queue_declare(self, **kwargs):
            return QueueStatus()

    monkeypatch.setattr(
        'company_ai_preprocessor._publish_to_queue',
        lambda task, priority, config, queue_name, channel=None: routed.append(queue_name),
    )
    config = {
        **dict(app.config),
        'GPU_QUEUE_BACKLOG_LIMIT': 1,
        'GPU_ENABLED': True,
        'COMPANY_AI_ENABLED': True,
    }
    assert _route_task({'storage': 'source'}, 1, config, FakeChannel()) == config[
        'RABBITMQ_GPU_QUEUE'
    ]
    assert _route_task({'storage': 'shared'}, 1, config, FakeChannel()) == config[
        'RABBITMQ_GPU_QUEUE'
    ]
    assert routed == [config['RABBITMQ_GPU_QUEUE'], config['RABBITMQ_GPU_QUEUE']]


def test_router_sends_source_overflow_to_company(monkeypatch):
    routed = []

    class QueueStatus:
        method = type('Method', (), {'message_count': 3})()

    class FakeChannel:
        def queue_declare(self, **kwargs):
            return QueueStatus()

    monkeypatch.setattr(
        'company_ai_preprocessor._publish_to_queue',
        lambda task, priority, config, queue_name, channel=None: routed.append(queue_name),
    )
    config = {
        **dict(app.config),
        'GPU_QUEUE_BACKLOG_LIMIT': 3,
        'GPU_ENABLED': True,
        'COMPANY_AI_ENABLED': True,
    }
    assert _route_task({'storage': 'source'}, 1, config, FakeChannel()) == config[
        'RABBITMQ_COMPANY_QUEUE'
    ]
    assert routed == [config['RABBITMQ_COMPANY_QUEUE']]


def test_gpu_queue_has_no_automatic_dead_letter_to_disabled_provider():
    declarations = []

    class FakeChannel:
        def queue_declare(self, **kwargs):
            declarations.append(kwargs)

    config = dict(app.config)
    _gpu_queue_declare(FakeChannel(), config)
    gpu = next(item for item in declarations if item['queue'] == config['RABBITMQ_GPU_QUEUE'])
    assert gpu['arguments'] == {'x-max-priority': config['RABBITMQ_MAX_PRIORITY']}


def test_router_never_sends_to_disabled_providers(monkeypatch):
    routed = []

    class FakeChannel:
        def queue_declare(self, **kwargs):
            return type('QueueStatus', (), {'method': type('Method', (), {'message_count': 0})()})()

    monkeypatch.setattr(
        'company_ai_preprocessor._publish_to_queue',
        lambda task, priority, config, queue_name, channel=None: routed.append(queue_name),
    )
    config = {
        **dict(app.config),
        'GPU_QUEUE_BACKLOG_LIMIT': 20,
        'GPU_ENABLED': False,
        'COMPANY_AI_ENABLED': True,
    }
    assert _route_task({'storage': 'source'}, 1, config, FakeChannel()) == config[
        'RABBITMQ_COMPANY_QUEUE'
    ]
    config['COMPANY_AI_ENABLED'] = False
    assert _route_task({'storage': 'source'}, 1, config, FakeChannel()) is None
    assert _route_task({'storage': 'shared'}, 1, config, FakeChannel()) is None
    assert routed == [config['RABBITMQ_COMPANY_QUEUE']]


def test_clear_queues_purges_intake_gpu_and_company(monkeypatch):
    purged = []

    class FakeChannel:
        def queue_declare(self, **kwargs):
            return None

        def queue_purge(self, queue):
            purged.append(queue)

    class FakeConnection:
        def channel(self):
            return FakeChannel()

        def close(self):
            return None

    monkeypatch.setattr(
        'company_ai_preprocessor.pika.BlockingConnection',
        lambda parameters: FakeConnection(),
    )
    config = dict(app.config)
    _clear_queues(config)
    assert purged == [
        config['RABBITMQ_INTAKE_QUEUE'],
        config['RABBITMQ_GPU_QUEUE'],
        config['RABBITMQ_COMPANY_QUEUE'],
    ]
