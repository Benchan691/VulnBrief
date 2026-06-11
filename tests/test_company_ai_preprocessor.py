from datetime import timedelta

import importlib

from app import app
from bootstrap import configure_application
from company_ai_preprocessor import (
    _claim_task,
    _complete_task,
    _now,
    _refresh_provider_room,
    _release_processing_task,
    _requeue_task,
    _reset_processing_for_owner,
    _shutdown_worker,
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


def test_content_hash_changes_with_language_model_and_details():
    config = dict(app.config)
    details = {'source': {'description': 'one'}}
    original = summary_content_hash(details, 'en', config)

    assert summary_content_hash(details, 'zh', config) != original
    assert summary_content_hash({'source': {'description': 'two'}}, 'en', config) != original
    config['COMPANY_AI_MODEL'] = 'different-model'
    assert summary_content_hash(details, 'en', config) != original


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
        'company_ai_preprocessor._publish',
        lambda task, priority, config, channel=None: republished.append((task, priority)),
    )
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
                app.config,
                FakeChannel(),
                claimed,
            )
            document = source.find_one({'_id': 'retry'})
            entry = document['html_json']['en']
            assert entry['status'] == 'pending'
            assert entry['error'] == 'temporary failure'
            assert republished[-1][1] == app.config['RABBITMQ_BACKGROUND_PRIORITY']
            assert republished[-1][0]['source_id'] == 'retry'
        finally:
            source.drop()


def test_refresh_provider_room_closes_and_reopens_chat():
    events = []

    class FakeProvider:
        def delete_room(self):
            events.append('delete')

        def create_room(self):
            events.append('create')
            return 'new-room'

    _refresh_provider_room(FakeProvider())
    assert events == ['delete', 'create']


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
        'company_ai_preprocessor._publish',
        lambda task, priority, config, channel=None: republished.append((task, priority)),
    )
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
            _release_processing_task(task, 'worker-release', app.config)
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
        'company_ai_preprocessor._publish',
        lambda task, priority, config, channel=None: republished.append((task, priority)),
    )
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
                app.config,
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


def test_refresh_provider_room_still_reopens_when_delete_fails():
    events = []

    class FakeProvider:
        def delete_room(self):
            raise RuntimeError('delete failed')

        def create_room(self):
            events.append('create')
            return 'new-room'

    _refresh_provider_room(FakeProvider())
    assert events == ['create']


def test_preprocessor_module_does_not_import_flask_app():
    loaded = importlib.import_module('company_ai_preprocessor')
    assert 'app' not in loaded.__dict__
    standalone_config = configure_application()
    assert standalone_config['COMPANY_AI_PARALLEL_CHATS'] >= 1
