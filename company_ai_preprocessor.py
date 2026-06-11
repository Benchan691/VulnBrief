import argparse
import hashlib
import json
import re
import signal
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import pika
from bson import json_util
from pymongo import ReturnDocument
from pymongo.errors import PyMongoError

from bootstrap import BASE_DIR, configure_application
from mongo import get_vulnerabilities_database, get_web_database
from report_harness import (
    CompanyAIProvider,
    REPORT_LANGUAGES,
    _debug_log,
    _looks_like_utf8_mojibake,
    compact_details,
    generate_item_data,
)


UPLOAD_CACHE_COLLECTION = 'company_ai_upload_summaries'
STOP_EVENT = threading.Event()


def _now():
    return datetime.now(timezone.utc)


def _upload_cache_collection():
    return get_web_database()[UPLOAD_CACHE_COLLECTION]


def ensure_cache_indexes():
    collection = _upload_cache_collection()
    collection.create_index(
        [('source_key', 1), ('language', 1)],
        unique=True,
        name='source_language',
    )
    collection.create_index([('status', 1), ('updated_at', 1)], name='status_updated')


def cache_source_key(source_collection=None, source_id=None, details=None):
    if source_collection is not None and source_id is not None:
        return f'source:{source_collection}:{source_id}'
    payload = json.dumps(details, ensure_ascii=False, sort_keys=True, default=str)
    return 'upload:' + hashlib.sha256(payload.encode('utf-8')).hexdigest()


def _source_collection(name):
    return get_vulnerabilities_database()[name]


def _language_path(language, field=None):
    path = f'html_json.{language}'
    return f'{path}.{field}' if field else path


def summary_content_hash(details, language, config):
    identity = {
        'details': details,
        'language': language,
        'model': config['COMPANY_AI_MODEL'],
        'start_prompt': config['COMPANY_AI_START_PROMPT'],
        'user_prompt': config['COMPANY_AI_USER_PROMPT'],
        'use_think': config['COMPANY_AI_USE_THINK'],
    }
    payload = json.dumps(identity, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def _queue_declare(channel, config):
    return channel.queue_declare(
        queue=config['RABBITMQ_QUEUE_NAME'],
        durable=True,
        arguments={'x-max-priority': config['RABBITMQ_MAX_PRIORITY']},
    )


def _publisher_channel(connection, config):
    channel = connection.channel()
    _queue_declare(channel, config)
    channel.confirm_delivery()
    return channel


def _publish(task, priority, config, channel=None):
    connection = None
    if channel is None:
        connection = pika.BlockingConnection(pika.URLParameters(config['RABBITMQ_URL']))
        channel = _publisher_channel(connection, config)
    try:
        channel.basic_publish(
            exchange='',
            routing_key=config['RABBITMQ_QUEUE_NAME'],
            body=json_util.dumps(task).encode('utf-8'),
            properties=pika.BasicProperties(
                delivery_mode=2,
                content_type='application/json',
                priority=max(0, min(priority, config['RABBITMQ_MAX_PRIORITY'])),
            ),
        )
    finally:
        if connection is not None:
            connection.close()


def enqueue_summary(
    details,
    language,
    config,
    priority,
    source_collection=None,
    source_id=None,
    channel=None,
):
    compacted = compact_details(details, config)
    source_key = cache_source_key(source_collection, source_id, compacted)
    content_hash = summary_content_hash(compacted, language, config)
    if source_collection is not None and source_id is not None:
        source = _source_collection(source_collection)
        document = source.find_one(
            {'_id': source_id},
            {_language_path(language): 1},
        )
        if document is None:
            raise ValueError(f'Source vulnerability not found: {source_collection}/{source_id}')
        existing = (document.get('html_json') or {}).get(language)
        reference = {
            'storage': 'source',
            'source_collection': source_collection,
            'source_id': source_id,
            'language': language,
            'content_hash': content_hash,
        }
    else:
        collection = _upload_cache_collection()
        existing = collection.find_one({'source_key': source_key, 'language': language})
        reference = {
            'storage': 'upload',
            'cache_id': existing['_id'] if existing else None,
            'language': language,
            'content_hash': content_hash,
        }
    if existing and existing.get('status') == 'completed' and existing.get('content_hash') == content_hash:
        return reference, False
    if (
        existing
        and existing.get('content_hash') == content_hash
        and existing.get('status') in {'pending', 'processing'}
    ):
        task = {
            **reference,
            'content_hash': content_hash,
            'source_collection': source_collection,
            'source_id': source_id,
            'details': compacted if source_collection is None else None,
            'language': language,
        }
        _publish(task, priority, config, channel)
        return reference, True

    now = _now()
    entry = {
            'source_key': source_key,
            'language': language,
            'content_hash': content_hash,
            'status': 'pending',
            'attempts': existing.get('attempts', 0) if existing else 0,
            'created_at': existing.get('created_at', now) if existing else now,
            'updated_at': now,
    }
    if source_collection is not None and source_id is not None:
        _source_collection(source_collection).update_one(
            {'_id': source_id},
            {'$set': {_language_path(language): entry}},
        )
    else:
        document = _upload_cache_collection().find_one_and_update(
            {'source_key': source_key, 'language': language},
            {'$set': entry},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        reference['cache_id'] = document['_id']
    task = {
        **reference,
        'content_hash': content_hash,
        'source_collection': source_collection,
        'source_id': source_id,
        'details': compacted if source_collection is None else None,
        'language': language,
    }
    _publish(task, priority, config, channel)
    return reference, True


def scan_unprocessed(config):
    ensure_cache_indexes()
    database = get_vulnerabilities_database()
    queued = 0
    connection = pika.BlockingConnection(pika.URLParameters(config['RABBITMQ_URL']))
    try:
        channel = _publisher_channel(connection, config)
        for metadata in database.list_collections(filter={'type': 'collection'}):
            collection_name = metadata['name']
            if collection_name.startswith('system.'):
                continue
            for document in database[collection_name].find({}, {'details': 1}):
                details = document.get('details')
                if not isinstance(details, dict):
                    continue
                for language in REPORT_LANGUAGES:
                    _, published = enqueue_summary(
                        details,
                        language,
                        config,
                        config['RABBITMQ_BACKGROUND_PRIORITY'],
                        collection_name,
                        document['_id'],
                        channel,
                    )
                    queued += int(published)
    finally:
        connection.close()
    return queued


def enqueue_report_items(items, language, config):
    references = []
    connection = pika.BlockingConnection(pika.URLParameters(config['RABBITMQ_URL']))
    try:
        channel = _publisher_channel(connection, config)
        for item in items:
            reference, _ = enqueue_summary(
                item['details'],
                language,
                config,
                config['RABBITMQ_REPORT_PRIORITY'],
                item.get('source_collection'),
                item.get('source_id'),
                channel,
            )
            references.append(reference)
    finally:
        connection.close()
    return references


def _reference_result(reference):
    if reference['storage'] == 'source':
        document = _source_collection(reference['source_collection']).find_one(
            {'_id': reference['source_id']},
            {_language_path(reference['language']): 1},
        )
        entry = ((document or {}).get('html_json') or {}).get(reference['language'], {})
    else:
        entry = _upload_cache_collection().find_one({'_id': reference['cache_id']}) or {}
    return entry.get('result') if entry.get('status') == 'completed' else None


def wait_for_summaries(references, timeout_seconds):
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        results = [_reference_result(reference) for reference in references]
        if all(result is not None for result in results):
            break
        time.sleep(0.5)
    return [_reference_result(reference) for reference in references]


def _task_details(task, config):
    if task.get('source_collection'):
        document = get_vulnerabilities_database()[task['source_collection']].find_one(
            {'_id': task['source_id']},
            {'details': 1},
        )
        if document is None or not isinstance(document.get('details'), dict):
            raise ValueError('Source vulnerability details no longer exist.')
        return compact_details(document['details'], config)
    return task['details']


def _claim_task(task, owner, config):
    stale_before = _now() - timedelta(seconds=config['COMPANY_AI_STALE_PROCESSING_SECONDS'])
    if task['storage'] == 'source':
        language = task['language']
        path = _language_path(language)
        document = _source_collection(task['source_collection']).find_one_and_update(
            {
                '_id': task['source_id'],
                f'{path}.content_hash': task['content_hash'],
                '$or': [
                    {f'{path}.status': {'$in': ['pending', 'failed']}},
                    {
                        f'{path}.status': 'processing',
                        f'{path}.processing_started_at': {'$lte': stale_before},
                    },
                ],
            },
            {
                '$set': {
                    f'{path}.status': 'processing',
                    f'{path}.processing_owner': owner,
                    f'{path}.processing_started_at': _now(),
                    f'{path}.updated_at': _now(),
                },
                '$inc': {f'{path}.attempts': 1},
                '$unset': {f'{path}.error': ''},
            },
            return_document=ReturnDocument.AFTER,
        )
        return ((document or {}).get('html_json') or {}).get(language)
    return _upload_cache_collection().find_one_and_update(
        {
            '_id': task['cache_id'],
            'content_hash': task['content_hash'],
            '$or': [
                {'status': {'$in': ['pending', 'failed']}},
                {'status': 'processing', 'processing_started_at': {'$lte': stale_before}},
            ],
        },
        {
            '$set': {
                'status': 'processing',
                'processing_owner': owner,
                'processing_started_at': _now(),
                'updated_at': _now(),
            },
            '$inc': {'attempts': 1},
            '$unset': {'error': ''},
        },
        return_document=ReturnDocument.AFTER,
    )


def _complete_task(task, owner, result):
    values = {
        'status': 'completed',
        'result': result,
        'completed_at': _now(),
        'updated_at': _now(),
    }
    _update_task_entry(task, owner, values, ['processing_owner', 'processing_started_at', 'error'])


def _fail_task(task, owner, error):
    _update_task_entry(
        task,
        owner,
        {'status': 'failed', 'error': str(error), 'updated_at': _now()},
        ['processing_owner', 'processing_started_at'],
    )


def store_completed_summary(reference, result, provider='company_ai'):
    content_hash = reference.get('content_hash')
    if not content_hash:
        return False
    now = _now()
    values = {
        'status': 'completed',
        'result': result,
        'completed_at': now,
        'updated_at': now,
        'provider': provider,
    }
    unset_fields = ['processing_owner', 'processing_started_at', 'error']
    if reference['storage'] == 'source':
        path = _language_path(reference['language'])
        document = _source_collection(reference['source_collection']).find_one(
            {'_id': reference['source_id']},
            {path: 1},
        )
        entry = ((document or {}).get('html_json') or {}).get(reference['language'], {})
        if entry.get('content_hash') != content_hash:
            return False
        if entry.get('status') == 'completed':
            return True
        _source_collection(reference['source_collection']).update_one(
            {'_id': reference['source_id'], f'{path}.content_hash': content_hash},
            {
                '$set': {f'{path}.{key}': value for key, value in values.items()},
                '$unset': {f'{path}.{key}': '' for key in unset_fields},
            },
        )
        return True
    cache_id = reference.get('cache_id')
    if not cache_id:
        return False
    document = _upload_cache_collection().find_one({'_id': cache_id}) or {}
    if document.get('content_hash') != content_hash:
        return False
    if document.get('status') == 'completed':
        return True
    _upload_cache_collection().update_one(
        {'_id': cache_id, 'content_hash': content_hash},
        {
            '$set': values,
            '$unset': {key: '' for key in unset_fields},
        },
    )
    return True


def _requeue_task(task, owner, error, config, channel, claimed):
    max_attempts = config.get('COMPANY_AI_MAX_TASK_ATTEMPTS', 10)
    if (claimed or {}).get('attempts', 0) >= max_attempts:
        _fail_task(task, owner, error)
        return
    _update_task_entry(
        task,
        owner,
        {'status': 'pending', 'error': str(error), 'updated_at': _now()},
        ['processing_owner', 'processing_started_at'],
    )
    _publish(task, config['RABBITMQ_BACKGROUND_PRIORITY'], config, channel)


def _refresh_provider_room(provider):
    try:
        provider.delete_room()
    except Exception:
        pass
    provider.create_room()


def _update_task_entry(task, owner, values, unset_fields):
    if task['storage'] == 'source':
        path = _language_path(task['language'])
        _source_collection(task['source_collection']).update_one(
            {'_id': task['source_id'], f'{path}.processing_owner': owner},
            {
                '$set': {f'{path}.{key}': value for key, value in values.items()},
                '$unset': {f'{path}.{key}': '' for key in unset_fields},
            },
        )
    else:
        _upload_cache_collection().update_one(
            {'_id': task['cache_id'], 'processing_owner': owner},
            {
                '$set': values,
                '$unset': {key: '' for key in unset_fields},
            },
        )


def _reset_processing_for_owner(owner):
    now = _now()
    database = get_vulnerabilities_database()
    for metadata in database.list_collections(filter={'type': 'collection'}):
        collection_name = metadata['name']
        if collection_name.startswith('system.'):
            continue
        for language in REPORT_LANGUAGES:
            path = _language_path(language)
            database[collection_name].update_many(
                {f'{path}.status': 'processing', f'{path}.processing_owner': owner},
                {
                    '$set': {f'{path}.status': 'pending', f'{path}.updated_at': now},
                    '$unset': {f'{path}.processing_owner': '', f'{path}.processing_started_at': ''},
                },
            )
    _upload_cache_collection().update_many(
        {'status': 'processing', 'processing_owner': owner},
        {
            '$set': {'status': 'pending', 'updated_at': now},
            '$unset': {'processing_owner': '', 'processing_started_at': ''},
        },
    )


def _release_processing_task(task, owner, config=None, channel=None):
    _update_task_entry(
        task,
        owner,
        {'status': 'pending', 'updated_at': _now()},
        ['processing_owner', 'processing_started_at', 'error'],
    )
    if config is not None:
        _publish(task, config['RABBITMQ_BACKGROUND_PRIORITY'], config, channel)


def _shutdown_worker(owner, provider, config, channel, active_task=None, active_method=None):
    if active_task is not None:
        try:
            _release_processing_task(active_task, owner, config, channel)
        except Exception:
            pass
    _reset_processing_for_owner(owner)
    if active_method is not None and channel is not None:
        try:
            channel.basic_ack(active_method.delivery_tag)
        except Exception:
            pass
    if provider is not None:
        try:
            provider.delete_room()
        except Exception:
            pass


def _consume(config, worker_number):
    owner = f'{uuid.uuid4()}:{worker_number}'
    while not STOP_EVENT.is_set():
        connection = None
        provider = None
        channel = None
        active_task = None
        active_method = None
        try:
            connection = pika.BlockingConnection(pika.URLParameters(config['RABBITMQ_URL']))
            channel = connection.channel()
            _queue_declare(channel, config)
            channel.basic_qos(prefetch_count=1)
            provider = CompanyAIProvider(config)
            provider.create_room()
            for method, _, body in channel.consume(
                config['RABBITMQ_QUEUE_NAME'],
                inactivity_timeout=1,
            ):
                if STOP_EVENT.is_set():
                    break
                if method is None:
                    continue
                task = json_util.loads(body.decode('utf-8'))
                claimed = _claim_task(task, owner, config)
                if claimed is None:
                    channel.basic_ack(method.delivery_tag)
                    continue
                active_task = task
                active_method = method
                if STOP_EVENT.is_set():
                    break
                try:
                    details = _task_details(task, config)
                    if summary_content_hash(details, task['language'], config) != task['content_hash']:
                        raise ValueError('Source details changed while the task was queued.')
                    result, _ = generate_item_data(
                        provider,
                        details,
                        claimed['source_key'],
                        task['language'],
                        config['REPORT_ITEM_JSON_RETRIES'],
                    )
                    _complete_task(task, owner, result)
                    # region agent log
                    highlight = (result or {}).get('highlight') or {}
                    _debug_log(
                        'H3',
                        'company_ai_preprocessor._consume',
                        'item_completed',
                        {
                            'language': task.get('language'),
                            'title': (highlight.get('title') or '')[:80],
                            'severity': (highlight.get('severity') or '')[:40],
                            'title_mojibake': _looks_like_utf8_mojibake(highlight.get('title') or ''),
                            'has_cjk': bool(
                                re.search(
                                    r'[\u4e00-\u9fff]',
                                    (highlight.get('title') or '') + (highlight.get('summary') or ''),
                                )
                            ),
                        },
                    )
                    # endregion
                    _refresh_provider_room(provider)
                except Exception as exc:
                    _requeue_task(task, owner, exc, config, channel, claimed)
                active_task = None
                active_method = None
                channel.basic_ack(method.delivery_tag)
        except Exception as exc:
            print(f'Company AI worker {worker_number} reconnecting after error: {exc}', flush=True)
            STOP_EVENT.wait(5)
        finally:
            _shutdown_worker(owner, provider, config, channel, active_task, active_method)
            if connection is not None and connection.is_open:
                connection.close()


def _scan_loop(config):
    while not STOP_EVENT.is_set():
        try:
            queued = scan_unprocessed(config)
            print(f'Company AI scan queued {queued} summaries.', flush=True)
        except (PyMongoError, pika.exceptions.AMQPError, ValueError) as exc:
            print(f'Company AI scan failed: {exc}', flush=True)
        STOP_EVENT.wait(config['COMPANY_AI_SCAN_INTERVAL_SECONDS'])


def run_worker(config):
    ensure_cache_indexes()
    threads = [threading.Thread(target=_scan_loop, args=(config,), daemon=True)]
    threads.extend(
        threading.Thread(target=_consume, args=(config, number), daemon=True)
        for number in range(config['COMPANY_AI_PARALLEL_CHATS'])
    )
    for thread in threads:
        thread.start()
    while not STOP_EVENT.wait(1):
        pass
    for thread in threads:
        thread.join(timeout=10)


def main():
    parser = argparse.ArgumentParser(description='Run RabbitMQ Company AI preprocessing workers.')
    parser.parse_args()
    signal.signal(signal.SIGINT, lambda *_: STOP_EVENT.set())
    signal.signal(signal.SIGTERM, lambda *_: STOP_EVENT.set())
    config = configure_application(BASE_DIR)
    run_worker(config)


if __name__ == '__main__':
    main()
