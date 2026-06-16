import argparse
import hashlib
import json
import signal
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import pika
from bson import json_util
from pymongo import ReturnDocument
from pymongo.errors import PyMongoError

from bootstrap import BASE_DIR, configure_worker
from mongo import get_config, get_vulnerabilities_database
from preprocessor_log import log_error, log_info
from preprocessing_priorities import (
    resolve_preprocessing_priority,
    scan_projection,
    sorted_scan_collections,
)
from report_harness import (
    CompanyAIProvider,
    CompanyAILoginLimitExceeded,
    REPORT_LANGUAGES,
    compact_details,
    generate_final_data,
    generate_item_data,
)


STOP_EVENT = threading.Event()
NO_PROVIDER_LOG_INTERVAL_SECONDS = 30
_LAST_NO_PROVIDER_LOG_AT = 0


def _now():
    return datetime.now(timezone.utc)


def _shared_task_collection():
    from mongo import get_config
    return get_vulnerabilities_database()[get_config()['AI_TASK_COLLECTION']]


def ensure_cache_indexes():
    collection = _shared_task_collection()
    collection.create_index(
        [('task_type', 1), ('source_key', 1), ('language', 1)],
        unique=True,
        name='task_source_language',
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
        'cache_version': config['PREPROCESSING_CACHE_VERSION'],
    }
    payload = json.dumps(identity, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def _queue_declare(channel, config):
    return channel.queue_declare(
        queue=config['RABBITMQ_INTAKE_QUEUE'],
        durable=True,
        arguments={'x-max-priority': config['RABBITMQ_MAX_PRIORITY']},
    )


def _company_queue_declare(channel, config):
    channel.queue_declare(
        queue=config['RABBITMQ_COMPANY_QUEUE'],
        durable=True,
        arguments={'x-max-priority': config['RABBITMQ_MAX_PRIORITY']},
    )


def _gpu_queue_declare(channel, config):
    return channel.queue_declare(
        queue=config['RABBITMQ_GPU_QUEUE'],
        durable=True,
        arguments={'x-max-priority': config['RABBITMQ_MAX_PRIORITY']},
    )


def _routed_queue_declare(channel, config):
    _company_queue_declare(channel, config)
    if config['GPU_ENABLED']:
        _gpu_queue_declare(channel, config)


def _task_target(task):
    if task.get('source_collection') and task.get('source_id') is not None:
        return f"{task['source_collection']}/{task['source_id']}"
    if task.get('task_id') is not None:
        return f"shared/{task['task_id']}"
    return 'unknown'


def _queue_status(config):
    connection = pika.BlockingConnection(pika.URLParameters(config['RABBITMQ_URL']))
    try:
        channel = connection.channel()
        intake_status = _queue_declare(channel, config)
        company_status = channel.queue_declare(
            queue=config['RABBITMQ_COMPANY_QUEUE'],
            durable=True,
            arguments={'x-max-priority': config['RABBITMQ_MAX_PRIORITY']},
        )
        counts = {
            config['RABBITMQ_INTAKE_QUEUE']: intake_status.method.message_count,
            config['RABBITMQ_COMPANY_QUEUE']: company_status.method.message_count,
        }
        if config['GPU_ENABLED']:
            gpu_status = _gpu_queue_declare(channel, config)
            counts[config['RABBITMQ_GPU_QUEUE']] = gpu_status.method.message_count
        else:
            counts[config['RABBITMQ_GPU_QUEUE']] = 0
        return counts
    finally:
        connection.close()


def _role_worker_counts(config, role):
    scan_count = 1 if role in {'all', 'scanner'} and (
        role == 'scanner' or config['COMPANY_AI_ENABLED'] or config['GPU_ENABLED']
    ) else 0
    router_count = 1 if role in {'all', 'router'} and (
        role == 'router' or config['COMPANY_AI_ENABLED'] or config['GPU_ENABLED']
    ) else 0
    company_count = (
        config['COMPANY_AI_PARALLEL_CHATS']
        if role in {'all', 'company-worker'} and config['COMPANY_AI_ENABLED']
        else 0
    )
    return scan_count, router_count, company_count


def _startup_worker(config, role='all'):
    scan_count, router_count, company_count = _role_worker_counts(config, role)

    log_info(
        'Starting Company AI preprocessor',
        role=role,
        parallel_chats=config['COMPANY_AI_PARALLEL_CHATS'],
        scan_interval=f"{config['COMPANY_AI_SCAN_INTERVAL_SECONDS']}s",
        company_ai=config['COMPANY_AI_ENABLED'],
        gpu=config['GPU_ENABLED'],
        priority_collections=len((config.get('PREPROCESSING_PRIORITIES') or {}).get('collections', {})),
        priority_boost_fields=list((config.get('PREPROCESSING_PRIORITIES') or {}).get('field_boosts', {})),
    )

    if company_count:
        provider = CompanyAIProvider(config)
        session_mode = provider.ensure_session()
        log_info(
            'Company AI login successful',
            username=config['COMPANY_AI_USERNAME'],
            mode=session_mode,
        )

    try:
        counts = _queue_status(config)
        log_info(
            'Connected to RabbitMQ',
            intake=counts[config['RABBITMQ_INTAKE_QUEUE']],
            gpu=counts[config['RABBITMQ_GPU_QUEUE']],
            company=counts[config['RABBITMQ_COMPANY_QUEUE']],
        )
    except pika.exceptions.AMQPError as exc:
        log_error('Failed to connect to RabbitMQ', error=str(exc))
        raise

    log_info(
        'Workers started',
        scan=scan_count,
        router=router_count,
        company_ai=company_count,
    )


def _clear_queues(config, queue_names=None):
    connection = pika.BlockingConnection(pika.URLParameters(config['RABBITMQ_URL']))
    try:
        channel = connection.channel()
        _queue_declare(channel, config)
        _routed_queue_declare(channel, config)
        default_queues = [config['RABBITMQ_INTAKE_QUEUE'], config['RABBITMQ_COMPANY_QUEUE']]
        if config['GPU_ENABLED']:
            default_queues.insert(1, config['RABBITMQ_GPU_QUEUE'])
        for queue_name in queue_names or default_queues:
            channel.queue_purge(queue=queue_name)
    finally:
        connection.close()


def _try_clear_queues(config, queue_names=None):
    try:
        _clear_queues(config, queue_names)
        return True
    except pika.exceptions.AMQPError as exc:
        log_error('Unable to clear preprocessing queues', error=str(exc))
        return False


def _publisher_channel(connection, config):
    channel = connection.channel()
    _queue_declare(channel, config)
    channel.confirm_delivery()
    return channel


def _publish(task, priority, config, channel=None):
    return _publish_to_queue(task, priority, config, config['RABBITMQ_INTAKE_QUEUE'], channel)


def _publish_to_queue(task, priority, config, queue_name, channel=None):
    connection = None
    if channel is None:
        connection = pika.BlockingConnection(pika.URLParameters(config['RABBITMQ_URL']))
        channel = connection.channel()
        if queue_name == config['RABBITMQ_INTAKE_QUEUE']:
            _queue_declare(channel, config)
        elif queue_name == config['RABBITMQ_COMPANY_QUEUE']:
            _company_queue_declare(channel, config)
        elif queue_name == config['RABBITMQ_GPU_QUEUE']:
            _gpu_queue_declare(channel, config)
        else:
            _company_queue_declare(channel, config)
        channel.confirm_delivery()
    try:
        channel.basic_publish(
            exchange='',
            routing_key=queue_name,
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
            'task_type': 'item',
            'source_collection': source_collection,
            'source_id': source_id,
            'language': language,
            'content_hash': content_hash,
        }
    else:
        collection = _shared_task_collection()
        existing = collection.find_one({
            'task_type': 'item', 'source_key': source_key, 'language': language,
        })
        reference = {
            'storage': 'shared',
            'task_id': existing['_id'] if existing else None,
            'task_type': 'item',
            'language': language,
            'content_hash': content_hash,
        }
    if existing and existing.get('content_hash') == content_hash:
        if existing.get('status') in {'completed', 'processing'}:
            return reference, False
        if existing.get('status') in {'pending', 'failed'}:
            _publish(reference, priority, config, channel)
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
        document = _shared_task_collection().find_one_and_update(
            {'task_type': 'item', 'source_key': source_key, 'language': language},
            {'$set': {**entry, 'task_type': 'item', 'payload': compacted}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        reference['task_id'] = document['_id']
    _publish(reference, priority, config, channel)
    return reference, True


def scan_unprocessed(config):
    ensure_cache_indexes()
    database = get_vulnerabilities_database()
    queued = 0
    projection = scan_projection(config)
    collection_names = []
    for metadata in database.list_collections(filter={'type': 'collection'}):
        collection_name = metadata['name']
        if collection_name.startswith('system.') or collection_name == config['AI_TASK_COLLECTION']:
            continue
        collection_names.append(collection_name)
    connection = pika.BlockingConnection(pika.URLParameters(config['RABBITMQ_URL']))
    try:
        channel = _publisher_channel(connection, config)
        for collection_name in sorted_scan_collections(collection_names, config):
            for document in database[collection_name].find({}, projection):
                details = document.get('details')
                if not isinstance(details, dict):
                    continue
                priority = resolve_preprocessing_priority(collection_name, document, config)
                for language in REPORT_LANGUAGES:
                    _, published = enqueue_summary(
                        details,
                        language,
                        config,
                        priority,
                        collection_name,
                        document['_id'],
                        channel,
                    )
                    queued += int(published)
        stale_before = _now() - timedelta(seconds=config['COMPANY_AI_STALE_PROCESSING_SECONDS'])
        for task in _shared_task_collection().find({
            '$or': [
                {'status': {'$in': ['pending', 'failed']}},
                {'status': 'processing', 'processing_started_at': {'$lte': stale_before}},
            ],
        }):
            reference = {
                'storage': 'shared',
                'task_id': task['_id'],
                'task_type': task.get('task_type', 'item'),
                'language': task['language'],
                'content_hash': task['content_hash'],
            }
            _publish(reference, config['RABBITMQ_BACKGROUND_PRIORITY'], config, channel)
            queued += 1
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


def enqueue_final_summary(item_results, language, config):
    payload = compact_details({'item_results': item_results}, config)
    source_key = cache_source_key(details={'task_type': 'final', **payload})
    content_hash = summary_content_hash(payload, language, config)
    collection = _shared_task_collection()
    existing = collection.find_one({
        'task_type': 'final', 'source_key': source_key, 'language': language,
    })
    reference = {
        'storage': 'shared',
        'task_id': existing['_id'] if existing else None,
        'task_type': 'final',
        'language': language,
        'content_hash': content_hash,
    }
    if existing and existing.get('content_hash') == content_hash:
        if existing.get('status') in {'completed', 'processing'}:
            return reference
    now = _now()
    document = collection.find_one_and_update(
        {'task_type': 'final', 'source_key': source_key, 'language': language},
        {'$set': {
            'task_type': 'final',
            'source_key': source_key,
            'language': language,
            'content_hash': content_hash,
            'payload': payload,
            'status': 'pending',
            'attempts': existing.get('attempts', 0) if existing else 0,
            'created_at': existing.get('created_at', now) if existing else now,
            'updated_at': now,
        }},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    reference['task_id'] = document['_id']
    _publish(reference, config['RABBITMQ_REPORT_PRIORITY'], config)
    return reference


def _reference_result(reference):
    if reference['storage'] == 'source':
        document = _source_collection(reference['source_collection']).find_one(
            {'_id': reference['source_id']},
            {_language_path(reference['language']): 1},
        )
        entry = ((document or {}).get('html_json') or {}).get(reference['language'], {})
    else:
        entry = _shared_task_collection().find_one({'_id': reference['task_id']}) or {}
    return entry.get('result') if entry.get('status') == 'completed' else None


def wait_for_summaries(references, timeout_seconds, should_continue=None):
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if should_continue is not None and not should_continue():
            break
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
    document = _shared_task_collection().find_one(
        {'_id': task['task_id'], 'content_hash': task['content_hash']},
        {'payload': 1},
    )
    if document is None or not isinstance(document.get('payload'), dict):
        raise ValueError('Shared AI task payload no longer exists.')
    return document['payload']


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
    return _shared_task_collection().find_one_and_update(
        {
            '_id': task['task_id'],
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


def _complete_task(task, owner, result, provider='company_ai'):
    values = {
        'status': 'completed',
        'result': result,
        'completed_at': _now(),
        'updated_at': _now(),
        'provider': provider,
    }
    _update_task_entry(task, owner, values, ['processing_owner', 'processing_started_at', 'error'])
    log_info(
        'Stored AI JSON',
        target=_task_target(task),
        storage=task.get('storage'),
        task_type=task.get('task_type', 'item'),
        language=task['language'],
        provider=provider,
    )


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
    task_id = reference.get('task_id')
    if not task_id:
        return False
    document = _shared_task_collection().find_one({'_id': task_id}) or {}
    if document.get('content_hash') != content_hash:
        return False
    if document.get('status') == 'completed':
        return True
    _shared_task_collection().update_one(
        {'_id': task_id, 'content_hash': content_hash},
        {
            '$set': values,
            '$unset': {key: '' for key in unset_fields},
        },
    )
    return True


def _requeue_task(task, owner, error, config, channel, claimed):
    max_attempts = config['COMPANY_AI_MAX_TASK_ATTEMPTS']
    if (claimed or {}).get('attempts', 0) >= max_attempts:
        _fail_task(task, owner, error)
        return
    _update_task_entry(
        task,
        owner,
        {'status': 'pending', 'error': str(error), 'updated_at': _now()},
        ['processing_owner', 'processing_started_at'],
    )
    if config['COMPANY_AI_ENABLED']:
        _publish_to_queue(
            task,
            config['RABBITMQ_BACKGROUND_PRIORITY'],
            config,
            config['RABBITMQ_COMPANY_QUEUE'],
            channel,
        )


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
        _shared_task_collection().update_one(
            {'_id': task['task_id'], 'processing_owner': owner},
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
        if collection_name.startswith('system.') or collection_name == get_config()['AI_TASK_COLLECTION']:
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
    _shared_task_collection().update_many(
        {'status': 'processing', 'processing_owner': owner},
        {
            '$set': {'status': 'pending', 'updated_at': now},
            '$unset': {'processing_owner': '', 'processing_started_at': ''},
        },
    )


def _reset_all_processing(config):
    now = _now()
    stale_before = now - timedelta(seconds=config['COMPANY_AI_STALE_PROCESSING_SECONDS'])
    database = get_vulnerabilities_database()
    for metadata in database.list_collections(filter={'type': 'collection'}):
        collection_name = metadata['name']
        if collection_name.startswith('system.') or collection_name == get_config()['AI_TASK_COLLECTION']:
            continue
        for language in REPORT_LANGUAGES:
            path = _language_path(language)
            database[collection_name].update_many(
                {
                    f'{path}.status': 'processing',
                    f'{path}.processing_started_at': {'$lte': stale_before},
                },
                {
                    '$set': {f'{path}.status': 'pending', f'{path}.updated_at': now},
                    '$unset': {f'{path}.processing_owner': '', f'{path}.processing_started_at': ''},
                },
            )
    _shared_task_collection().update_many(
        {'status': 'processing', 'processing_started_at': {'$lte': stale_before}},
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
        queue_name = _route_destination(task, config, channel)
        if queue_name:
            _publish_to_queue(
                task,
                config['RABBITMQ_BACKGROUND_PRIORITY'],
                config,
                queue_name,
                channel,
            )


def _delete_company_chat(provider, *, worker=None, target=None):
    if provider is None or not getattr(provider, 'conversation_id', None):
        return
    conversation_id = provider.conversation_id
    try:
        provider.delete_room()
        log_info(
            'Company AI chat deleted',
            worker=worker,
            conversation_id=conversation_id,
            target=target,
        )
    except Exception as exc:
        log_error(
            'Company AI chat delete failed',
            worker=worker,
            conversation_id=conversation_id,
            target=target,
            error=str(exc),
        )


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
        _delete_company_chat(provider)


def _process_company_task(task, claimed, owner, config, worker_number):
    provider = CompanyAIProvider(config)
    task_type = task.get('task_type', 'item')
    target = _task_target(task)
    started = time.monotonic()
    try:
        log_info(
            'Processing task',
            worker=worker_number,
            task_type=task_type,
            language=task['language'],
            target=target,
        )
        session_mode = provider.ensure_session()
        log_info(
            'Company AI session ready',
            worker=worker_number,
            mode=session_mode,
            target=target,
        )
        if task_type == 'final':
            conversation_id = provider.create_room(prime_prompt='')
            primed = False
        else:
            conversation_id = provider.create_room()
            primed = True
        log_info(
            'Company AI room created',
            worker=worker_number,
            conversation_id=conversation_id,
            task_type=task_type,
            primed=primed,
            target=target,
        )
        details = _task_details(task, config)
        if summary_content_hash(details, task['language'], config) != task['content_hash']:
            raise ValueError('Source details changed while the task was queued.')
        if task_type == 'final':
            result, _ = generate_final_data(
                provider,
                details['item_results'],
                task['language'],
                config['REPORT_FINAL_JSON_RETRIES'],
                config,
            )
        else:
            result, _ = generate_item_data(
                provider,
                details,
                claimed['source_key'],
                task['language'],
                config['REPORT_ITEM_JSON_RETRIES'],
            )
        _complete_task(task, owner, result, provider='company_ai')
        log_info(
            'Task completed',
            worker=worker_number,
            task_type=task_type,
            language=task['language'],
            target=target,
            seconds=round(time.monotonic() - started, 1),
        )
        return result
    except CompanyAILoginLimitExceeded as exc:
        log_error(
            'Company AI login limit exceeded; stopping preprocessor',
            failures=config['COMPANY_AI_LOGIN_MAX_FAILURES'],
            error=str(exc),
        )
        STOP_EVENT.set()
        raise
    finally:
        _delete_company_chat(provider, worker=worker_number, target=target)


def _consume(config, worker_number):
    owner = f'{uuid.uuid4()}:{worker_number}'
    while not STOP_EVENT.is_set():
        connection = None
        channel = None
        active_task = None
        active_method = None
        try:
            connection = pika.BlockingConnection(pika.URLParameters(config['RABBITMQ_URL']))
            channel = connection.channel()
            company_status = channel.queue_declare(
                queue=config['RABBITMQ_COMPANY_QUEUE'],
                durable=True,
                arguments={'x-max-priority': config['RABBITMQ_MAX_PRIORITY']},
            )
            log_info(
                'Company AI worker connected',
                worker=worker_number,
                queue=config['RABBITMQ_COMPANY_QUEUE'],
                messages=company_status.method.message_count,
            )
            channel.basic_qos(prefetch_count=1)
            for method, _, body in channel.consume(
                config['RABBITMQ_COMPANY_QUEUE'],
                inactivity_timeout=1,
            ):
                if STOP_EVENT.is_set():
                    break
                if method is None:
                    continue
                task = json_util.loads(body.decode('utf-8'))
                claimed = _claim_task(task, owner, config)
                if claimed is None:
                    log_info(
                        'Skipped stale task',
                        worker=worker_number,
                        target=_task_target(task),
                    )
                    channel.basic_ack(method.delivery_tag)
                    continue
                active_task = task
                active_method = method
                if STOP_EVENT.is_set():
                    break
                try:
                    _process_company_task(task, claimed, owner, config, worker_number)
                except CompanyAILoginLimitExceeded:
                    active_task = None
                    active_method = None
                    channel.basic_ack(method.delivery_tag)
                    break
                except Exception as exc:
                    log_error(
                        'Task failed',
                        worker=worker_number,
                        target=_task_target(task),
                        error=str(exc),
                    )
                    _requeue_task(task, owner, exc, config, channel, claimed)
                active_task = None
                active_method = None
                channel.basic_ack(method.delivery_tag)
        except Exception as exc:
            log_error(
                'Company AI worker reconnecting after error',
                worker=worker_number,
                error=str(exc),
            )
            STOP_EVENT.wait(5)
        finally:
            _shutdown_worker(owner, None, config, channel, active_task, active_method)
            if connection is not None and connection.is_open:
                connection.close()


def _scan_loop(config):
    while not STOP_EVENT.is_set():
        try:
            queued = scan_unprocessed(config)
            log_info('Scan complete', published=queued)
        except (PyMongoError, pika.exceptions.AMQPError, ValueError) as exc:
            log_error('Scan failed', error=str(exc))
        STOP_EVENT.wait(config['COMPANY_AI_SCAN_INTERVAL_SECONDS'])


def _route_destination(task, config, channel):
    company_enabled = config['COMPANY_AI_ENABLED']
    gpu_enabled = config['GPU_ENABLED']
    if gpu_enabled:
        status = _gpu_queue_declare(channel, config)
        if not company_enabled or status.method.message_count < config['GPU_QUEUE_BACKLOG_LIMIT']:
            return config['RABBITMQ_GPU_QUEUE']
    if company_enabled:
        return config['RABBITMQ_COMPANY_QUEUE']
    return None


def _route_task(task, priority, config, channel):
    queue_name = _route_destination(task, config, channel)
    if queue_name is None:
        return None
    _publish_to_queue(task, priority, config, queue_name, channel)
    return queue_name


def _nack_unroutable_task(channel, method, task):
    global _LAST_NO_PROVIDER_LOG_AT
    now = time.monotonic()
    if now - _LAST_NO_PROVIDER_LOG_AT >= NO_PROVIDER_LOG_INTERVAL_SECONDS:
        log_error(
            'No preprocessing provider enabled; leaving intake task queued',
            target=_task_target(task),
        )
        _LAST_NO_PROVIDER_LOG_AT = now
    channel.basic_nack(method.delivery_tag, requeue=True)


def _route_loop(config):
    while not STOP_EVENT.is_set():
        connection = None
        try:
            connection = pika.BlockingConnection(pika.URLParameters(config['RABBITMQ_URL']))
            channel = connection.channel()
            intake_status = _queue_declare(channel, config)
            _company_queue_declare(channel, config)
            log_info(
                'Router connected to intake queue',
                queue=config['RABBITMQ_INTAKE_QUEUE'],
                messages=intake_status.method.message_count,
            )
            channel.confirm_delivery()
            channel.basic_qos(prefetch_count=1)
            for method, properties, body in channel.consume(
                config['RABBITMQ_INTAKE_QUEUE'],
                inactivity_timeout=1,
            ):
                if STOP_EVENT.is_set():
                    break
                if method is None:
                    continue
                task = json_util.loads(body.decode('utf-8'))
                priority = getattr(properties, 'priority', None)
                if priority is None:
                    priority = config['RABBITMQ_BACKGROUND_PRIORITY']
                queue_name = _route_task(task, priority, config, channel)
                if queue_name is None:
                    _nack_unroutable_task(channel, method, task)
                    STOP_EVENT.wait(5)
                    continue
                channel.basic_ack(method.delivery_tag)
        except Exception as exc:
            log_error('Preprocessing router reconnecting after error', error=str(exc))
            STOP_EVENT.wait(5)
        finally:
            if connection is not None and connection.is_open:
                connection.close()


def _run_threads(threads):
    try:
        for thread in threads:
            thread.start()
        while not STOP_EVENT.wait(1):
            pass
        for thread in threads:
            thread.join()
    finally:
        pass


def run_worker(config, role='all'):
    STOP_EVENT.clear()
    threads = []
    if role not in {'all', 'scanner', 'router', 'company-worker'}:
        raise ValueError(f'Unsupported preprocessor role: {role}')
    if role != 'router':
        ensure_cache_indexes()
        _reset_all_processing(config)
    if role == 'scanner':
        threads.append(threading.Thread(target=_scan_loop, args=(config,), daemon=True))
    elif role == 'router':
        threads.append(threading.Thread(target=_route_loop, args=(config,), daemon=True))
    elif role == 'all':
        if config['COMPANY_AI_ENABLED'] or config['GPU_ENABLED']:
            threads.extend([
                threading.Thread(target=_scan_loop, args=(config,), daemon=True),
                threading.Thread(target=_route_loop, args=(config,), daemon=True),
            ])
    if role in {'all', 'company-worker'} and config['COMPANY_AI_ENABLED']:
        threads.extend([
            threading.Thread(target=_consume, args=(config, number), daemon=True)
            for number in range(config['COMPANY_AI_PARALLEL_CHATS'])
        ])
    if not threads:
        log_info('No workers enabled for preprocessor role; waiting for shutdown', role=role)
    else:
        _startup_worker(config, role)
    try:
        _run_threads(threads)
    finally:
        if role != 'router':
            _reset_all_processing(config)


def main():
    parser = argparse.ArgumentParser(description='Run RabbitMQ Company AI preprocessing workers.')
    parser.add_argument(
        '--purge-queues',
        action='store_true',
        help='Purge intake, GPU, and Company AI queues, then exit.',
    )
    parser.add_argument(
        '--role',
        choices=['all', 'scanner', 'router', 'company-worker'],
        default='all',
        help='Run all workers, or only the scanner, intake router, or Company AI queue worker.',
    )
    args = parser.parse_args()
    signal.signal(signal.SIGINT, lambda *_: STOP_EVENT.set())
    signal.signal(signal.SIGTERM, lambda *_: STOP_EVENT.set())
    config = configure_worker(BASE_DIR)
    if args.purge_queues:
        _clear_queues(config)
        return
    run_worker(config, args.role)


if __name__ == '__main__':
    main()
