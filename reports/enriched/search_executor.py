import hashlib
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from .pipeline_collections import collection
from .search_results_cache import (
    lookup_cached_results,
    store_cached_results,
)
from .tavily_client import build_search_client

logger = logging.getLogger(__name__)


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _content_hash(*parts):
    payload = json.dumps(parts, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def _result_document(task, result):
    url = (result.get('url') or '').strip()
    title = (result.get('title') or '').strip()
    snippet = (result.get('content') or result.get('snippet') or '').strip()
    page_content = (result.get('raw_content') or result.get('page_content') or snippet).strip()
    return {
        'run_id': task['run_id'],
        'task_id': task.get('_id'),
        'candidate_id': task['candidate_id'],
        'cve_id': task['cve_id'],
        'task_type': task['task_type'],
        'query': task['query'],
        'url': url,
        'title': title,
        'snippet': snippet,
        'page_content': page_content[:60000],
        'score': result.get('score'),
        'source_api': result.get('source_api') or 'tavily',
        'retrieved_at': _now_iso(),
        'content_hash': result.get('content_hash') or _content_hash(url, title, snippet, page_content),
    }


class SearchTaskError(RuntimeError):
    def __init__(self, task, attempts, error):
        super().__init__(str(error))
        self.task = task
        self.attempts = attempts
        self.error = error


def _execute_one(client, task, max_retries):
    attempts = 0
    last_error = None
    include_domains = task.get('include_domains') or None
    for _ in range(max_retries + 1):
        attempts += 1
        try:
            return task, client.search(task['query'], include_domains=include_domains), attempts
        except Exception as exc:
            last_error = exc
    raise SearchTaskError(task, attempts, last_error)


def _complete_task(tasks_collection, results_collection, task, documents, attempts):
    if documents:
        results_collection.insert_many(documents)
    tasks_collection.update_one(
        {'_id': task['_id']},
        {'$set': {
            'status': 'completed',
            'result_count': len(documents),
            'updated_at': _now_iso(),
        }, '$inc': {'attempts': attempts}},
    )


def execute_pending_search_tasks(web_database, run_id, config, client=None, progress_callback=None):
    tasks_collection = collection(web_database, 'search_enrichment_tasks')
    results_collection = collection(web_database, 'search_enrichment_results')
    tasks = list(tasks_collection.find({'run_id': run_id, 'status': 'pending'}))
    if not tasks:
        return 0

    cache_version = '1'
    client = client or build_search_client(config)
    provider = getattr(client, 'provider', type(client).__name__)
    concurrency = max(1, int(config.get('TAVILY_MAX_CONCURRENT_REQUESTS', 4)))
    max_retries = max(0, int(config.get('TAVILY_MAX_RETRIES', 1)))
    total_tasks = len(tasks)
    completed = 0
    cache_hits = 0
    pending_tavily = []
    logger.info(
        'enriched search starting run=%s provider=%s tasks=%d concurrency=%d',
        run_id,
        provider,
        total_tasks,
        concurrency,
    )

    for task in tasks:
        cached_payloads = lookup_cached_results(web_database, task, cache_version)
        if cached_payloads is not None:
            cache_hits += 1
            documents = [
                _result_document(task, payload)
                for payload in cached_payloads
                if (payload.get('url') or '').strip()
            ]
            _complete_task(tasks_collection, results_collection, task, documents, 0)
            completed += 1
            logger.info(
                'enriched search cache hit cve=%s task_type=%s results=%d',
                task.get('cve_id'),
                task.get('task_type'),
                len(documents),
            )
            if progress_callback is not None:
                progress_callback(
                    completed,
                    total_tasks,
                    f'Reused cached search {completed}/{total_tasks} for {task.get("cve_id")}',
                )
            continue
        pending_tavily.append(task)

    if cache_hits:
        logger.info(
            'enriched search cache hits run=%s hits=%d/%d',
            run_id,
            cache_hits,
            total_tasks,
        )

    if not pending_tavily:
        return completed

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(_execute_one, client, task, max_retries) for task in pending_tavily]
        for future in as_completed(futures):
            task = None
            try:
                task, results, attempts = future.result()
                documents = [
                    _result_document(task, result)
                    for result in results
                    if (result.get('url') or '').strip()
                ]
                _complete_task(tasks_collection, results_collection, task, documents, attempts)
                if documents:
                    store_cached_results(web_database, task, documents, cache_version)
                completed += 1
                logger.info(
                    'enriched search completed cve=%s task_type=%s results=%d attempts=%d',
                    task.get('cve_id'),
                    task.get('task_type'),
                    len(documents),
                    attempts,
                )
                if progress_callback is not None:
                    progress_callback(
                        completed,
                        total_tasks,
                        f'Completed search {completed}/{total_tasks} for {task.get("cve_id")}',
                    )
            except SearchTaskError as exc:
                task = exc.task
                tasks_collection.update_one(
                    {'_id': task['_id']},
                    {'$set': {
                        'status': 'failed',
                        'error': str(exc.error),
                        'updated_at': _now_iso(),
                    }, '$inc': {'attempts': exc.attempts}},
                )
            except Exception as exc:
                if task is None:
                    continue
                tasks_collection.update_one(
                    {'_id': task['_id']},
                    {'$set': {
                        'status': 'failed',
                        'error': str(exc),
                        'updated_at': _now_iso(),
                    }, '$inc': {'attempts': 1}},
                )
    return completed
