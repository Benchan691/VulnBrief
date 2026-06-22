import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from .pipeline_collections import collection
from .tavily_client import TavilyClient


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
        'source_api': 'tavily',
        'retrieved_at': _now_iso(),
        'content_hash': _content_hash(url, title, snippet, page_content),
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
    for _ in range(max_retries + 1):
        attempts += 1
        try:
            return task, client.search(task['query']), attempts
        except Exception as exc:
            last_error = exc
    raise SearchTaskError(task, attempts, last_error)


def execute_pending_search_tasks(web_database, run_id, config, client=None):
    tasks_collection = collection(web_database, 'search_enrichment_tasks')
    results_collection = collection(web_database, 'search_enrichment_results')
    tasks = list(tasks_collection.find({'run_id': run_id, 'status': 'pending'}))
    if not tasks:
        return 0

    client = client or TavilyClient(
        config.get('TAVILY_API_KEY'),
        config.get('TAVILY_SEARCH_DEPTH', 'basic'),
        config.get('TAVILY_MAX_RESULTS', 5),
        config.get('TAVILY_REQUEST_TIMEOUT_SECONDS', 30),
    )
    concurrency = max(1, int(config.get('TAVILY_MAX_CONCURRENT_REQUESTS', 4)))
    max_retries = max(0, int(config.get('TAVILY_MAX_RETRIES', 1)))
    completed = 0
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(_execute_one, client, task, max_retries) for task in tasks]
        for future in as_completed(futures):
            task = None
            try:
                task, results, attempts = future.result()
                documents = [
                    _result_document(task, result)
                    for result in results
                    if (result.get('url') or '').strip()
                ]
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
                completed += 1
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
