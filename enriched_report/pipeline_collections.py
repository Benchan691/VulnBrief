COLLECTION_NAMES = (
    'candidate_vulnerability_items',
    'search_enrichment_tasks',
    'search_enrichment_results',
    'filtered_enrichment_results',
    'source_evidence_cards',
    'vulnerability_cards',
    'report_metrics',
)

EVIDENCE_CACHE_COLLECTION = 'source_evidence_cache'


def collection(database, name):
    if name not in COLLECTION_NAMES:
        raise ValueError(f'Unknown enriched report collection: {name}')
    return database[name]


def evidence_cache_collection(database):
    return database[EVIDENCE_CACHE_COLLECTION]


def ensure_indexes(database):
    candidates = collection(database, 'candidate_vulnerability_items')
    candidates.create_index([('run_id', 1), ('cve_id', 1)], name='run_cve')
    candidates.create_index([('run_id', 1), ('content_hash', 1)], name='run_content_hash')

    tasks = collection(database, 'search_enrichment_tasks')
    tasks.create_index([('run_id', 1), ('status', 1)], name='run_status')
    tasks.create_index([('run_id', 1), ('cve_id', 1), ('task_type', 1)], name='run_cve_task')

    results = collection(database, 'search_enrichment_results')
    results.create_index([('run_id', 1), ('cve_id', 1), ('task_type', 1)], name='run_cve_task')
    results.create_index([('run_id', 1), ('content_hash', 1)], name='run_content_hash')

    filtered = collection(database, 'filtered_enrichment_results')
    filtered.create_index([('run_id', 1), ('cve_id', 1), ('task_type', 1)], name='run_cve_task')
    filtered.create_index([('run_id', 1), ('content_hash', 1)], name='run_content_hash')

    evidence = collection(database, 'source_evidence_cards')
    evidence.create_index([('run_id', 1), ('cve_id', 1), ('task_type', 1)], name='run_cve_task')
    evidence.create_index([('run_id', 1), ('source_url', 1)], name='run_source_url')

    cards = collection(database, 'vulnerability_cards')
    cards.create_index([('run_id', 1), ('cve_id', 1)], name='run_cve')
    cards.create_index([('run_id', 1), ('priority_score', -1)], name='run_priority')

    metrics = collection(database, 'report_metrics')
    metrics.create_index([('run_id', 1)], name='run_id')

    cache = evidence_cache_collection(database)
    cache.create_index([('cache_key', 1)], name='cache_key', unique=True)
    cache.create_index([('cve_id', 1), ('task_type', 1), ('source_url', 1)], name='cve_task_url')
    cache.create_index([('cache_version', 1), ('updated_at', -1)], name='cache_version_updated')


def purge_run_artifacts(database, run_id):
    for name in COLLECTION_NAMES:
        collection(database, name).delete_many({'run_id': run_id})

