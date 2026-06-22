from datetime import datetime, timezone
import logging

from bson import ObjectId

from mongo import get_vulnerabilities_database, get_web_database

from .candidate_loader import load_candidates_from_inputs
from .card_merger import merge_vulnerability_cards
from .evidence_extractor import extract_evidence_cards
from .llama_client import EnrichedLlamaClient
from .pipeline_collections import ensure_indexes
from .report_generator import generate_enriched_report
from .result_ranker import rank_results_for_run
from .scorer import score_cards_and_metrics
from .search_executor import execute_pending_search_tasks
from .search_tasks import write_search_tasks
from .tavily_client import TavilyClient


def _now():
    return datetime.now(timezone.utc)


def _job_collection():
    return get_web_database()['report_jobs']


def _input_collection():
    return get_web_database()['report_job_inputs']


def _stage(job_id, stage, extra=None):
    update = {'pipeline_stage': stage, 'updated_at': _now()}
    if extra:
        update.update(extra)
    _job_collection().update_one({'_id': job_id}, {'$set': update})


def _cancelled(job_id):
    job = _job_collection().find_one({'_id': job_id}, {'status': 1})
    return job is not None and job.get('status') == 'cancelled'


def _require_config(config):
    missing = []
    if not config.get('TAVILY_API_KEY'):
        missing.append('TAVILY_API_KEY')
    if not config.get('ENRICHED_LLM_BASE_URL'):
        missing.append('ENRICHED_LLM_BASE_URL')
    if missing:
        raise ValueError('Missing required enriched_weekly configuration: ' + ', '.join(missing))


def run_enriched_pipeline(app, job_id, tavily_client=None, llama_client=None):
    with app.app_context():
        job_object_id = ObjectId(job_id)
        run_id = str(job_object_id)
        jobs = _job_collection()
        inputs_collection = _input_collection()
        web_database = get_web_database()
        vulnerability_database = get_vulnerabilities_database()
        config = app.config
        try:
            job = jobs.find_one({'_id': job_object_id})
            if job is None or job.get('status') == 'cancelled':
                return
            if job.get('status') not in ('queued', 'running'):
                return
            jobs.update_one(
                {'_id': job_object_id, 'status': {'$in': ['queued', 'running']}},
                {'$set': {
                    'status': 'running',
                    'pipeline_stage': 'starting',
                    'updated_at': _now(),
                    'provider': 'Tavily + llama-server',
                    'model': config.get('ENRICHED_LLM_MODEL') or 'qwen-local',
                }, '$unset': {'html': '', 'html_updated_at': '', 'html_path': ''}},
            )
            _require_config(config)
            ensure_indexes(web_database)
            logger = logging.getLogger(__name__)
            logger.info(
                'enriched pipeline starting job=%s llm_base_url=%s llm_model=%s',
                job_id,
                config.get('ENRICHED_LLM_BASE_URL'),
                config.get('ENRICHED_LLM_MODEL'),
            )

            inputs = list(inputs_collection.find({'job_id': job_object_id}).sort('position', 1))
            if not inputs:
                raise ValueError('At least one cve_review selection is required.')

            if _cancelled(job_object_id):
                return
            _stage(job_object_id, 'loading_candidates')
            candidates = load_candidates_from_inputs(
                run_id,
                vulnerability_database,
                web_database,
                inputs,
                config.get('ENRICHED_VENDOR_DOMAIN_MAP', {}),
            )
            if not candidates:
                raise ValueError('No CVE candidates remained after deduplication.')

            if _cancelled(job_object_id):
                return
            _stage(job_object_id, 'creating_search_tasks', {'processed_count': 0})
            write_search_tasks(web_database, run_id, candidates)

            if _cancelled(job_object_id):
                return
            _stage(job_object_id, 'searching_tavily')
            tavily_client = tavily_client or TavilyClient(
                config.get('TAVILY_API_KEY'),
                config.get('TAVILY_SEARCH_DEPTH', 'basic'),
                config.get('TAVILY_MAX_RESULTS', 5),
                config.get('TAVILY_REQUEST_TIMEOUT_SECONDS', 30),
            )
            execute_pending_search_tasks(web_database, run_id, config, tavily_client)

            if _cancelled(job_object_id):
                return
            _stage(job_object_id, 'ranking_results')
            filtered = rank_results_for_run(
                web_database,
                run_id,
                int(config.get('ENRICHED_RESULTS_PER_TASK', 4)),
            )
            if not filtered:
                raise ValueError('No relevant Tavily enrichment results were found for selected CVEs.')

            if _cancelled(job_object_id):
                return
            _stage(job_object_id, 'extracting_evidence')
            llama_client = llama_client or EnrichedLlamaClient(config)
            evidence_cards = extract_evidence_cards(web_database, run_id, config, llama_client)

            if _cancelled(job_object_id):
                return
            _stage(job_object_id, 'merging_cards')
            vulnerability_cards = merge_vulnerability_cards(web_database, run_id)

            if _cancelled(job_object_id):
                return
            _stage(job_object_id, 'scoring')
            vulnerability_cards, metrics = score_cards_and_metrics(web_database, run_id)

            if _cancelled(job_object_id):
                return
            _stage(job_object_id, 'generating_report')
            report = generate_enriched_report(
                vulnerability_cards,
                metrics,
                evidence_cards,
                config,
                job.get('report_language', 'en'),
                llama_client,
            )

            jobs.update_one(
                {'_id': job_object_id, 'status': {'$ne': 'cancelled'}},
                {'$set': {
                    'status': 'completed',
                    'pipeline_stage': 'completed',
                    'report': report,
                    'processed_count': len(vulnerability_cards),
                    'current_position': len(vulnerability_cards),
                    'source_count': len(candidates),
                    'completed_at': _now(),
                    'updated_at': _now(),
                }},
            )
        except Exception as exc:
            if _cancelled(job_object_id):
                return
            jobs.update_one(
                {'_id': job_object_id, 'status': {'$ne': 'cancelled'}},
                {'$set': {
                    'status': 'failed',
                    'updated_at': _now(),
                    'error': str(exc),
                }},
            )
        finally:
            inputs_collection.delete_many({'job_id': job_object_id})

