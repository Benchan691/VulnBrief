from datetime import datetime, timezone
import logging

from bson import ObjectId

from core.database import get_vulnerabilities_database, get_web_database
from reports.progress import (
    JobLogHandler,
    append_job_log,
    mark_job_started,
    update_job_progress,
)

from .candidate_loader import load_candidates_from_inputs
from .card_merger import merge_vulnerability_cards
from .evidence_cache import delete_cached_payload
from .evidence_extractor import extract_evidence_cards
from .llama_client import EnrichedLlamaClient
from .pipeline_collections import collection, ensure_indexes
from .report_generator import generate_enriched_report
from .result_ranker import rank_results_for_run
from .scorer import score_cards_and_metrics
from .search_executor import execute_pending_search_tasks
from .search_tasks import write_search_tasks
from .tavily_client import build_search_client


def _now():
    return datetime.now(timezone.utc)


def _job_collection():
    return get_web_database()['report_jobs']


def _input_collection():
    return get_web_database()['report_job_inputs']


FIXED_STAGE_UNITS = 6
TAVILY_TASK_WEIGHT = 1
EVIDENCE_CARD_WEIGHT = 4
REPORT_SECTION_UNITS = 3
REPORT_SECTION_WEIGHT = 3


class _EnrichedProgress:
    def __init__(self, job_id):
        self.job_id = job_id
        self.tavily_total = 0
        self.evidence_total = 0
        self.total = 1

    def set_tavily_total(self, tavily_total):
        self.tavily_total = max(int(tavily_total), 0)
        self._refresh_total(self.evidence_total or self.tavily_total)

    def set_evidence_total(self, evidence_total):
        self.evidence_total = max(int(evidence_total), 0)
        self._refresh_total(self.evidence_total)

    def _refresh_total(self, evidence_total):
        self.total = (
            FIXED_STAGE_UNITS
            + (self.tavily_total * TAVILY_TASK_WEIGHT)
            + (evidence_total * EVIDENCE_CARD_WEIGHT)
            + (REPORT_SECTION_UNITS * REPORT_SECTION_WEIGHT)
        )

    def _tavily_offset(self):
        return 3

    def _ranking_offset(self):
        return self._tavily_offset() + (self.tavily_total * TAVILY_TASK_WEIGHT)

    def _evidence_offset(self):
        return self._ranking_offset() + 1

    def _merge_offset(self):
        return self._evidence_offset() + (self.evidence_total * EVIDENCE_CARD_WEIGHT)

    def _score_offset(self):
        return self._merge_offset() + 1

    def _report_offset(self):
        return self._score_offset() + 1

    def step(self, current, label, message=None):
        update_job_progress(
            self.job_id,
            current=current,
            total=self.total,
            label=label,
            message=message,
        )

    def tavily_progress(self, completed, message):
        self.step(
            self._tavily_offset() + (max(int(completed), 0) * TAVILY_TASK_WEIGHT),
            f'Searching web {completed}/{self.tavily_total}',
            message,
        )

    def evidence_progress(self, index, message):
        self.step(
            self._evidence_offset() + (max(int(index), 0) * EVIDENCE_CARD_WEIGHT),
            f'Extracting evidence {index}/{self.evidence_total}',
            message,
        )

    def report_progress(self, index, message):
        self.step(
            self._report_offset() + (max(int(index), 0) * REPORT_SECTION_WEIGHT),
            f'Generating report section {index}/{REPORT_SECTION_UNITS}',
            message,
        )


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
    if not (config.get('TAVILY_API_KEYS') or config.get('TAVILY_API_KEY')):
        missing.append('TAVILY_API_KEYS or TAVILY_API_KEY')
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
        log_handler = JobLogHandler(job_id)
        enriched_logger = logging.getLogger(__package__)
        enriched_logger.setLevel(logging.INFO)
        enriched_logger.addHandler(log_handler)
        progress = _EnrichedProgress(job_id)
        try:
            job = jobs.find_one({'_id': job_object_id})
            if job is None or job.get('status') == 'cancelled':
                return
            if job.get('status') not in ('queued', 'running'):
                return
            mark_job_started(job_id)
            jobs.update_one(
                {'_id': job_object_id, 'status': {'$in': ['queued', 'running']}},
                {'$set': {
                    'status': 'running',
                    'pipeline_stage': 'starting',
                    'updated_at': _now(),
                    'provider': 'Search API + llama-server',
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
            append_job_log(job_id, 'Starting enriched weekly pipeline.')
            progress.step(1, 'Starting pipeline', 'Starting enriched weekly pipeline.')

            inputs = list(inputs_collection.find({'job_id': job_object_id}).sort('position', 1))
            if not inputs:
                raise ValueError('At least one cve_review selection is required.')

            if _cancelled(job_object_id):
                return
            _stage(job_object_id, 'loading_candidates')
            progress.step(2, 'Loading candidates', 'Loading CVE candidates.')
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
            progress.step(3, 'Creating search tasks', 'Creating search tasks.')
            write_search_tasks(
                web_database,
                run_id,
                candidates,
                search_prompt=job.get('search_prompt') or '',
            )
            tavily_total = collection(web_database, 'search_enrichment_tasks').count_documents({'run_id': run_id})
            progress.set_tavily_total(tavily_total)

            if _cancelled(job_object_id):
                return
            _stage(job_object_id, 'searching')

            def on_tavily_progress(completed, total, message):
                progress.tavily_progress(completed, message)

            completed_searches = execute_pending_search_tasks(
                web_database,
                run_id,
                config,
                tavily_client or build_search_client(config),
                progress_callback=on_tavily_progress,
            )
            search_tasks = collection(web_database, 'search_enrichment_tasks')
            failed_searches = search_tasks.count_documents({'run_id': run_id, 'status': 'failed'})
            if completed_searches == 0:
                failed_task = search_tasks.find_one(
                    {'run_id': run_id, 'status': 'failed'},
                    {'error': 1},
                )
                detail = (failed_task or {}).get('error') or 'unknown search provider error'
                raise ValueError(
                    f'All {tavily_total} Tavily search tasks failed; '
                    f'enriched report was not generated. First error: {detail}'
                )
            if failed_searches:
                logger.warning(
                    'enriched search partial failure run=%s succeeded=%d failed=%d',
                    run_id,
                    completed_searches,
                    failed_searches,
                )

            if _cancelled(job_object_id):
                return
            _stage(job_object_id, 'ranking_results')
            filtered = rank_results_for_run(
                web_database,
                run_id,
                int(config.get('ENRICHED_RESULTS_PER_TASK', 4)),
            )
            if not filtered:
                raise ValueError('No relevant search enrichment results were found for selected CVEs.')
            searched_candidate_ids = {
                item.get('candidate_id')
                for item in filtered
                if item.get('source_type') != 'candidate_reference'
            }
            missing_search_evidence = [
                candidate['cve_id']
                for candidate in candidates
                if candidate.get('candidate_id') not in searched_candidate_ids
            ]
            if missing_search_evidence:
                raise ValueError(
                    'No relevant Tavily search results were found for: '
                    + ', '.join(missing_search_evidence)
                    + '; enriched report was not generated.'
                )
            evidence_total = len(filtered)
            progress.set_evidence_total(evidence_total)
            progress.step(
                progress._ranking_offset(),
                'Ranking results',
                f'Ranked {evidence_total} enrichment results.',
            )

            if _cancelled(job_object_id):
                return
            _stage(job_object_id, 'extracting_evidence')
            llama_client = llama_client or EnrichedLlamaClient(config)

            def on_evidence_progress(index, total, message):
                progress.evidence_progress(index, message)

            evidence_cards = extract_evidence_cards(
                web_database,
                run_id,
                config,
                llama_client,
                progress_callback=on_evidence_progress,
            )
            evidence_by_candidate = {}
            for card in evidence_cards:
                evidence_by_candidate.setdefault(card.get('candidate_id'), []).append(card)
            incomplete_evidence = []
            incomplete_candidate_ids = set()
            for candidate in candidates:
                candidate_cards = evidence_by_candidate.get(candidate.get('candidate_id'), [])
                missing_fields = [
                    field
                    for field in ('why_matters', 'how_to_respond')
                    if not any(card.get(field) for card in candidate_cards)
                ]
                if missing_fields:
                    incomplete_candidate_ids.add(candidate.get('candidate_id'))
                    incomplete_evidence.append(
                        f"{candidate['cve_id']} ({', '.join(missing_fields)})"
                    )
            if incomplete_evidence:
                evidence_cache_version = str(
                    config.get('ENRICHED_EVIDENCE_CACHE_VERSION', '2')
                )
                evicted_cache_entries = 0
                if bool(config.get('ENRICHED_EVIDENCE_CACHE_ENABLED', True)):
                    evicted_cache_entries = sum(
                        delete_cached_payload(
                            web_database,
                            result,
                            evidence_cache_version,
                        )
                        for result in filtered
                        if result.get('candidate_id') in incomplete_candidate_ids
                    )
                logger.warning(
                    'enriched evidence incomplete run=%s candidates=%d evicted_cache_entries=%d',
                    run_id,
                    len(incomplete_candidate_ids),
                    evicted_cache_entries,
                )
                raise ValueError(
                    'Evidence extraction did not confirm required risk/impact and remediation '
                    'guidance for: '
                    + '; '.join(incomplete_evidence)
                    + '; enriched report was not generated.'
                )

            if _cancelled(job_object_id):
                return
            _stage(job_object_id, 'merging_cards')
            progress.step(
                progress._merge_offset(),
                'Merging vulnerability cards',
                'Merging evidence into vulnerability cards.',
            )
            vulnerability_cards = merge_vulnerability_cards(web_database, run_id)

            if _cancelled(job_object_id):
                return
            _stage(job_object_id, 'scoring')
            progress.step(
                progress._score_offset(),
                'Scoring vulnerabilities',
                'Scoring vulnerability cards.',
            )
            vulnerability_cards, metrics = score_cards_and_metrics(web_database, run_id)

            if _cancelled(job_object_id):
                return
            _stage(job_object_id, 'generating_report')

            def on_report_progress(index, total, message):
                progress.report_progress(index, message)

            report = generate_enriched_report(
                vulnerability_cards,
                metrics,
                evidence_cards,
                config,
                job.get('report_language', 'en'),
                llama_client,
                progress_callback=on_report_progress,
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
                    'progress_percent': 100,
                    'progress_current': progress.total,
                    'progress_total': progress.total,
                    'progress_label': 'Completed',
                    'estimated_seconds_remaining': 0,
                    'completed_at': _now(),
                    'updated_at': _now(),
                }},
            )
            append_job_log(job_id, 'Enriched weekly report completed.')
        except Exception as exc:
            if _cancelled(job_object_id):
                return
            append_job_log(job_id, f'Pipeline failed: {exc}')
            jobs.update_one(
                {'_id': job_object_id, 'status': {'$ne': 'cancelled'}},
                {'$set': {
                    'status': 'failed',
                    'updated_at': _now(),
                    'error': str(exc),
                    'status_message': str(exc),
                }},
            )
        finally:
            enriched_logger.removeHandler(log_handler)
            inputs_collection.delete_many({'job_id': job_object_id})
