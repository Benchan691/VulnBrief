import logging
from datetime import datetime, timezone

from bson import ObjectId

from core.database import get_web_database

MAX_PIPELINE_LOG_LINES = 500
MAX_ETA_SECONDS = 24 * 60 * 60


def _now():
    return datetime.now(timezone.utc)


def _jobs():
    return get_web_database()['report_jobs']


def _job_object_id(job_id):
    return job_id if isinstance(job_id, ObjectId) else ObjectId(str(job_id))


def compute_eta_seconds(started_at, progress_percent):
    if started_at is None or progress_percent is None or progress_percent <= 0:
        return None
    if progress_percent >= 100:
        return 0
    if isinstance(started_at, str):
        started_at = datetime.fromisoformat(started_at.replace('Z', '+00:00'))
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)
    elapsed = (_now() - started_at).total_seconds()
    if elapsed < 0:
        return None
    eta = int(elapsed * (100 - progress_percent) / progress_percent)
    return min(max(eta, 0), MAX_ETA_SECONDS)


def mark_job_started(job_id):
    now = _now()
    _jobs().update_one(
        {
            '_id': _job_object_id(job_id),
            '$or': [{'started_at': {'$exists': False}}, {'started_at': None}],
        },
        {'$set': {'started_at': now}},
    )


def init_job_progress(job_id, *, total_units, label, message=None):
    mark_job_started(job_id)
    update = {
        'progress_total': max(int(total_units), 1),
        'progress_current': 0,
        'progress_percent': 0,
        'progress_label': label,
        'estimated_seconds_remaining': None,
        'pipeline_logs': [],
        'updated_at': _now(),
    }
    if message is not None:
        update['status_message'] = message
    _jobs().update_one({'_id': _job_object_id(job_id)}, {'$set': update})


def update_job_progress(
    job_id,
    *,
    current=None,
    total=None,
    percent=None,
    label=None,
    message=None,
):
    job = _jobs().find_one({'_id': _job_object_id(job_id)}, {'started_at': 1, 'progress_total': 1})
    if job is None:
        return
    update = {'updated_at': _now()}
    if total is not None:
        update['progress_total'] = max(int(total), 1)
    progress_total = update.get('progress_total', job.get('progress_total') or 1)
    if current is not None:
        update['progress_current'] = int(current)
        if percent is None:
            percent = int(round(100 * int(current) / progress_total))
    if percent is not None:
        update['progress_percent'] = max(0, min(100, int(percent)))
    if label is not None:
        update['progress_label'] = label
    if message is not None:
        update['status_message'] = message
    progress_percent = update.get('progress_percent')
    if progress_percent is None and update.get('progress_current') is not None:
        progress_percent = int(round(100 * update['progress_current'] / progress_total))
        update['progress_percent'] = progress_percent
    if progress_percent is not None:
        update['estimated_seconds_remaining'] = compute_eta_seconds(
            job.get('started_at'),
            progress_percent,
        )
    _jobs().update_one({'_id': _job_object_id(job_id)}, {'$set': update})


def append_job_log(job_id, line):
    text = str(line or '').strip()
    if not text:
        return
    _jobs().update_one(
        {'_id': _job_object_id(job_id)},
        {
            '$push': {'pipeline_logs': {'$each': [text], '$slice': -MAX_PIPELINE_LOG_LINES}},
            '$set': {'status_message': text, 'updated_at': _now()},
        },
    )


def get_job_logs(job_id):
    job = _jobs().find_one({'_id': _job_object_id(job_id)}, {'pipeline_logs': 1})
    if job is None:
        return None
    return list(job.get('pipeline_logs') or [])


class JobLogHandler(logging.Handler):
    def __init__(self, job_id):
        super().__init__(level=logging.INFO)
        self.job_id = job_id

    def emit(self, record):
        try:
            append_job_log(self.job_id, self.format(record))
        except Exception:
            self.handleError(record)
