from datetime import datetime, timedelta, timezone

import pytest
from bson import ObjectId

from report_job_progress import (
    MAX_ETA_SECONDS,
    append_job_log,
    compute_eta_seconds,
    get_job_logs,
    init_job_progress,
    update_job_progress,
)


class FakeJobsCollection:
    def __init__(self):
        self.docs = {}

    def update_one(self, query, update, upsert=False):
        job_id = query['_id']
        doc = self.docs.setdefault(job_id, {'_id': job_id})
        if '$set' in update:
            doc.update(update['$set'])
        if '$push' in update:
            for key, push in update['$push'].items():
                existing = list(doc.get(key) or [])
                if isinstance(push, dict) and '$each' in push:
                    existing.extend(push['$each'])
                    if '$slice' in push:
                        existing = existing[push['$slice']:]
                else:
                    existing.append(push)
                doc[key] = existing
        return None

    def find_one(self, query, projection=None):
        doc = self.docs.get(query['_id'])
        if doc is None:
            return None
        if projection is None:
            return dict(doc)
        return {key: doc.get(key) for key in projection if key != '_id'}


@pytest.fixture(autouse=True)
def fake_jobs(monkeypatch):
    collection = FakeJobsCollection()
    monkeypatch.setattr('report_job_progress._jobs', lambda: collection)
    return collection


def test_compute_eta_seconds_returns_none_for_zero_percent():
    started = datetime.now(timezone.utc) - timedelta(minutes=5)
    assert compute_eta_seconds(started, 0) is None


def test_compute_eta_seconds_linear_extrapolation():
    started = datetime.now(timezone.utc) - timedelta(minutes=10)
    eta = compute_eta_seconds(started, 50)
    assert 590 <= eta <= 610


def test_compute_eta_seconds_caps_at_max():
    started = datetime.now(timezone.utc) - timedelta(seconds=1)
    eta = compute_eta_seconds(started, 1)
    assert eta <= MAX_ETA_SECONDS


def test_init_and_update_job_progress(fake_jobs):
    job_id = ObjectId()
    init_job_progress(job_id, total_units=10, label='Starting', message='Starting job.')
    update_job_progress(job_id, current=5, label='Halfway', message='Half done.')

    doc = fake_jobs.docs[job_id]
    assert doc['progress_total'] == 10
    assert doc['progress_current'] == 5
    assert doc['progress_percent'] == 50
    assert doc['progress_label'] == 'Halfway'
    assert doc['status_message'] == 'Half done.'
    assert doc['started_at'] is not None
    assert doc['estimated_seconds_remaining'] is not None


def test_append_job_log_caps_entries(fake_jobs):
    job_id = ObjectId()
    fake_jobs.docs[job_id] = {'_id': job_id, 'pipeline_logs': []}
    for index in range(505):
        append_job_log(job_id, f'line-{index}')

    logs = get_job_logs(job_id)
    assert len(logs) == 500
    assert logs[0] == 'line-5'
    assert logs[-1] == 'line-504'
