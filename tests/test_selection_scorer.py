from datetime import datetime, timezone

from selection_scorer import (
    rank_scored_selections,
    score_review_document,
    selection_score,
)


def _critical_kev_document():
    return {
        '_id': 'critical:1',
        'cveMetadata': {
            'cveId': 'CVE-2026-9000',
            'datePublished': '2026-06-20T00:00:00+00:00',
        },
        'cisa_kev': True,
        'scraped_at': '2026-06-20T00:00:00+00:00',
        'containers': {
            'cna': {
                'metrics': [{'cvssV3_1': {'baseSeverity': 'CRITICAL', 'baseScore': 9.8}}],
                'descriptions': [{
                    'value': 'Remote code execution exploited in the wild on internet-facing systems.',
                }],
            },
        },
    }


def _medium_document():
    return {
        '_id': 'medium:1',
        'code': 'CVE-2026-1000',
        'severity': 'Medium',
        'summary': 'Information disclosure in a configuration panel.',
        'scraped_at': '2020-01-01T00:00:00+00:00',
    }


def test_selection_score_critical_kev_is_high_priority():
    scored = score_review_document(_critical_kev_document())

    assert scored['selection_score'] >= 80
    assert scored['patch_priority'] == 'Critical'
    assert scored['cve_id'] == 'CVE-2026-9000'


def test_selection_score_medium_without_signals_is_lower():
    assert selection_score(_medium_document()) < 40


def test_rank_scored_selections_dedupes_by_cve_and_keeps_highest_score():
    rows = [
        {
            'collection': 'cve_review',
            'selection_id': 'low',
            'selection_score': 30.0,
            'patch_priority': 'Low',
            'cve_id': 'CVE-2026-2000',
            'severity': 'Low',
            'disclosure_date': None,
            'scraped_at': '2026-06-01T00:00:00+00:00',
        },
        {
            'collection': 'cve_review',
            'selection_id': 'high',
            'selection_score': 75.0,
            'patch_priority': 'High',
            'cve_id': 'CVE-2026-2000',
            'severity': 'High',
            'disclosure_date': None,
            'scraped_at': '2026-06-10T00:00:00+00:00',
        },
        {
            'collection': 'cve_review',
            'selection_id': 'other',
            'selection_score': 50.0,
            'patch_priority': 'Medium',
            'cve_id': 'CVE-2026-3000',
            'severity': 'Medium',
            'disclosure_date': None,
            'scraped_at': '2026-06-08T00:00:00+00:00',
        },
    ]

    ranked = rank_scored_selections(rows, 2)

    assert [item['selection_id'] for item in ranked] == ['high', 'other']


def test_rank_scored_selections_returns_top_n_in_score_order():
    rows = [
        {
            'collection': 'cve_review',
            'selection_id': 'first',
            'selection_score': 90.0,
            'patch_priority': 'Critical',
            'cve_id': 'CVE-2026-0001',
            'severity': 'Critical',
            'disclosure_date': '2026-06-20T00:00:00+00:00',
            'scraped_at': '2026-06-20T00:00:00+00:00',
        },
        {
            'collection': 'cve_review',
            'selection_id': 'second',
            'selection_score': 60.0,
            'patch_priority': 'High',
            'cve_id': 'CVE-2026-0002',
            'severity': 'High',
            'disclosure_date': '2026-06-18T00:00:00+00:00',
            'scraped_at': '2026-06-18T00:00:00+00:00',
        },
        {
            'collection': 'cve_review',
            'selection_id': 'third',
            'selection_score': 25.0,
            'patch_priority': 'Low',
            'cve_id': 'CVE-2026-0003',
            'severity': 'Low',
            'disclosure_date': '2026-06-01T00:00:00+00:00',
            'scraped_at': '2026-06-01T00:00:00+00:00',
        },
    ]

    ranked = rank_scored_selections(rows, 2)

    assert [item['selection_id'] for item in ranked] == ['first', 'second']
