import copy
from datetime import datetime, timezone

from .schemas import validate_enriched_report


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _card_map(cards):
    return {card['cve_id']: card for card in cards}


def _evidence_urls(evidence_cards, vulnerability_cards):
    urls = set()
    for card in evidence_cards:
        if card.get('source_url'):
            urls.add(card['source_url'])
        urls.update(card.get('references') or [])
    for card in vulnerability_cards:
        urls.update(card.get('source_references') or [])
    return urls


def python_verify(report, vulnerability_cards, report_metrics, evidence_cards):
    issues = []
    cards_by_cve = _card_map(vulnerability_cards)
    rows = (report.get('vulnerability_detail_table') or {}).get('rows') or []
    row_cves = [row.get('cve_id') for row in rows]
    seen = set()
    for cve_id in row_cves:
        if cve_id in seen:
            issues.append(f'Duplicate CVE row: {cve_id}')
        seen.add(cve_id)
        if cve_id not in cards_by_cve:
            issues.append(f'Report includes CVE outside vulnerability_cards: {cve_id}')
    if len(rows) != report_metrics.get('total_vulnerabilities'):
        issues.append('Vulnerability table row count does not match report metrics.')

    known_urls = _evidence_urls(evidence_cards, vulnerability_cards)
    for row in rows:
        card = cards_by_cve.get(row.get('cve_id'))
        if not card:
            continue
        if row.get('priority_score') != card.get('priority_score'):
            issues.append(f"Priority score mismatch for {row.get('cve_id')}.")
        if row.get('patch_priority') != card.get('patch_priority'):
            issues.append(f"Patch priority mismatch for {row.get('cve_id')}.")
        for url in row.get('source_urls') or []:
            if url not in known_urls:
                issues.append(f"Unknown source URL in report for {row.get('cve_id')}: {url}")
    return issues


def _replace_claim(value, claim):
    replacement = 'Not confirmed from available sources.'
    if isinstance(value, dict):
        return {key: _replace_claim(child, claim) for key, child in value.items()}
    if isinstance(value, list):
        return [_replace_claim(child, claim) for child in value]
    if isinstance(value, str) and claim and claim in value:
        return value.replace(claim, replacement)
    return value


def replace_unsupported_claims(report, unsupported_claims):
    updated = copy.deepcopy(report)
    for claim in unsupported_claims:
        updated = _replace_claim(updated, claim)
    return updated


def verify_and_finalize_report(report, vulnerability_cards, report_metrics, evidence_cards):
    issues = python_verify(report, vulnerability_cards, report_metrics, evidence_cards)
    report['verification'] = {
        'python_checks': 'passed' if not issues else 'issues_found',
        'ai_checks': 'skipped',
        'issues': issues,
        'unsupported_claims': [],
        'verified_at': _now_iso(),
    }
    return validate_enriched_report(report)
