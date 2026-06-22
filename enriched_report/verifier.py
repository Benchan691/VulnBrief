import copy
import json
from datetime import datetime, timezone

from jsonschema import ValidationError

from .llama_client import EnrichedLLMError
from .schemas import validate_enriched_report
from .section_parsers import SectionParseError, parse_unsupported_claims


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


def ai_verify(report, vulnerability_cards, evidence_cards, client):
    evidence = [
        {
            'cve_id': card.get('cve_id'),
            'task_type': card.get('task_type'),
            'source_url': card.get('source_url'),
            'what_happened': card.get('what_happened'),
            'why_matters': card.get('why_matters'),
            'how_to_respond': card.get('how_to_respond'),
            'fixed_versions': card.get('fixed_versions'),
            'affected_versions': card.get('affected_versions'),
        }
        for card in evidence_cards
    ]
    system = (
        'You verify a cybersecurity report against structured evidence. Return plain text only. '
        'List exact unsupported report text snippets under UNSUPPORTED_CLAIMS. '
        'Use one bullet per snippet. If nothing is unsupported, return exactly:\n'
        'UNSUPPORTED_CLAIMS:\n'
        'NONE\n'
        'Do not return JSON or commentary.'
    )
    prompt = json.dumps({
        'report': report,
        'vulnerability_cards': vulnerability_cards,
        'source_evidence_cards': evidence,
    }, ensure_ascii=False, default=str)
    try:
        text, _ = client.complete_text(
            system,
            prompt,
            max_output_tokens=client.report_max_output_tokens,
        )
        claims = parse_unsupported_claims(text)
        if not all(isinstance(claim, str) and claim.strip() for claim in claims):
            raise SectionParseError('Unsupported claims must be non-empty strings.')
        return claims
    except EnrichedLLMError:
        raise
    except (SectionParseError, ValidationError) as exc:
        raise EnrichedLLMError(str(exc)) from exc


def verify_and_finalize_report(report, vulnerability_cards, report_metrics, evidence_cards, client):
    issues = python_verify(report, vulnerability_cards, report_metrics, evidence_cards)
    unsupported_claims = ai_verify(report, vulnerability_cards, evidence_cards, client)
    report = replace_unsupported_claims(report, unsupported_claims)
    report['verification'] = {
        'python_checks': 'passed' if not issues else 'issues_found',
        'ai_checks': 'passed' if not unsupported_claims else 'unsupported_claims_found',
        'issues': issues,
        'unsupported_claims': unsupported_claims,
        'verified_at': _now_iso(),
    }
    return validate_enriched_report(report)
