from datetime import datetime, timezone

from .pipeline_collections import collection
from .reference_urls import filter_reference_urls
from .schemas import validate_vulnerability_card


CONFIDENCE_SCORE = {'high': 3, 'medium': 2, 'low': 1}


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


_PLACEHOLDER_VALUES = frozenset({
    '',
    'not confirmed',
    'none',
    'null',
    'n/a',
    'na',
    'unknown',
    'tbd',
    '...',
    '…',
    '.',
    '-',
    '--',
})


def _confirmed(value):
    if value is None:
        return ''
    text = str(value).strip()
    normalized = text.lower()
    if (
        not text
        or normalized in _PLACEHOLDER_VALUES
        or normalized.startswith('not confirmed')
        or set(normalized) <= {'.', '…', ' '}
    ):
        return ''
    return text


def _pick_text(cards, field):
    options = [
        card for card in cards
        if _confirmed(card.get(field))
    ]
    if not options:
        return ''
    options.sort(
        key=lambda card: (CONFIDENCE_SCORE.get(card.get('confidence'), 0), len(_confirmed(card.get(field)))),
        reverse=True,
    )
    return _confirmed(options[0].get(field))


def _unique(values):
    seen = set()
    output = []
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            output.append(text)
    return output


def _source_references(candidate, cards):
    refs = []
    refs.extend(candidate.get('references') or [])
    if candidate.get('source_url'):
        refs.append(candidate['source_url'])
    for card in cards:
        refs.append(card.get('source_url'))
        refs.extend(card.get('references') or [])
    merged = _unique(refs)
    cve_id = candidate.get('cve_id')
    return filter_reference_urls(
        merged,
        cve_id,
        candidate.get('vendor_official_domain') or '',
    )


def _best_value(cards, key):
    options = [
        card for card in cards
        if card.get(key) not in (None, '', [], 'Not confirmed')
    ]
    if not options:
        return None
    options.sort(key=lambda card: CONFIDENCE_SCORE.get(card.get('confidence'), 0), reverse=True)
    return options[0].get(key)


def _combined_list(cards, key):
    values = []
    for card in cards:
        value = card.get(key)
        if isinstance(value, list):
            values.extend(value)
        elif value:
            values.append(value)
    return _unique(values)


def _conflicts(cards):
    conflicts = []
    fixed_sets = {
        tuple(sorted(str(item).strip() for item in card.get('fixed_versions') or [] if str(item).strip()))
        for card in cards
        if card.get('fixed_versions')
    }
    fixed_sets.discard(())
    if len(fixed_sets) > 1:
        conflicts.append('Sources report different fixed versions.')
    cvss_values = {
        str(card.get('cvss_score')).strip()
        for card in cards
        if card.get('cvss_score') not in (None, '')
    }
    if len(cvss_values) > 1:
        conflicts.append('Sources report different CVSS scores.')
    return conflicts


def _missing_fields(card):
    missing = []
    for field in ('vendor', 'product', 'severity', 'what_happened', 'why_matters', 'how_to_respond'):
        if not _confirmed(card.get(field)):
            missing.append(field)
    if not card.get('source_references'):
        missing.append('source_references')
    return missing


def merge_vulnerability_cards(web_database, run_id):
    candidates = list(collection(web_database, 'candidate_vulnerability_items').find({'run_id': run_id}))
    evidence_by_candidate = {}
    for card in collection(web_database, 'source_evidence_cards').find({'run_id': run_id}):
        evidence_by_candidate.setdefault(card['candidate_id'], []).append(card)

    cards = []
    for candidate in candidates:
        evidence_cards = evidence_by_candidate.get(candidate['candidate_id'], [])
        card = {
            'run_id': run_id,
            'candidate_id': candidate['candidate_id'],
            'cve_id': candidate['cve_id'],
            'advisory_id': candidate.get('advisory_id'),
            'vendor': candidate.get('vendor') or None,
            'product': candidate.get('product') or None,
            'title': candidate.get('title') or candidate['cve_id'],
            'severity': candidate.get('severity') or None,
            'published_at': candidate.get('published_at'),
            'observed_at': candidate.get('observed_at'),
            'what_happened': _pick_text(evidence_cards, 'what_happened') or candidate.get('summary') or 'Not confirmed from available sources.',
            'why_matters': _pick_text(evidence_cards, 'why_matters') or 'Not confirmed from available sources.',
            'how_to_respond': _pick_text(evidence_cards, 'how_to_respond') or 'Not confirmed from available sources.',
            'priority_score': 0,
            'patch_priority': 'Unscored',
            'missing_fields': [],
            'conflicts': _conflicts(evidence_cards),
            'source_references': _source_references(candidate, evidence_cards),
            'affected_versions': _combined_list(evidence_cards, 'affected_versions'),
            'fixed_versions': _combined_list(evidence_cards, 'fixed_versions'),
            'cvss_score': _best_value(evidence_cards, 'cvss_score'),
            'cvss_vector': _best_value(evidence_cards, 'cvss_vector'),
            'exploit_status': _best_value(evidence_cards, 'exploit_status'),
            'cisa_kev': _best_value(evidence_cards, 'cisa_kev'),
            'epss': _best_value(evidence_cards, 'epss'),
            'updated_at': _now_iso(),
        }
        card['missing_fields'] = _missing_fields(card)
        cards.append(validate_vulnerability_card(card))

    target = collection(web_database, 'vulnerability_cards')
    target.delete_many({'run_id': run_id})
    if cards:
        target.insert_many(cards)
    return cards
