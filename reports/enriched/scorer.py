from collections import Counter, defaultdict
from datetime import datetime, timezone

from .pipeline_collections import collection
from .schemas import validate_vulnerability_card


SEVERITY_WEIGHTS = {
    'critical': 45,
    'high': 35,
    'medium': 22,
    'low': 10,
}


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def normalize_severity(value):
    text = str(value or '').lower()
    for key in SEVERITY_WEIGHTS:
        if key in text:
            return key.title()
    return 'Unknown'


def _float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def normalize_exploit_status(value):
    text = str(value or '').lower()
    if any(term in text for term in ('exploited', 'active', 'weaponized', 'kev')):
        return 'Known Exploited'
    if any(term in text for term in ('poc', 'proof', 'exploit available')):
        return 'PoC Available'
    if any(term in text for term in ('not confirmed', 'unknown', 'none')):
        return 'Unknown'
    return value or 'Unknown'


def priority_score(card):
    severity = normalize_severity(card.get('severity'))
    score = SEVERITY_WEIGHTS.get(severity.lower(), 8)
    if card.get('cisa_kev') is True:
        score += 25
    epss = _float(card.get('epss'))
    if epss >= 0.8:
        score += 15
    elif epss >= 0.5:
        score += 10
    elif epss >= 0.2:
        score += 5
    exploit = normalize_exploit_status(card.get('exploit_status'))
    if exploit == 'Known Exploited':
        score += 15
    elif exploit == 'PoC Available':
        score += 8
    if any(term in str(card.get('why_matters') or '').lower() for term in ('remote code', 'ransomware', 'internet-facing', 'privilege')):
        score += 8
    if card.get('conflicts'):
        score += 3
    if card.get('missing_fields'):
        score -= min(len(card['missing_fields']) * 2, 10)
    return max(0, min(100, round(score, 1)))


def patch_priority(score, severity, kev=False):
    if kev or score >= 80 or severity == 'Critical':
        return 'Critical'
    if score >= 60 or severity == 'High':
        return 'High'
    if score >= 35 or severity == 'Medium':
        return 'Medium'
    return 'Low'


def _metrics(cards):
    severity_counts = Counter(normalize_severity(card.get('severity')) for card in cards)
    exploit_counts = Counter(normalize_exploit_status(card.get('exploit_status')) for card in cards)
    product_counts = Counter((card.get('product') or 'Unknown') for card in cards)
    vendor_counts = Counter((card.get('vendor') or 'Unknown') for card in cards)
    priority_counts = Counter(card.get('patch_priority') or 'Unknown' for card in cards)
    top_items = sorted(cards, key=lambda item: item.get('priority_score', 0), reverse=True)[:5]
    remediation_items = [
        {
            'cve_id': item['cve_id'],
            'priority': item.get('patch_priority'),
            'action': item.get('how_to_respond') or 'Not confirmed from available sources.',
        }
        for item in top_items
    ]
    timeline = [
        {
            'cve_id': item['cve_id'],
            'disclosure_date': item.get('disclosure_date'),
            'scraped_at': item.get('scraped_at'),
            'fixed_versions': item.get('fixed_versions') or [],
        }
        for item in cards
    ]
    return {
        'total_vulnerabilities': len(cards),
        'severity_counts': dict(severity_counts),
        'exploit_maturity_counts': dict(exploit_counts),
        'product_breakdown': dict(product_counts),
        'vendor_breakdown': dict(vendor_counts),
        'patch_priority_counts': dict(priority_counts),
        'disclosure_vs_patch_timeline': timeline,
        'top_remediation_items': remediation_items,
        'generated_at': _now_iso(),
    }


def score_cards_and_metrics(web_database, run_id):
    cards_collection = collection(web_database, 'vulnerability_cards')
    cards = list(cards_collection.find({'run_id': run_id}))
    scored = []
    for card in cards:
        score = priority_score(card)
        severity = normalize_severity(card.get('severity'))
        card['priority_score'] = score
        card['patch_priority'] = patch_priority(score, severity, card.get('cisa_kev') is True)
        card['exploit_status'] = normalize_exploit_status(card.get('exploit_status'))
        card['updated_at'] = _now_iso()
        validate_vulnerability_card(card)
        cards_collection.replace_one({'_id': card['_id']}, card)
        scored.append(card)

    metrics = {'run_id': run_id, **_metrics(scored)}
    metrics_collection = collection(web_database, 'report_metrics')
    metrics_collection.delete_many({'run_id': run_id})
    metrics_collection.insert_one(metrics)
    return scored, metrics
