import re


def _card_anchor(card):
    label = ' '.join(
        str(value)
        for value in (card.get('cve_id'), card.get('vendor'), card.get('product'))
        if value
    )
    slug = re.sub(r'[^a-z0-9]+', '-', label.lower()).strip('-')
    return f'card-{slug or "vulnerability"}'


def build_vulnerability_detail_table(cards):
    return {
        'rows': [
            {
                'cve_id': card['cve_id'],
                'card_anchor': _card_anchor(card),
                'title': card['title'],
                'vendor': card.get('vendor'),
                'product': card.get('product'),
                'severity': card.get('severity'),
                'priority_score': card['priority_score'],
                'patch_priority': card['patch_priority'],
                'what_happened': card['what_happened'],
                'why_matters': card['why_matters'],
                'how_to_respond': card['how_to_respond'],
                'source_urls': list(card.get('source_references') or []),
            }
            for card in cards
        ],
    }


def build_executive_summary(rows):
    total = len(rows)
    severity_counts = {}
    for row in rows:
        severity = str(row.get('severity') or 'Unknown').title()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    severities = {severity.lower() for severity in severity_counts}
    if 'critical' in severities:
        risk = 'Critical'
    elif 'high' in severities:
        risk = 'High'
    elif 'medium' in severities:
        risk = 'Medium'
    elif 'low' in severities:
        risk = 'Low'
    else:
        risk = 'Unknown'

    products = []
    seen_products = set()
    for row in rows:
        vendor = row.get('vendor') or 'Unknown vendor'
        product = row.get('product') or 'Unknown product'
        name = f'{vendor} {product}'.strip()
        key = name.lower()
        if key not in seen_products:
            seen_products.add(key)
            products.append(name)
    product_text = ', '.join(products[:8]) if products else 'No affected products confirmed'
    if len(products) > 8:
        product_text += f', and {len(products) - 8} more'

    count_word = 'vulnerability' if total == 1 else 'vulnerabilities'
    severity_text = ', '.join(
        f'{count} {severity}'
        for severity, count in severity_counts.items()
    ) or 'no confirmed severity data'
    return {
        'key_findings': [
            f'{total} {count_word} reviewed.',
            f'Overall risk: {risk}.',
            f'Affected products: {product_text}.',
            f'Severity coverage: {severity_text}.',
            'Validate whether affected systems are deployed, internet-facing, or business-critical before scheduling changes.',
            'Patch Critical and High severity items first, apply vendor fixes, and record remediation evidence through change control.',
            'Keep unconfirmed exposures in the follow-up queue until asset owners verify product presence.',
        ],
    }
