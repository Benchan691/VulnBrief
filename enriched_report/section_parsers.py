from jsonschema import validate


def build_vulnerability_detail_table(cards):
    return {
        'rows': [
            {
                'cve_id': card['cve_id'],
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


def build_appendix(cards, evidence_cards, metrics):
    refs_by_cve = {}
    cve_order = []
    seen = set()

    def add_url(cve_id, url):
        if not url:
            return
        key = (cve_id, url)
        if key in seen:
            return
        seen.add(key)
        if cve_id not in refs_by_cve:
            refs_by_cve[cve_id] = []
            cve_order.append(cve_id)
        refs_by_cve[cve_id].append(url)

    for card in cards:
        cve_id = card['cve_id']
        for url in card.get('source_references') or []:
            add_url(cve_id, url)
    for card in evidence_cards:
        add_url(card['cve_id'], card.get('source_url'))

    refs = [
        {'cve_id': cve_id, 'urls': refs_by_cve[cve_id]}
        for cve_id in cve_order
    ]
    appendix_metrics = {
        key: value
        for key, value in metrics.items()
        if key not in {'run_id', '_id'}
    }
    return {
        'source_references': refs,
        'metrics': appendix_metrics,
    }


def validate_section(section_name, section, schema):
    validate(instance=section, schema=schema)
    return section
