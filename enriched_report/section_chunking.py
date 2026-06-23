CHUNKABLE_SECTIONS = frozenset({'remediation_playbook'})

DEFAULT_CHUNK_PROMPT_CHARS = 20000
DEFAULT_CHUNK_CARD_COUNT = 4

PRIORITY_RANK = {
    'Critical': 0,
    'High': 1,
    'Medium': 2,
    'Low': 3,
}


def chunk_prompt_chars_threshold(config):
    return max(1000, int(config.get('REPORT_SECTION_CHUNK_PROMPT_CHARS', DEFAULT_CHUNK_PROMPT_CHARS)))


def chunk_card_count(config):
    return max(1, int(config.get('REPORT_SECTION_CHUNK_CARD_COUNT', DEFAULT_CHUNK_CARD_COUNT)))


def should_chunk_section(section_name, prompt_chars, config):
    if section_name not in CHUNKABLE_SECTIONS:
        return False
    return prompt_chars > chunk_prompt_chars_threshold(config)


def chunk_cards(cards, chunk_size):
    size = max(1, chunk_size)
    for start in range(0, len(cards), size):
        yield cards[start:start + size]


def evidence_for_cve_ids(evidence_cards, cve_ids):
    allowed = set(cve_ids)
    return [
        card for card in evidence_cards
        if card.get('cve_id') in allowed
    ]


def _normalize_action_key(action):
    return str(action.get('action') or '').strip().casefold()


def _action_dedupe_key(action):
    cve_ids = tuple(sorted(str(item) for item in (action.get('cve_ids') or []) if item))
    return (_normalize_action_key(action), cve_ids)


def _priority_rank(action):
    return PRIORITY_RANK.get(str(action.get('priority') or '').strip(), 99)


def merge_remediation_playbook_partials(partials):
    merged_actions = []
    seen = set()
    for partial in partials:
        for action in partial.get('actions') or []:
            if not isinstance(action, dict):
                continue
            key = _action_dedupe_key(action)
            if key in seen:
                continue
            seen.add(key)
            merged_actions.append({
                'priority': str(action.get('priority') or 'Low'),
                'action': str(action.get('action') or '').strip(),
                'cve_ids': [str(item) for item in (action.get('cve_ids') or []) if item],
            })

    merged_actions.sort(key=lambda item: (_priority_rank(item), item['action'].casefold()))
    return {
        'summary': build_remediation_summary(merged_actions),
        'actions': merged_actions,
    }


def build_remediation_summary(actions):
    if not actions:
        return 'No remediation actions were identified from available sources.'
    priority_counts = {priority: 0 for priority in PRIORITY_RANK}
    for action in actions:
        priority = str(action.get('priority') or 'Low')
        if priority in priority_counts:
            priority_counts[priority] += 1
    labels = []
    for priority in ('Critical', 'High', 'Medium', 'Low'):
        count = priority_counts[priority]
        if count:
            labels.append(f'{count} {priority.lower()}-priority')
    priority_text = ', '.join(labels)
    return (
        f'Prioritize {priority_text} remediation actions across {len(actions)} items.'
    )
