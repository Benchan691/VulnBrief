CHUNKABLE_SECTIONS = frozenset({
    'executive_summary',
})

DEFAULT_CHUNK_PROMPT_CHARS = 20000
DEFAULT_CHUNK_CARD_COUNT = 4


def chunk_prompt_chars_threshold(config):
    return max(1000, int(config.get('REPORT_SECTION_CHUNK_PROMPT_CHARS', DEFAULT_CHUNK_PROMPT_CHARS)))


def chunk_card_count(config):
    return max(1, int(config.get('REPORT_SECTION_CHUNK_CARD_COUNT', DEFAULT_CHUNK_CARD_COUNT)))


def should_chunk_section(section_name, prompt_chars, card_count, config):
    if section_name not in CHUNKABLE_SECTIONS:
        return False
    return (
        prompt_chars > chunk_prompt_chars_threshold(config)
        or card_count > chunk_card_count(config)
    )


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
