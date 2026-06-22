"""Enriched weekly report pipeline."""

import logging
import sys


def _ensure_enriched_logging():
    enriched_logger = logging.getLogger('enriched_report')
    if enriched_logger.handlers:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter('%(levelname)s [%(name)s] %(message)s'))
    enriched_logger.addHandler(handler)
    enriched_logger.setLevel(logging.INFO)
    enriched_logger.propagate = False


_ensure_enriched_logging()
