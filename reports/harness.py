"""Stable internal API for report routes and workers."""

from reports.jobs import (
    _assemble_report,
    _deterministic_final,
    _load_input_details,
    _render_job_html,
    _translation_html_for_job,
    cancel_job,
    create_job,
    delete_job,
    resolve_review_selections,
)
from reports.runner import run_job, run_template_job, start_job
from reports.template_builder import (
    REPORT_SCHEMA,
    _finalize_item_result,
    compact_details,
    compact_document,
    generate_template_report_data,
)
from reports.translation import (
    _translation_report_for_job,
    request_report_translation,
    run_report_translation,
)


__all__ = [name for name in globals() if not name.startswith('__')]
