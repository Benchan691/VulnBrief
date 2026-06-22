from jsonschema import validate


TASK_TYPES = ('what_happened', 'why_matters', 'how_to_respond')
CONFIDENCE_VALUES = ('high', 'medium', 'low')


NULLABLE_STRING = {'type': ['string', 'null']}
STRING_ARRAY = {'type': 'array', 'items': {'type': 'string'}}


SOURCE_EVIDENCE_CARD_SCHEMA = {
    'type': 'object',
    'required': [
        'run_id', 'candidate_id', 'cve_id', 'task_type', 'source_url',
        'confidence', 'extracted_at',
    ],
    'properties': {
        'run_id': {'type': 'string'},
        'candidate_id': {'type': 'string'},
        'cve_id': {'type': 'string'},
        'task_type': {'type': 'string', 'enum': list(TASK_TYPES)},
        'source_url': {'type': 'string'},
        'confidence': {'type': 'string', 'enum': list(CONFIDENCE_VALUES)},
        'title': NULLABLE_STRING,
        'what_happened': NULLABLE_STRING,
        'why_matters': NULLABLE_STRING,
        'how_to_respond': NULLABLE_STRING,
        'affected_versions': STRING_ARRAY,
        'fixed_versions': STRING_ARRAY,
        'cvss_score': {'type': ['number', 'string', 'null']},
        'cvss_vector': NULLABLE_STRING,
        'exploit_status': NULLABLE_STRING,
        'cisa_kev': {'type': ['boolean', 'null']},
        'epss': {'type': ['number', 'string', 'null']},
        'business_impact': NULLABLE_STRING,
        'references': STRING_ARRAY,
        'extracted_at': {'type': 'string'},
    },
}


VULNERABILITY_CARD_SCHEMA = {
    'type': 'object',
    'required': [
        'run_id', 'candidate_id', 'cve_id', 'title', 'what_happened',
        'why_matters', 'how_to_respond', 'priority_score', 'patch_priority',
        'missing_fields', 'conflicts', 'source_references',
    ],
    'properties': {
        'run_id': {'type': 'string'},
        'candidate_id': {'type': 'string'},
        'cve_id': {'type': 'string'},
        'advisory_id': NULLABLE_STRING,
        'vendor': NULLABLE_STRING,
        'product': NULLABLE_STRING,
        'title': {'type': 'string'},
        'severity': NULLABLE_STRING,
        'what_happened': {'type': 'string'},
        'why_matters': {'type': 'string'},
        'how_to_respond': {'type': 'string'},
        'priority_score': {'type': 'number'},
        'patch_priority': {'type': 'string'},
        'missing_fields': STRING_ARRAY,
        'conflicts': STRING_ARRAY,
        'source_references': STRING_ARRAY,
        'affected_versions': STRING_ARRAY,
        'fixed_versions': STRING_ARRAY,
        'cvss_score': {'type': ['number', 'string', 'null']},
        'cvss_vector': NULLABLE_STRING,
        'exploit_status': NULLABLE_STRING,
        'cisa_kev': {'type': ['boolean', 'null']},
        'epss': {'type': ['number', 'string', 'null']},
    },
}


VULNERABILITY_DETAIL_ROW_SCHEMA = {
    'type': 'object',
    'required': [
        'cve_id', 'title', 'vendor', 'product', 'severity',
        'priority_score', 'patch_priority', 'what_happened',
        'why_matters', 'how_to_respond', 'source_urls',
    ],
    'properties': {
        'cve_id': {'type': 'string'},
        'title': {'type': 'string'},
        'vendor': NULLABLE_STRING,
        'product': NULLABLE_STRING,
        'severity': NULLABLE_STRING,
        'priority_score': {'type': 'number'},
        'patch_priority': {'type': 'string'},
        'what_happened': {'type': 'string'},
        'why_matters': {'type': 'string'},
        'how_to_respond': {'type': 'string'},
        'source_urls': STRING_ARRAY,
    },
}


ENRICHED_REPORT_SCHEMA = {
    'type': 'object',
    'required': [
        'title', 'executive_summary', 'research_scope', 'weekly_risk_trend',
        'vulnerability_detail_table', 'remediation_playbook',
        'management_brief', 'appendix', 'verification',
    ],
    'properties': {
        'title': {'type': 'string'},
        'executive_summary': {
            'type': 'object',
            'required': ['summary', 'key_findings'],
            'properties': {
                'summary': {'type': 'string'},
                'key_findings': STRING_ARRAY,
            },
        },
        'research_scope': {
            'type': 'object',
            'required': ['summary', 'criteria'],
            'properties': {
                'summary': {'type': 'string'},
                'criteria': STRING_ARRAY,
            },
        },
        'weekly_risk_trend': {
            'type': 'object',
            'required': ['summary', 'trend_points'],
            'properties': {
                'summary': {'type': 'string'},
                'trend_points': STRING_ARRAY,
            },
        },
        'vulnerability_detail_table': {
            'type': 'object',
            'required': ['rows'],
            'properties': {
                'rows': {'type': 'array', 'items': VULNERABILITY_DETAIL_ROW_SCHEMA},
            },
        },
        'remediation_playbook': {
            'type': 'object',
            'required': ['summary', 'actions'],
            'properties': {
                'summary': {'type': 'string'},
                'actions': {
                    'type': 'array',
                    'items': {
                        'type': 'object',
                        'required': ['priority', 'action', 'cve_ids'],
                        'properties': {
                            'priority': {'type': 'string'},
                            'action': {'type': 'string'},
                            'cve_ids': STRING_ARRAY,
                        },
                    },
                },
            },
        },
        'management_brief': {
            'type': 'object',
            'required': ['summary', 'business_impact', 'decisions_needed'],
            'properties': {
                'summary': {'type': 'string'},
                'business_impact': {'type': 'string'},
                'decisions_needed': STRING_ARRAY,
            },
        },
        'appendix': {
            'type': 'object',
            'required': ['source_references', 'metrics'],
            'properties': {
                'source_references': {
                    'type': 'array',
                    'items': {
                        'type': 'object',
                        'required': ['cve_id', 'url'],
                        'properties': {
                            'cve_id': {'type': 'string'},
                            'url': {'type': 'string'},
                            'source_type': NULLABLE_STRING,
                        },
                    },
                },
                'metrics': {'type': 'object'},
            },
        },
        'verification': {
            'type': 'object',
            'required': ['python_checks', 'ai_checks', 'issues', 'verified_at'],
            'properties': {
                'python_checks': {'type': 'string'},
                'ai_checks': {'type': 'string'},
                'issues': {
                    'type': 'array',
                    'items': {'type': 'string'},
                },
                'unsupported_claims': {
                    'type': 'array',
                    'items': {'type': 'string'},
                },
                'verified_at': {'type': 'string'},
            },
        },
    },
}


def validate_source_evidence_card(card):
    validate(instance=card, schema=SOURCE_EVIDENCE_CARD_SCHEMA)
    return card


def validate_vulnerability_card(card):
    validate(instance=card, schema=VULNERABILITY_CARD_SCHEMA)
    return card


def validate_enriched_report(report):
    validate(instance=report, schema=ENRICHED_REPORT_SCHEMA)
    return report

