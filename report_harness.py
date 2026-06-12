import base64
import hashlib
import html
import json
import os
import random
import re
import string
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from string import Template
from zoneinfo import ZoneInfo

import requests
from bson import ObjectId, json_util
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from flask import current_app, render_template
from jsonschema import ValidationError, validate
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from mongo import get_vulnerabilities_database, get_web_database
from review_data import (
    MAX_EXPORT_SELECTIONS,
    canonical_selection_id,
    resolve_vulnerability_document,
    review_views,
)


WORKER_LOCK = threading.Lock()
DEBUG_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.cursor', 'debug-7a435c.log')
def _debug_log(hypothesis_id, location, message, data=None, run_id='pre-fix'):
    # region agent log
    try:
        payload = {
            'sessionId': '7a435c',
            'runId': run_id,
            'hypothesisId': hypothesis_id,
            'location': location,
            'message': message,
            'data': data or {},
            'timestamp': int(time.time() * 1000),
        }
        with open(DEBUG_LOG_PATH, 'a', encoding='utf-8') as log_file:
            log_file.write(json.dumps(payload, ensure_ascii=False, default=str) + '\n')
    except OSError:
        pass
    # endregion


def _looks_like_utf8_mojibake(text):
    if not isinstance(text, str) or not text:
        return False
    if re.search(r'[\u4e00-\u9fff]', text):
        return False
    try:
        repaired = text.encode('latin-1').decode('utf-8')
    except (UnicodeDecodeError, UnicodeEncodeError):
        return False
    return bool(re.search(r'[\u4e00-\u9fff]', repaired))


DEFAULT_JSON_ERROR_MESSAGE = (
    'The JSON above is invalid.\n\nError:\n${error}\n\n'
    'Fix it and return only valid JSON. No Markdown, no explanation, no extra text. '
    'Keep the original fields and meaning. Make only the minimum changes needed so it can parse '
    'with `json.loads()`.'
)
REPORT_TEMPLATE = 'generated_report.html'
GENERATION_MODES = {'company_ai', 'template'}
LEGACY_GENERATION_MODES = {'ai': 'company_ai'}
REPORT_LANGUAGES = {
    'en': 'English',
    'zh': 'Traditional Chinese',
    'ch': 'Simplified Chinese',
}
HTML_LANGUAGE_CODES = {'en': 'en', 'zh': 'zh-Hant', 'ch': 'zh-Hans'}
REPORT_LABELS = {
    'en': {
        'report_title': 'Cybersecurity Report',
        'generated': 'Generated {date} from {count} source records.',
        'executive_summary': 'Executive Summary',
        'important_vulnerabilities': 'Important Vulnerabilities',
        'trends': 'Trends',
        'high_priority_vulnerabilities': 'High-Priority Vulnerabilities',
        'affected': 'Affected',
        'references': 'References',
        'recommended_actions': 'Recommended Actions',
        'strategic_recommendations': 'Strategic Recommendations',
    },
    'zh': {
        'report_title': '網絡安全報告',
        'generated': '於 {date} 根據 {count} 筆來源記錄產生。',
        'executive_summary': '執行摘要',
        'important_vulnerabilities': '重要漏洞',
        'trends': '趨勢',
        'high_priority_vulnerabilities': '高優先級漏洞',
        'affected': '受影響項目',
        'references': '參考資料',
        'recommended_actions': '建議措施',
        'strategic_recommendations': '策略建議',
    },
    'ch': {
        'report_title': '网络安全报告',
        'generated': '于 {date} 根据 {count} 条来源记录生成。',
        'executive_summary': '执行摘要',
        'important_vulnerabilities': '重要漏洞',
        'trends': '趋势',
        'high_priority_vulnerabilities': '高优先级漏洞',
        'affected': '受影响项目',
        'references': '参考资料',
        'recommended_actions': '建议措施',
        'strategic_recommendations': '战略建议',
    },
}
HIGHLIGHT_TABLE_SCHEMA = {
    'type': 'object',
    'required': ['headers', 'rows'],
    'properties': {
        'caption': {'type': 'string'},
        'headers': {
            'type': 'array',
            'items': {'type': 'string'},
            'minItems': 1,
            'maxItems': 12,
        },
        'rows': {
            'type': 'array',
            'maxItems': 50,
            'items': {
                'type': 'array',
                'items': {'type': 'string'},
            },
        },
    },
}
HIGHLIGHT_PROPERTIES = {
    'title': {'type': 'string'},
    'code': {'type': 'string'},
    'severity': {'type': 'string'},
    'summary': {'type': 'string'},
    'affected': {'type': 'array', 'items': {'type': 'string'}},
    'references': {'type': 'array', 'items': {'type': 'string'}},
    'table': HIGHLIGHT_TABLE_SCHEMA,
}
AI_HIGHLIGHT_SCHEMA = {
    'type': 'object',
    'required': ['summary'],
    'properties': HIGHLIGHT_PROPERTIES,
}
REPORT_HIGHLIGHT_SCHEMA = {
    'type': 'object',
    'required': ['title', 'summary'],
    'properties': HIGHLIGHT_PROPERTIES,
}
REPORT_SCHEMA = {
    'type': 'object',
    'required': ['title', 'executive_summary', 'highlights', 'trends', 'recommendations'],
    'properties': {
        'title': {'type': 'string'},
        'executive_summary': {'type': 'string'},
        'highlights': {
            'type': 'array',
            'items': REPORT_HIGHLIGHT_SCHEMA,
        },
        'trends': {'type': 'array', 'items': {'type': 'string'}},
        'recommendations': {'type': 'array', 'items': {'type': 'string'}},
    },
}
ITEM_SCHEMA = {
    'type': 'object',
    'required': ['highlight', 'recommendations'],
    'properties': {
        'highlight': AI_HIGHLIGHT_SCHEMA,
        'recommendations': {'type': 'array', 'items': {'type': 'string'}},
    },
}
FINAL_SCHEMA = {
    'type': 'object',
    'required': ['executive_summary', 'trends', 'recommendations'],
    'properties': {
        'title': {'type': 'string'},
        'executive_summary': {'type': 'string'},
        'trends': {'type': 'array', 'items': {'type': 'string'}},
        'recommendations': {'type': 'array', 'items': {'type': 'string'}},
    },
}


def _fixed_report_title(report_language):
    labels = REPORT_LABELS.get(report_language, REPORT_LABELS['en'])
    return labels['report_title']


def _clean(value, depth=0):
    if depth > 5:
        return None
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if key == 'raw':
                continue
            result = _clean(item, depth + 1)
            if result not in (None, '', [], {}):
                cleaned[key] = result
        return cleaned
    if isinstance(value, list):
        cleaned = [_clean(item, depth + 1) for item in value[:100]]
        return [item for item in cleaned if item not in (None, '', [], {})]
    if isinstance(value, str):
        return value[:12000]
    if value is None:
        return None
    return value


def compact_document(document):
    details = document.get('details') or {}
    detail_fields = {
        'description', 'summary', 'impacts', 'impact', 'severity', 'status',
        'affected', 'affected_products', 'systems_affected', 'recommendation',
        'recommendations', 'solution', 'solutions', 'remediation', 'mitigation',
        'mitigations', 'references', 'reference_links', 'related_links',
    }
    if isinstance(details, dict) and detail_fields.intersection(details):
        normalized = details
    elif isinstance(details, dict):
        normalized = next(
            (value for value in details.values() if isinstance(value, dict)),
            {},
        )
    else:
        normalized = {}
    compacted = _clean({
        'id': str(document.get('_id', '')),
        'type': document.get('type'),
        'code': document.get('cve_code') or document.get('cve') or document.get('code'),
        'title': document.get('title'),
        'vulnerability_type': document.get('vuln_type'),
        'disclosure_date': document.get('disclosure_date'),
        'scraped_at': document.get('scraped_at'),
        'status': document.get('status'),
        'severity': document.get('severity'),
        'summary': document.get('summary') or document.get('description') or document.get('impacts'),
        'affected': document.get('affected') or document.get('affected_products'),
        'recommendations': (
            document.get('recommendations')
            or document.get('recommendation')
            or document.get('solutions')
            or document.get('solution')
        ),
        'references': document.get('references') or document.get('reference_links'),
        'source': document.get('source'),
        'details': normalized,
    })
    if estimate_tokens(compacted) > 12000:
        compacted['details'] = {
            'description': str(normalized.get('description') or normalized.get('summary') or '')[:12000],
            'affected': _clean(
                normalized.get('affected')
                or normalized.get('affected_products')
                or normalized.get('systems_affected')
                or [],
            ),
            'recommendation': str(
                normalized.get('recommendation')
                or normalized.get('solution')
                or normalized.get('solutions')
                or '',
            )[:8000],
            'references': _clean(
                normalized.get('references')
                or normalized.get('reference_links')
                or normalized.get('related_links')
                or [],
            ),
        }
        compacted = _clean(compacted)
    return compacted


def compact_details(details, config):
    deny_keys = {str(key).casefold() for key in config['REPORT_DENY_KEYS']}
    deny_prefixes = tuple(str(prefix).casefold() for prefix in config['REPORT_DENY_PREFIXES'])
    max_depth = config['REPORT_MAX_DEPTH']
    max_list = config['REPORT_MAX_LIST_ITEMS']
    max_string = config['REPORT_MAX_STRING_CHARS']

    def clean(value, depth=0):
        if depth > max_depth:
            return None
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                normalized = str(key).casefold()
                if normalized in deny_keys or normalized.startswith(deny_prefixes):
                    continue
                cleaned = clean(item, depth + 1)
                if cleaned not in (None, '', [], {}):
                    result[str(key)] = cleaned
            return result
        if isinstance(value, (list, tuple, set)):
            result = []
            seen = set()
            for item in list(value)[:max_list]:
                cleaned = clean(item, depth + 1)
                if cleaned in (None, '', [], {}):
                    continue
                marker = json.dumps(cleaned, ensure_ascii=False, sort_keys=True, default=str)
                if marker not in seen:
                    seen.add(marker)
                    result.append(cleaned)
            return result
        if isinstance(value, str):
            return ' '.join(html.unescape(value).split())[:max_string]
        if value is None:
            return None
        return value

    if not isinstance(details, dict):
        raise ValueError('Each report input must contain a details object.')
    return clean(details)


def compact_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), default=str)


def estimate_tokens(value):
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return max(1, (len(text) + 3) // 4)


def json_error_prompt(provider, error):
    template = getattr(provider, 'json_error_message', DEFAULT_JSON_ERROR_MESSAGE)
    return Template(template).safe_substitute(error=str(error))


def _item_schema_example(report_language):
    language = REPORT_LANGUAGES[report_language]
    return {
        'highlight': {
            'code': 'CVE identifier or source code',
            'severity': 'Severity if known',
            'summary': f'Evidence-based summary in {language}.',
            'affected': [f'Affected product in {language}'],
            'references': ['https://example.com'],
            'table': {
                'caption': f'Optional table caption in {language}',
                'headers': ['Product', 'Version', 'Status'],
                'rows': [['Example product', '1.0', 'Affected']],
            },
        },
        'recommendations': [f'Prioritized defensive action in {language}.'],
    }


def _response_schema_example(report_language):
    language = REPORT_LANGUAGES[report_language]
    return {
        'title': f'{language} Cybersecurity Report title',
        'executive_summary': f'Concise executive summary in {language}.',
        'highlights': [{
            'title': f'Vulnerability title in {language}',
            'code': 'CVE identifier or source code',
            'severity': 'Severity if known',
            'summary': f'Evidence-based summary in {language}.',
            'affected': [f'Affected product in {language}'],
            'references': ['https://example.com'],
        }],
        'trends': [f'Trends in {language}.'],
        'recommendations': [f'Prioritized defensive action in {language}.'],
    }


class ProviderError(RuntimeError):
    pass


def _parse_json_text(content):
    if not isinstance(content, str) or not content.strip():
        raise ProviderError('AI provider returned an empty response.')
    text = content.strip()
    fenced = re.fullmatch(r'```(?:json)?\s*(.*?)\s*```', text, flags=re.IGNORECASE | re.DOTALL)
    if fenced:
        text = fenced.group(1)
    try:
        result = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProviderError(f'AI provider returned invalid JSON: {exc}') from exc
    if not isinstance(result, dict):
        raise ProviderError('AI provider JSON response must be an object.')
    return result


class CompanyAIProvider:
    retains_conversation_context = True

    def __init__(self, config):
        self.base_url = config['COMPANY_AI_BASE_URL'].rstrip('/')
        self.api_base = self.base_url + '/api'
        self.smartbot_base = self.base_url + '/smartbot/openapi/im'
        self.username = config['COMPANY_AI_USERNAME']
        self.password = config['COMPANY_AI_PASSWORD']
        self.start_prompt = config['COMPANY_AI_START_PROMPT']
        self.summary_prompt = config.get('COMPANY_AI_SUMMARY_PROMPT', '')
        self.public_key_b64 = config['COMPANY_AI_PUBLIC_KEY_B64']
        self.sign_secret = config['COMPANY_AI_SIGN_SECRET']
        self.api_timezone = config['COMPANY_AI_API_TIMEZONE']
        self.sse_delay = config['COMPANY_AI_SSE_DELAY_SECONDS']
        self.conversation_id = None
        self.system_token = None
        self.bot_token = None
        self.model = config['COMPANY_AI_MODEL']
        self.owner_account = config['COMPANY_AI_OWNER_ACCOUNT']
        self.platform_id = config['COMPANY_AI_PLATFORM_ID']
        self.qa_type = config['COMPANY_AI_QA_TYPE']
        self.from_source = config['COMPANY_AI_FROM_SOURCE']
        self.use_think = config['COMPANY_AI_USE_THINK']
        self.user_prompt = config['COMPANY_AI_USER_PROMPT']
        self.dataset_ids = config['COMPANY_AI_DATASET_IDS']
        self.file_ids = config['COMPANY_AI_FILE_IDS']
        self.max_output = config['COMPANY_AI_MAX_OUTPUT_TOKENS']
        self.timeout = config['COMPANY_AI_TIMEOUT_SECONDS']
        self.retries = config['COMPANY_AI_RETRIES']
        self.json_error_message = config.get('REPORT_JSON_ERROR_MESSAGE', DEFAULT_JSON_ERROR_MESSAGE)

    @staticmethod
    def _normalize_bearer(token):
        token = (token or '').strip()
        if not token:
            return ''
        return token if token.lower().startswith('bearer ') else f'Bearer {token}'

    @staticmethod
    def _sort_asc(value):
        if isinstance(value, dict):
            return {
                key: CompanyAIProvider._sort_asc(value[key])
                for key in sorted(value)
                if value[key] not in (None, '')
            }
        if isinstance(value, list):
            return [CompanyAIProvider._sort_asc(item) for item in value]
        return value

    def _request_id(self, length=20):
        alphabet = string.ascii_lowercase + string.digits
        return ''.join(random.choice(alphabet) for _ in range(length))

    def _timestamp(self):
        return datetime.now(ZoneInfo(self.api_timezone)).strftime('%Y%m%d%H%M%S')

    def _signature(self, request_id, timestamp, body, url_path):
        payload = self._sort_asc({
            **body,
            '_url_': url_path,
            'requestId': request_id,
            'timestamp': timestamp,
        })
        text = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
        return hashlib.md5((self.sign_secret + text).encode('utf-8')).hexdigest().upper()

    def _api_headers(self, url_path, body=None, authorization=''):
        body = body or {}
        request_id = self._request_id()
        timestamp = self._timestamp()
        return {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en_US',
            'Accept-Time-Zone': self.api_timezone,
            'Authorization': authorization,
            'Content-Type': 'application/json',
            'Origin': self.base_url,
            'Referer': self.base_url + '/',
            'User-Agent': 'Mozilla/5.0',
            'platform': 'pc',
            'requestId': request_id,
            'timestamp': timestamp,
            'signature': self._signature(request_id, timestamp, body, url_path),
        }

    def _smartbot_headers(self, accept='application/json, text/plain, */*'):
        return {
            'Accept': accept,
            'Accept-Language': 'en_US',
            'Authorization': self.bot_token,
            'x-authorization': self.system_token,
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Content-Type': 'application/json',
            'Origin': self.base_url,
            'Referer': self.base_url + '/',
            'User-Agent': 'Mozilla/5.0',
        }

    def _validate_config(self):
        required = {
            'COMPANY_AI_BASE_URL': self.base_url,
            'COMPANY_AI_USERNAME': self.username,
            'COMPANY_AI_PASSWORD': self.password,
            'COMPANY_AI_START_PROMPT': self.start_prompt,
            'COMPANY_AI_PUBLIC_KEY_B64': self.public_key_b64,
            'COMPANY_AI_SIGN_SECRET': self.sign_secret,
            'COMPANY_AI_MODEL': self.model,
            'COMPANY_AI_OWNER_ACCOUNT': self.owner_account,
        }
        missing = [key for key, value in required.items() if not value]
        if missing:
            raise ProviderError(f'Company AI configuration is missing: {", ".join(missing)}.')

    def _encrypt_password(self):
        clean = ''.join(self.public_key_b64.split())
        lines = [clean[index:index + 64] for index in range(0, len(clean), 64)]
        pem = (
            '-----BEGIN PUBLIC KEY-----\n'
            + '\n'.join(lines)
            + '\n-----END PUBLIC KEY-----\n'
        ).encode('ascii')
        public_key = serialization.load_pem_public_key(pem)
        encrypted = public_key.encrypt(self.password.encode('utf-8'), padding.PKCS1v15())
        return base64.b64encode(encrypted).decode('ascii')

    def authenticate(self):
        self._validate_config()
        login_path = '/sys/login'
        login_body = {'username': self.username, 'password': self._encrypt_password()}
        response = requests.post(
            self.api_base + login_path,
            headers=self._api_headers(login_path, login_body),
            json=login_body,
            timeout=self.timeout,
        )
        response.raise_for_status()
        body = response.json()
        if body.get('success') is not True or not body.get('data'):
            raise ProviderError('Company AI login failed.')
        self.system_token = self._normalize_bearer(body['data'])

        token_path = '/sys/getBotToken'
        response = requests.get(
            self.api_base + token_path,
            headers=self._api_headers(token_path, authorization=self.system_token),
            timeout=self.timeout,
        )
        response.raise_for_status()
        body = response.json()
        if body.get('success') is not True or not body.get('data'):
            raise ProviderError('Company AI bot-token request failed.')
        self.bot_token = self._normalize_bearer(body['data'])

    def _chat_payload(self, content):
        return {
            'content': content,
            'conversationId': self.conversation_id,
            'datasets': {'datasetIds': self.dataset_ids, 'fileIds': self.file_ids},
            'fromSource': self.from_source,
            'isUseThink': self.use_think,
            'modelName': self.model,
            'ownerAccount': self.owner_account,
            'platformId': self.platform_id,
            'qaType': self.qa_type,
            'userPrompt': self.user_prompt,
        }

    def create_room(self, prime_prompt=None):
        self.authenticate()
        self.conversation_id = str(uuid.uuid4())
        prompt = self.start_prompt if prime_prompt is None else prime_prompt
        if prompt:
            self._chat_once(prompt)
        return self.conversation_id

    def _open_stream(self):
        headers = self._smartbot_headers('text/event-stream')
        headers.pop('Content-Type', None)
        return requests.get(
            self.smartbot_base + '/sse/createSse',
            headers=headers,
            params={
                'uid': self.conversation_id,
                'platformId': self.platform_id,
                'type': 'normal_chat',
            },
            stream=True,
            timeout=(10, self.timeout),
        )

    def _decode_sse_line(self, raw_line):
        if isinstance(raw_line, bytes):
            return raw_line.decode('utf-8')
        return raw_line

    def _listen_sse(self):
        chunks = []
        with self._open_stream() as stream:
            stream.raise_for_status()
            _debug_log(
                'H3',
                'report_harness.CompanyAIProvider._listen_sse',
                'sse_stream_opened',
                {'encoding': getattr(stream, 'encoding', None)},
            )
            for raw_line in stream.iter_lines(chunk_size=1):
                if not raw_line:
                    continue
                # region agent log
                if chunks == [] and (
                    (isinstance(raw_line, bytes) and raw_line.startswith(b'data:'))
                    or (isinstance(raw_line, str) and raw_line.startswith('data:'))
                ):
                    prefix = (
                        raw_line[:80].decode('utf-8', errors='replace')
                        if isinstance(raw_line, bytes)
                        else raw_line[:80]
                    )
                    _debug_log(
                        'H1',
                        'report_harness.CompanyAIProvider._listen_sse',
                        'sse_first_data_line',
                        {
                            'raw_line_type': type(raw_line).__name__,
                            'stream_encoding': getattr(stream, 'encoding', None),
                            'raw_prefix': prefix,
                        },
                    )
                # endregion
                try:
                    line = self._decode_sse_line(raw_line)
                except UnicodeDecodeError as exc:
                    _debug_log(
                        'H3',
                        'report_harness.CompanyAIProvider._listen_sse',
                        'sse_utf8_decode_failed',
                        {'error': str(exc)},
                    )
                    raise ProviderError(f'Company AI SSE line is not valid UTF-8: {exc}') from exc
                if not line.startswith('data:'):
                    continue
                try:
                    event = json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    continue
                if event.get('type') == 'heartbeat':
                    continue
                if event.get('event') == 'message':
                    chunk = event.get('answer_content', '')
                    chunks.append(chunk)
                if event.get('event') == 'message_end':
                    answer = ''.join(chunks)
                    _debug_log(
                        'H1',
                        'report_harness.CompanyAIProvider._listen_sse',
                        'sse_message_complete',
                        {
                            'chunk_count': len(chunks),
                            'has_cjk': bool(re.search(r'[\u4e00-\u9fff]', answer)),
                            'looks_mojibake': _looks_like_utf8_mojibake(answer),
                            'sample': answer[:120],
                        },
                    )
                    return answer
        raise ProviderError('Company AI stream ended before message_end.')

    def _send_message(self, content):
        response = requests.post(
            self.smartbot_base + '/biz/createChat',
            headers=self._smartbot_headers(),
            json=self._chat_payload(content),
            timeout=self.timeout,
        )
        response.raise_for_status()

    def _chat_once(self, content, *, wait_for_response=True):
        if not wait_for_response:
            time.sleep(self.sse_delay)
            self._send_message(content)
            return ''

        result = {'answer': '', 'error': None}

        def listen():
            try:
                result['answer'] = self._listen_sse()
            except Exception as exc:
                result['error'] = exc

        thread = threading.Thread(target=listen, daemon=True)
        thread.start()
        time.sleep(self.sse_delay)
        self._send_message(content)
        thread.join()
        if result['error']:
            raise result['error']
        return result['answer']

    def delete_room(self):
        if not self.conversation_id or not self.system_token or not self.bot_token:
            return
        response = requests.delete(
            self.smartbot_base + '/biz/deleteChat/' + self.conversation_id,
            headers=self._smartbot_headers(),
            timeout=self.timeout,
        )
        response.raise_for_status()
        body = response.json()
        if body.get('success') is not True or body.get('data') is not True:
            raise ProviderError(body.get('msg') or 'Company AI room deletion failed.')

    def complete_json(self, system_prompt, user_prompt):
        self._validate_config()
        if not self.conversation_id:
            raise ProviderError('Company AI room has not been created.')
        prompt = f'{system_prompt}\n\n{user_prompt}'
        error = None
        for _ in range(self.retries + 1):
            try:
                return _parse_json_text(self._chat_once(prompt)), {}
            except requests.RequestException as exc:
                error = exc
            except (KeyError, ValueError, ProviderError) as exc:
                error = exc
                prompt = json_error_prompt(self, exc)
        raise ProviderError(str(error))


def _fit_batches(records, budget):
    batches, batch, tokens = [], [], 0
    for record in records:
        record_tokens = estimate_tokens(record)
        if batch and tokens + record_tokens > budget:
            batches.append(batch)
            batch, tokens = [], 0
        batch.append(record)
        tokens += record_tokens
    if batch:
        batches.append(batch)
    return batches


def _summarize_batches(provider, records, input_budget, report_language):
    language = REPORT_LANGUAGES[report_language]
    summaries = records
    while estimate_tokens(summaries) > input_budget:
        reduced = []
        for batch in _fit_batches(summaries, max(input_budget // 2, 1000)):
            result, _ = provider.complete_json(
                f'Summarize vulnerability records for a {language} cybersecurity report. '
                f'Write all descriptive text in {language}. '
                'Return json with a "records" array. Preserve identifiers, evidence, affected '
                'products, severity, recommendations, and references. Do not invent facts.',
                'Input records:\n' + json.dumps(batch, ensure_ascii=False),
            )
            batch_records = result.get('records')
            if not isinstance(batch_records, list):
                raise ProviderError('AI batch summary did not contain a records array.')
            reduced.extend(batch_records)
        if estimate_tokens(reduced) >= estimate_tokens(summaries):
            raise ProviderError('Unable to reduce input within the configured context limit.')
        summaries = reduced
    return summaries


def generate_report_data(provider, records, context_limit, report_language='en'):
    if report_language not in REPORT_LANGUAGES:
        raise ValueError('Report language must be "en", "zh", or "ch".')
    language = REPORT_LANGUAGES[report_language]
    input_budget = context_limit - provider.max_output - 3000
    if input_budget < 2000:
        raise ProviderError('AI context budget is too small for report generation.')
    records = _summarize_batches(provider, records, input_budget, report_language)
    system = (
        f'Write a {language} cybersecurity report from supplied evidence. '
        f'Write all descriptive text in {language}, while preserving identifiers and URLs. '
        'Return valid json only. Do not invent facts. Preserve CVE identifiers and URLs. '
        'Follow this JSON shape exactly: '
        + json.dumps(_response_schema_example(report_language), ensure_ascii=False)
    )
    result, usage = provider.complete_json(
        system,
        'Report evidence:\n' + json.dumps(records, ensure_ascii=False),
    )
    validate(instance=result, schema=REPORT_SCHEMA)
    return result, usage


def generate_item_data(provider, details, identifier, report_language, retries, position=1):
    language = REPORT_LANGUAGES[report_language]
    schema_example = _item_schema_example(report_language)
    system = (
        f'Write one cybersecurity vulnerability report item in {language}. '
        'Use only the provided JSON details. Do not invent facts. Preserve identifiers and URLs. '
        'Do not return highlight.title; the system assigns titles from source metadata. '
        'Include highlight.table only when structured comparison (products, versions, patches, '
        'or CVE mapping) is clearer as a table than prose. Use caption, headers, and rows. '
        'Omit table when unnecessary. '
        'Return valid JSON only using this exact shape: '
        + compact_json(schema_example)
    )
    prompt = 'Review details:' + compact_json(details)
    error = None
    for attempt in range(retries + 1):
        try:
            result, usage = provider.complete_json(system, prompt)
            validate(instance=result, schema=ITEM_SCHEMA)
            return _finalize_item_result(result, details, identifier, position), usage
        except (ProviderError, ValidationError) as exc:
            error = exc
            if isinstance(exc, ValidationError) and hasattr(provider, 'prepare_json_correction'):
                provider.prepare_json_correction(result)
            prompt = json_error_prompt(provider, exc)
    raise ProviderError(str(error))


def generate_final_data(provider, item_results, report_language, retries, config):
    language = REPORT_LANGUAGES[report_language]
    summary_prompt = config.get('COMPANY_AI_SUMMARY_PROMPT', '')
    if not summary_prompt:
        raise ProviderError('Company AI summary prompt is not configured.')
    system = Template(summary_prompt).substitute(language=language)
    prompt = 'Processed review results:' + compact_json(item_results)
    error = None
    for _ in range(retries + 1):
        try:
            result, usage = provider.complete_json(system, prompt)
            validate(instance=result, schema=FINAL_SCHEMA)
            result['title'] = _fixed_report_title(report_language)
            return result, usage
        except (ProviderError, ValidationError) as exc:
            error = exc
            if isinstance(exc, ValidationError) and hasattr(provider, 'prepare_json_correction'):
                provider.prepare_json_correction(result)
            prompt = json_error_prompt(provider, exc)
    raise ProviderError(str(error))


def _strip_html(value):
    if value in (None, ''):
        return ''
    text = html.unescape(str(value))
    text = re.sub(r'<br\s*/?>', ' ', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)
    return ' '.join(html.unescape(text).split())


def _string_values(value):
    if value in (None, ''):
        return []
    if isinstance(value, dict):
        values = []
        for item in value.values():
            values.extend(_string_values(item))
        return values
    if isinstance(value, (list, tuple, set)):
        values = []
        for item in value:
            values.extend(_string_values(item))
        return values
    return [str(value).strip()]


def _unique_strings(*values):
    unique = []
    seen = set()
    for value in values:
        for item in _string_values(value):
            key = item.casefold()
            if item and key not in seen:
                seen.add(key)
                unique.append(item)
    return unique


def _first_value(record, details, *fields):
    for source in (record, details):
        for field in fields:
            values = _unique_strings(source.get(field))
            if values:
                return values[0]
    return ''


def _all_values(record, details, *fields):
    return _unique_strings(*[
        source.get(field)
        for source in (record, details)
        for field in fields
    ])


def _template_first_value(record, details, *fields):
    return _strip_html(_first_value(record, details, *fields))


def _template_all_values(record, details, *fields):
    return [_strip_html(value) for value in _all_values(record, details, *fields)]


def _normalized_details_root(details):
    if not isinstance(details, dict):
        return {}
    if len(details) == 1:
        inner = next(iter(details.values()))
        return inner if isinstance(inner, dict) else details
    return details


def _item_title_from_details(details, identifier, position, record=None):
    record = record if isinstance(record, dict) else {}
    normalized = _normalized_details_root(details)
    title = _template_first_value(record, normalized, 'title')
    code = _template_first_value(record, normalized, 'code', 'cve', 'cve_code')
    return title or code or identifier or f'Vulnerability record {position}'


def _finalize_item_result(result, details, identifier, position, record=None):
    finalized = dict(result)
    highlight = dict(finalized.get('highlight') or {})
    highlight['title'] = _item_title_from_details(details, identifier, position, record)
    finalized['highlight'] = highlight
    return finalized


def _source_record_for_item(item):
    record = {}
    if isinstance(item.get('source_record'), dict):
        record.update(item['source_record'])
    if item.get('source_collection') and item.get('selection_id'):
        document = resolve_vulnerability_document(
            get_vulnerabilities_database(),
            item['source_collection'],
            item['selection_id'],
            {'title': 1, 'code': 1, 'cve': 1, 'cve_code': 1},
        )
        if document:
            for field in ('title', 'code', 'cve', 'cve_code'):
                if document.get(field):
                    record.setdefault(field, document[field])
    return record


def generate_template_report_data(records):
    if not records:
        raise ValueError('At least one vulnerability record is required.')

    highlights = []
    recommendations = []
    severities = {}
    for position, record in enumerate(records, start=1):
        details = record.get('details') if isinstance(record.get('details'), dict) else {}
        code = _template_first_value(record, details, 'code', 'cve', 'cve_code')
        severity = _template_first_value(record, details, 'severity', 'status', 'risk', 'priority')
        summary = _template_first_value(
            record, details, 'description', 'summary', 'impacts', 'impact',
        )
        title = (
            _template_first_value(record, details, 'title')
            or code
            or f'Vulnerability record {position}'
        )
        if not summary:
            summary = 'No description or summary was provided in the source record.'

        highlights.append({
            'title': title,
            'code': code,
            'severity': severity,
            'summary': summary,
            'affected': _template_all_values(
                record, details, 'affected', 'affected_products', 'systems_affected', 'products',
            ),
            'references': _template_all_values(
                record, details, 'references', 'reference_links', 'related_links', 'urls',
            ),
        })
        recommendations.extend(_template_all_values(
            record, details, 'recommendation', 'recommendations', 'solution', 'solutions',
            'remediation', 'mitigation', 'mitigations',
        ))
        if severity:
            severity_key = severity.casefold()
            if severity_key not in severities:
                severities[severity_key] = {'label': severity, 'count': 0}
            severities[severity_key]['count'] += 1

    severity_summary = ', '.join(
        f"{item['label']}: {item['count']}"
        for item in sorted(severities.values(), key=lambda item: item['label'].casefold())
    )
    executive_summary = (
        f'This report contains {len(highlights)} vulnerability '
        f'{"record" if len(highlights) == 1 else "records"}.'
    )
    if severity_summary:
        executive_summary += f' Source-provided severity or status counts: {severity_summary}.'

    trends = [f'Total vulnerability records: {len(highlights)}.']
    if severity_summary:
        trends.append(f'Source-provided severity or status counts: {severity_summary}.')

    report = {
        'title': _fixed_report_title('en'),
        'executive_summary': executive_summary,
        'highlights': highlights,
        'trends': trends,
        'recommendations': _unique_strings(recommendations) or [
            'No recommendations were provided in the source records.',
        ],
    }
    validate(instance=report, schema=REPORT_SCHEMA)
    return report


def resolve_review_selections(selections):
    if not isinstance(selections, list) or not selections or len(selections) > MAX_EXPORT_SELECTIONS:
        raise ValueError('Select between 1 and 500 vulnerability records.')
    database = get_vulnerabilities_database()
    views = review_views(database)
    inputs = []
    for selection in selections:
        view = views.get(selection.get('collection')) if isinstance(selection, dict) else None
        selection_id = selection.get('selection_id') if isinstance(selection, dict) else None
        if view is None or not isinstance(selection_id, str):
            raise ValueError('Invalid Vulnerability Reviews selection.')
        source_collection = view['options']['viewOn']
        document = resolve_vulnerability_document(
            database,
            source_collection,
            selection_id,
            {'_id': 1},
        )
        if document is None:
            raise ValueError(f'Selected vulnerability not found: {selection_id}')
        resolved_id = canonical_selection_id(document)
        inputs.append({
            'collection': selection['collection'],
            'source_collection': source_collection,
            'selection_id': resolved_id,
        })
    return inputs


def _job_collection():
    return get_web_database()['report_jobs']


def _input_collection():
    return get_web_database()['report_job_inputs']


def _result_collection():
    return get_web_database()['report_job_results']


def create_job(inputs, input_source, generation_mode='company_ai', report_language='en'):
    if not inputs:
        raise ValueError('At least one vulnerability record is required.')
    generation_mode = LEGACY_GENERATION_MODES.get(generation_mode, generation_mode)
    if generation_mode not in GENERATION_MODES:
        raise ValueError('Generation mode must be "company_ai" or "template".')
    if report_language not in REPORT_LANGUAGES:
        raise ValueError('Report language must be "en", "zh", or "ch".')
    if generation_mode == 'template':
        report_language = 'en'
    if len(inputs) > MAX_EXPORT_SELECTIONS:
        raise ValueError(f'Reports are limited to {MAX_EXPORT_SELECTIONS} vulnerability records.')
    queued_inputs = []
    for position, item in enumerate(inputs):
        if input_source == 'review_selections':
            queued = {
                'source_collection': item['source_collection'],
                'selection_id': item['selection_id'],
                'identifier': item['selection_id'],
            }
        else:
            if not isinstance(item.get('details'), dict):
                raise ValueError('Each uploaded document must contain a details object.')
            source_record = {
                key: item[key]
                for key in ('title', 'code', 'cve', 'cve_code')
                if item.get(key)
            }
            queued = {
                'details': item['details'],
                'identifier': str(item.get('_id') or item.get('code') or item.get('title') or position + 1),
            }
            if source_record:
                queued['source_record'] = source_record
        queued_inputs.append({'position': position, **queued})
    now = datetime.now(timezone.utc)
    if generation_mode == 'company_ai':
        provider = current_app.config['COMPANY_AI_BASE_URL']
        model = 'Company AI'
    else:
        provider = None
        model = 'Fixed Template'
    job = {
        'generation_mode': generation_mode,
        'effective_generation_mode': generation_mode,
        'report_language': report_language,
        'effective_report_language': report_language,
        'input_source': input_source,
        'source_count': len(inputs),
        'processed_count': 0,
        'current_position': 0,
        'item_fallback_count': 0,
        'status': 'queued',
        'created_at': now,
        'updated_at': now,
        'provider': provider,
        'model': model,
    }
    job_id = _job_collection().insert_one(job).inserted_id
    _input_collection().insert_many([
        {'job_id': job_id, **item}
        for item in queued_inputs
    ])
    return str(job_id)


def _load_input_details(item):
    if 'details' in item:
        return item['details']
    document = resolve_vulnerability_document(
        get_vulnerabilities_database(),
        item['source_collection'],
        item['selection_id'],
        {'details': 1, '_id': 1},
    )
    if document is None:
        raise ValueError(f"Selected vulnerability not found: {item['selection_id']}")
    details = document.get('details')
    if not isinstance(details, dict):
        raise ValueError(f"Selected vulnerability has no details object: {item['selection_id']}")
    return details


def _local_item(details):
    normalized = next(iter(details.values()), details) if len(details) == 1 else details
    report = generate_template_report_data([{'details': normalized}])
    return {'highlight': report['highlights'][0], 'recommendations': report['recommendations']}


def _deterministic_final(item_results, report_language='en'):
    # region agent log
    sample_title = (item_results[0].get('highlight') or {}).get('title') if item_results else None
    _debug_log(
        'H2',
        'report_harness._deterministic_final',
        'deterministic_final_called',
        {
            'report_language': report_language,
            'item_count': len(item_results),
            'sample_title': (sample_title or '')[:80],
            'sample_title_mojibake': _looks_like_utf8_mojibake(sample_title or ''),
        },
    )
    # endregion
    records = [
        {
            'title': item['highlight'].get('title'),
            'code': item['highlight'].get('code'),
            'severity': item['highlight'].get('severity'),
            'summary': item['highlight'].get('summary'),
            'affected': item['highlight'].get('affected'),
            'references': item['highlight'].get('references'),
            'table': item['highlight'].get('table'),
            'recommendations': item.get('recommendations'),
        }
        for item in item_results
    ]
    report = generate_template_report_data(records)
    return {
        'title': _fixed_report_title(report_language),
        'executive_summary': report['executive_summary'],
        'trends': report['trends'],
        'recommendations': report['recommendations'],
    }


def _assemble_report(final_data, item_results, report_language='en'):
    report = dict(final_data)
    report['highlights'] = [item['highlight'] for item in item_results]
    report['title'] = _fixed_report_title(report_language)
    validate(instance=report, schema=REPORT_SCHEMA)
    return report


def _render_job_html(job, report, relative_path=None):
    return render_template(
        REPORT_TEMPLATE,
        report=report,
        generated_at=datetime.now(timezone.utc),
        source_count=job['source_count'],
        report_language=job['effective_report_language'],
        html_language=HTML_LANGUAGE_CODES[job['effective_report_language']],
        labels=REPORT_LABELS[job['effective_report_language']],
    )


def _acquire_worker_lease(owner):
    locks = get_web_database()['report_worker_locks']
    while True:
        now = datetime.now(timezone.utc)
        try:
            lock = locks.find_one_and_update(
                {
                    '_id': 'report_generation',
                    '$or': [
                        {'expires_at': {'$lte': now}},
                        {'owner': owner},
                        {'expires_at': {'$exists': False}},
                    ],
                },
                {'$set': {'owner': owner, 'expires_at': now + timedelta(hours=1)}},
                upsert=True,
                return_document=ReturnDocument.AFTER,
            )
            if lock and lock.get('owner') == owner:
                return
        except DuplicateKeyError:
            pass
        time.sleep(1)


def _release_worker_lease(owner):
    get_web_database()['report_worker_locks'].delete_one({
        '_id': 'report_generation',
        'owner': owner,
    })


def run_job(app, job_id):
    with WORKER_LOCK:
        with app.app_context():
            owner = f'{job_id}:{uuid.uuid4()}'
            _acquire_worker_lease(owner)
            collection = _job_collection()
            provider = None
            cleanup_provider = None
            try:
                job_object_id = ObjectId(job_id)
                now = datetime.now(timezone.utc)
                job = collection.find_one({'_id': job_object_id})
                collection.update_one(
                    {'_id': job_object_id},
                    {'$set': {
                        'status': 'running',
                        'updated_at': now,
                    }, '$unset': {'html': '', 'html_updated_at': '', 'html_path': ''}},
                )
                inputs = list(_input_collection().find({'job_id': job_object_id}).sort('position', 1))
                generation_mode = LEGACY_GENERATION_MODES.get(
                    job.get('generation_mode', 'company_ai'),
                    job.get('generation_mode', 'company_ai'),
                )
                report_language = job.get('report_language', 'en')
                if generation_mode == 'template':
                    records = []
                    for item in inputs:
                        details = compact_details(_load_input_details(item), current_app.config)
                        normalized = next(iter(details.values()), details) if len(details) == 1 else details
                        records.append({'details': normalized})
                    report = generate_template_report_data(records)
                    collection.update_one({'_id': job_object_id}, {'$set': {
                        'status': 'completed',
                        'processed_count': len(inputs),
                        'current_position': len(inputs),
                        'report': report,
                        'completed_at': datetime.now(timezone.utc),
                        'updated_at': datetime.now(timezone.utc),
                    }})
                    return
                item_results = []
                item_errors = []
                fallback_count = 0
                prepared_details = [
                    compact_details(_load_input_details(item), current_app.config)
                    for item in inputs
                ]
                cached_company_results = None
                company_cache_warning = None
                if generation_mode == 'company_ai':
                    try:
                        from company_ai_preprocessor import enqueue_report_items, wait_for_summaries

                        summary_references = enqueue_report_items([
                            {
                                'details': details,
                                'source_collection': item.get('source_collection'),
                                'source_id': item.get('selection_id'),
                            }
                            for item, details in zip(inputs, prepared_details)
                        ], report_language, current_app.config)
                        cached_company_results = wait_for_summaries(
                            summary_references,
                            current_app.config['COMPANY_AI_REPORT_WAIT_TIMEOUT_SECONDS'],
                        )
                    except Exception as exc:
                        cached_company_results = [None] * len(inputs)
                        company_cache_warning = str(exc)
                        collection.update_one(
                            {'_id': job_object_id},
                            {'$set': {'company_ai_cache_warning': company_cache_warning}},
                        )

                for position, (item, details) in enumerate(
                    zip(inputs, prepared_details),
                    start=1,
                ):
                    identifier = item.get('identifier') or str(position)
                    fallback_reason = None
                    if generation_mode == 'company_ai':
                        result = cached_company_results[position - 1]
                        if result is not None:
                            # region agent log
                            highlight = (result or {}).get('highlight') or {}
                            _debug_log(
                                'H3',
                                'report_harness.run_job',
                                'cached_item_loaded',
                                {
                                    'position': position,
                                    'report_language': report_language,
                                    'title': (highlight.get('title') or '')[:80],
                                    'title_mojibake': _looks_like_utf8_mojibake(highlight.get('title') or ''),
                                },
                            )
                            # endregion
                        if result is None:
                            result = _local_item(details)
                            fallback_reason = (
                                company_cache_warning
                                or 'Timed out waiting for the prioritized Company AI summary.'
                            )
                    else:
                        result = _local_item(details)
                        fallback_reason = 'Unexpected generation mode for item processing.'
                    result = _finalize_item_result(
                        result,
                        details,
                        identifier,
                        position,
                        _source_record_for_item(item),
                    )
                    if fallback_reason:
                        fallback_count += 1
                        item_errors.append({'position': position, 'identifier': identifier,
                                            'error': fallback_reason})
                    stored = {
                        'job_id': job_object_id,
                        'position': position - 1,
                        'identifier': identifier,
                        'highlight': result['highlight'],
                        'recommendations': result['recommendations'],
                        'fallback_reason': fallback_reason,
                    }
                    _result_collection().replace_one(
                        {'job_id': job_object_id, 'position': position - 1},
                        stored,
                        upsert=True,
                    )
                    item_results.append(result)
                    progress = {
                        'processed_count': position,
                        'current_position': position,
                        'item_fallback_count': fallback_count,
                        'item_errors': item_errors,
                        'updated_at': datetime.now(timezone.utc),
                    }
                    collection.update_one({'_id': job_object_id}, {'$set': progress})
                final_fallback_reason = None
                final_source = None
                provider = None
                cleanup_provider = None
                if generation_mode == 'company_ai':
                    try:
                        provider = CompanyAIProvider(current_app.config)
                        cleanup_provider = provider
                        conversation_id = provider.create_room(prime_prompt='')
                        collection.update_one(
                            {'_id': job_object_id},
                            {'$set': {'company_ai_conversation_id': conversation_id}},
                        )
                        try:
                            final_data, _ = generate_final_data(
                                provider,
                                item_results,
                                report_language,
                                current_app.config['REPORT_FINAL_JSON_RETRIES'],
                                current_app.config,
                            )
                            final_source = 'company_ai'
                            # region agent log
                            _debug_log(
                                'H4',
                                'report_harness.run_job',
                                'final_summary_from_ai',
                                {
                                    'report_language': report_language,
                                    'title': (final_data.get('title') or '')[:80],
                                    'executive_summary': (final_data.get('executive_summary') or '')[:120],
                                    'title_mojibake': _looks_like_utf8_mojibake(final_data.get('title') or ''),
                                },
                            )
                            # endregion
                        except (ProviderError, ValidationError) as exc:
                            final_data = _deterministic_final(
                                item_results, report_language,
                            )
                            final_source = 'deterministic_after_ai_error'
                            final_fallback_reason = str(exc)
                    except (requests.RequestException, ValueError, ProviderError) as exc:
                        provider = None
                        cleanup_provider = None
                        final_data = _deterministic_final(
                            item_results, report_language,
                        )
                        final_source = 'deterministic_no_provider'
                        final_fallback_reason = 'AI provider or Company AI room was unavailable.'
                        collection.update_one(
                            {'_id': job_object_id},
                            {'$set': {'room_creation_warning': str(exc)}},
                        )
                else:
                    final_data = _deterministic_final(
                        item_results, report_language,
                    )
                    final_source = 'deterministic_wrong_mode'
                    final_fallback_reason = 'Unexpected generation mode for final summary.'
                # region agent log
                _debug_log(
                    'H2',
                    'report_harness.run_job',
                    'final_summary_selected',
                    {
                        'report_language': report_language,
                        'final_source': final_source,
                        'final_fallback_reason': final_fallback_reason,
                        'title': (final_data.get('title') or '')[:80],
                    },
                )
                # endregion
                report = _assemble_report(final_data, item_results, report_language)
                completed = {
                    'status': 'completed',
                    'updated_at': datetime.now(timezone.utc),
                    'completed_at': datetime.now(timezone.utc),
                    'report': report,
                    'processed_count': len(item_results),
                    'current_position': len(item_results),
                    'item_fallback_count': fallback_count,
                    'item_errors': item_errors,
                }
                if final_fallback_reason:
                    completed['final_summary_fallback_reason'] = final_fallback_reason
                collection.update_one(
                    {'_id': job_object_id},
                    {'$set': completed},
                )
            except Exception as exc:
                collection.update_one(
                    {'_id': ObjectId(job_id)},
                    {'$set': {
                        'status': 'failed',
                        'updated_at': datetime.now(timezone.utc),
                        'error': str(exc),
                    }},
                )
            finally:
                if cleanup_provider is not None and hasattr(cleanup_provider, 'delete_room'):
                    try:
                        cleanup_provider.delete_room()
                    except Exception as exc:
                        collection.update_one(
                            {'_id': ObjectId(job_id)},
                            {'$set': {'room_cleanup_warning': str(exc)}},
                        )
                _input_collection().delete_many({'job_id': ObjectId(job_id)})
                _release_worker_lease(owner)


def start_job(app, job_id):
    thread = threading.Thread(target=run_job, args=(app, job_id), daemon=True)
    thread.start()
