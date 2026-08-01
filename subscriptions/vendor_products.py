import csv
import io
import re
import unicodedata
from copy import deepcopy

from bson import BSON


CSV_COLUMNS = (
    'vendor', 'product', 'vendor_aliases', 'product_aliases',
)
MAX_CSV_BYTES = 1024 * 1024
MAX_VENDOR_PRODUCT_ROWS = 500
MAX_ALIASES_PER_FIELD = 10
MAX_CELL_CHARS = 200
MAX_FILTER_TEXT_CHARS = 100_000
MAX_CANDIDATE_QUERY_BYTES = 10 * 1024 * 1024
MAX_REGEX_ALTERNATIVES = 250
MAX_ROW_NUMBER = MAX_CSV_BYTES + 1
SCHEMA_VERSION = 1

DEFAULT_VENDOR_PRODUCT_FILTER = {
    'enabled': False,
    'schema_version': SCHEMA_VERSION,
    'include_possible_matches': False,
    'rows': [],
}

_FILTER_FIELDS = frozenset(DEFAULT_VENDOR_PRODUCT_FILTER)
_ROW_FIELDS = frozenset((*CSV_COLUMNS, 'row_number'))
_UNKNOWN_VALUES = frozenset({
    '', '*', 'n/a', 'na', 'none', 'not specified', 'unknown', 'unspecified',
})
_GENERIC_PRODUCT_KEYS = frozenset({
    'app', 'application', 'client', 'device', 'enterprise', 'library',
    'package', 'platform', 'plugin', 'product', 'server', 'service', 'software',
    'system', 'tool', 'web',
    '伺服器', '服务器', '套件', '工具', '平台', '应用', '應用', '插件',
    '服务', '服務', '程序', '系統', '系统', '設備', '设备', '軟件', '软件',
})
_VENDOR_SUFFIXES = frozenset({
    'co', 'company', 'corp', 'corporation', 'gmbh', 'inc', 'incorporated',
    'limited', 'llc', 'ltd', 'plc',
})

_STRUCTURED_ARRAY_PATHS = (
    ('details', 'affected'),
    ('details', 'containers', 'cna', 'affected'),
    ('affected',),
    ('affected_products',),
    ('details', 'affected_products'),
    ('containers', 'cna', 'affected'),
)
_STRUCTURED_PAIR_PATHS = (
    (('vendor',), ('product',), 'vendor/product'),
    (('details', 'vendor'), ('details', 'product'), 'details.vendor/product'),
)
_STRUCTURED_VENDOR_FIELDS = ('vendor', 'vendor_name', 'manufacturer')
_STRUCTURED_PRODUCT_FIELDS = ('product', 'product_name', 'packageName')
_FALLBACK_PATHS = (
    ('affected',),
    ('affected_products',),
    ('systems_affected',),
    ('products',),
    ('title',),
    ('description',),
    ('descriptions',),
    ('summary',),
    ('impacts',),
    ('details', 'affected'),
    ('details', 'affected_products'),
    ('details', 'description'),
    ('details', 'descriptions'),
    ('details', 'summary'),
    ('details', 'containers', 'cna', 'affected'),
    ('details', 'containers', 'cna', 'descriptions'),
    ('containers', 'cna', 'affected'),
    ('containers', 'cna', 'descriptions'),
)
_FALLBACK_TEXT_PATHS = tuple(dict.fromkeys((
    *_FALLBACK_PATHS,
    *(
        (*path, 'value')
        for path in _FALLBACK_PATHS
        if path[-1] in {'description', 'descriptions'}
    ),
)))


def _default_filter():
    return deepcopy(DEFAULT_VENDOR_PRODUCT_FILTER)


def _display_text(value):
    if not isinstance(value, str):
        raise ValueError('must be text')
    text = unicodedata.normalize('NFC', value).strip()
    text = re.sub(r'\s+', ' ', text)
    if any(unicodedata.category(char) == 'Cc' for char in text):
        raise ValueError('contains a control character')
    if len(text) > MAX_CELL_CHARS:
        raise ValueError(f'must be at most {MAX_CELL_CHARS} characters')
    return text


def _match_key(value):
    # Keep compatibility-width and multi-character case variants distinct so
    # Python acceptance mirrors MongoDB's regex prefilter. Administrators can
    # list such source variants explicitly in the alias columns.
    text = unicodedata.normalize('NFC', str(value or '')).lower()
    text = text.replace('&', ' ')
    text = re.sub(r'[^\w]+', ' ', text, flags=re.UNICODE)
    return ' '.join(text.split())


def _vendor_key(value):
    key = _match_key(value)
    tokens = key.split()
    while len(tokens) > 1 and tokens[-1] in _VENDOR_SUFFIXES:
        tokens.pop()
    return ' '.join(tokens)


_UNKNOWN_VENDOR_KEYS = frozenset(_vendor_key(value) for value in _UNKNOWN_VALUES)
_UNKNOWN_PRODUCT_KEYS = frozenset(_match_key(value) for value in _UNKNOWN_VALUES)


def _clean_aliases(value, *, canonical, field):
    if value is None:
        value = []
    if not isinstance(value, list):
        raise ValueError(f'{field} must be a list')
    if len(value) > MAX_ALIASES_PER_FIELD:
        raise ValueError(f'{field} must contain at most {MAX_ALIASES_PER_FIELD} aliases')

    key_function = _vendor_key if field == 'vendor_aliases' else _match_key
    unknown_keys = _UNKNOWN_VENDOR_KEYS if field == 'vendor_aliases' else _UNKNOWN_PRODUCT_KEYS
    canonical_key = key_function(canonical)
    aliases = []
    seen = {canonical_key}
    for raw_alias in value:
        alias = _display_text(raw_alias)
        if not alias:
            continue
        key = key_function(alias)
        if not key:
            raise ValueError(f'{field} contains an alias with no usable identity text')
        if key in unknown_keys:
            raise ValueError(f'{field} must not contain placeholder values such as Unknown or N/A')
        if key in seen:
            continue
        seen.add(key)
        aliases.append(alias)
    return aliases


def _normalize_row(value, default_row_number):
    if not isinstance(value, dict):
        raise ValueError('must be an object')
    unknown = sorted(set(value) - _ROW_FIELDS)
    if unknown:
        raise ValueError('contains unknown field(s): ' + ', '.join(unknown))

    row_number = value.get('row_number', default_row_number)
    if (
        isinstance(row_number, bool)
        or not isinstance(row_number, int)
        or row_number < 2
        or row_number > MAX_ROW_NUMBER
    ):
        raise ValueError(
            f'row_number must be an integer from 2 through {MAX_ROW_NUMBER}',
        )

    vendor = _display_text(value.get('vendor', ''))
    product = _display_text(value.get('product', ''))
    if not vendor:
        raise ValueError('vendor is required')
    if not product:
        raise ValueError('product is required')
    vendor_key = _vendor_key(vendor)
    product_key = _match_key(product)
    if not vendor_key or vendor_key in _UNKNOWN_VENDOR_KEYS:
        raise ValueError('vendor must contain a usable, non-placeholder identity')
    if not product_key or product_key in _UNKNOWN_PRODUCT_KEYS:
        raise ValueError('product must contain a usable, non-placeholder identity')

    vendor_aliases = _clean_aliases(
        value.get('vendor_aliases', []), canonical=vendor, field='vendor_aliases',
    )
    product_aliases = _clean_aliases(
        value.get('product_aliases', []), canonical=product, field='product_aliases',
    )
    return {
        'vendor': vendor,
        'product': product,
        'vendor_aliases': vendor_aliases,
        'product_aliases': product_aliases,
        'row_number': row_number,
    }


def _merge_rows(rows):
    merged = []
    by_pair = {}
    duplicate_pairs = []
    for row in rows:
        pair = (_vendor_key(row['vendor']), _match_key(row['product']))
        existing = by_pair.get(pair)
        if existing is None:
            existing = dict(row)
            existing['vendor_aliases'] = list(row['vendor_aliases'])
            existing['product_aliases'] = list(row['product_aliases'])
            by_pair[pair] = existing
            merged.append(existing)
            continue

        duplicate_pairs.append((existing['row_number'], row['row_number']))
        for field, key_function in (
            ('vendor_aliases', _vendor_key),
            ('product_aliases', _match_key),
        ):
            canonical_field = 'vendor' if field == 'vendor_aliases' else 'product'
            seen = {key_function(existing[canonical_field])}
            seen.update(key_function(alias) for alias in existing[field])
            for alias in row[field]:
                key = key_function(alias)
                if key and key not in seen:
                    seen.add(key)
                    existing[field].append(alias)
    return merged, duplicate_pairs


def validate_vendor_product_filter(value, *, check_query_size=True):
    if value is None:
        return _default_filter()
    if not isinstance(value, dict):
        raise ValueError('Vendor/product filter must be an object.')

    unknown = sorted(set(value) - _FILTER_FIELDS)
    if unknown:
        raise ValueError(
            'Vendor/product filter contains unknown field(s): ' + ', '.join(unknown) + '.',
        )

    enabled = value.get('enabled', False)
    include_possible = value.get('include_possible_matches', False)
    schema_version = value.get('schema_version', SCHEMA_VERSION)
    if not isinstance(enabled, bool):
        raise ValueError('Vendor/product filter enabled must be true or false.')
    if not isinstance(include_possible, bool):
        raise ValueError('Include possible matches must be true or false.')
    if type(schema_version) is not int or schema_version != SCHEMA_VERSION:
        raise ValueError(f'Vendor/product filter schema_version must be {SCHEMA_VERSION}.')

    raw_rows = value.get('rows', [])
    if not isinstance(raw_rows, list):
        raise ValueError('Vendor/product filter rows must be a list.')
    if len(raw_rows) > MAX_VENDOR_PRODUCT_ROWS:
        raise ValueError(
            f'Vendor/product filter must contain at most {MAX_VENDOR_PRODUCT_ROWS} rows.',
        )

    rows = []
    errors = []
    for index, raw_row in enumerate(raw_rows, start=2):
        try:
            rows.append(_normalize_row(raw_row, index))
        except ValueError as exc:
            row_number = raw_row.get('row_number', index) if isinstance(raw_row, dict) else index
            errors.append(f'Row {row_number}: {exc}.')
    if errors:
        raise ValueError('\n'.join(errors))

    rows, _ = _merge_rows(rows)
    if enabled and not rows:
        raise ValueError('Enabled vendor/product filter requires at least one row.')
    for row in rows:
        for field in ('vendor_aliases', 'product_aliases'):
            if len(row[field]) > MAX_ALIASES_PER_FIELD:
                raise ValueError(
                    f'Row {row["row_number"]}: merged duplicate {field} must contain '
                    f'at most {MAX_ALIASES_PER_FIELD} aliases.',
                )
    identity_chars = sum(
        len(value)
        for row in rows
        for value in (
            row['vendor'], row['product'],
            *row['vendor_aliases'], *row['product_aliases'],
        )
    )
    if identity_chars > MAX_FILTER_TEXT_CHARS:
        raise ValueError(
            'Vendor/product filter text is too large; shorten aliases or split the inventory.',
        )
    normalized = {
        'enabled': enabled,
        'schema_version': SCHEMA_VERSION,
        'include_possible_matches': include_possible,
        'rows': rows,
    }
    if enabled and check_query_size:
        _ensure_candidate_query_size(_build_candidate_clause(normalized))
    return normalized


def _parse_alias_cell(value, field, row_number, errors):
    aliases = []
    for item in value.split('|'):
        item = item.strip()
        if item:
            aliases.append(item)
    if len(aliases) > MAX_ALIASES_PER_FIELD:
        errors.append(
            f'Row {row_number}: {field} must contain at most '
            f'{MAX_ALIASES_PER_FIELD} aliases.',
        )
    return aliases


def parse_vendor_product_csv(payload):
    if not isinstance(payload, bytes):
        raise ValueError('CSV payload must be bytes.')
    if len(payload) > MAX_CSV_BYTES:
        raise ValueError(f'CSV file must be at most {MAX_CSV_BYTES} bytes.')
    if b'\x00' in payload:
        raise ValueError('CSV file contains a NUL byte.')
    try:
        text = payload.decode('utf-8-sig')
    except UnicodeDecodeError as exc:
        raise ValueError('CSV file must be UTF-8 encoded.') from exc

    reader = csv.reader(io.StringIO(text, newline=''), strict=True)
    try:
        header = next(reader)
    except StopIteration as exc:
        raise ValueError('CSV file is empty.') from exc
    except csv.Error as exc:
        raise ValueError(f'CSV line 1: {exc}.') from exc
    if tuple(header) != CSV_COLUMNS:
        raise ValueError('CSV header must be exactly: ' + ','.join(CSV_COLUMNS) + '.')

    rows = []
    data_row_count = 0
    errors = []
    try:
        for values in reader:
            row_number = reader.line_num
            if not values or all(not str(value).strip() for value in values):
                continue
            data_row_count += 1
            if len(values) != len(CSV_COLUMNS):
                errors.append(
                    f'Row {row_number}: expected {len(CSV_COLUMNS)} columns, got {len(values)}.',
                )
                continue
            if data_row_count > MAX_VENDOR_PRODUCT_ROWS:
                errors.append(
                    f'Row {row_number}: CSV must contain at most '
                    f'{MAX_VENDOR_PRODUCT_ROWS} data rows.',
                )
                continue

            row_errors = []
            for column, cell in zip(CSV_COLUMNS, values):
                if len(cell) > MAX_CELL_CHARS:
                    row_errors.append(
                        f'Row {row_number}: {column} must be at most '
                        f'{MAX_CELL_CHARS} characters.',
                    )
            vendor_aliases = _parse_alias_cell(
                values[2], 'vendor_aliases', row_number, row_errors,
            )
            product_aliases = _parse_alias_cell(
                values[3], 'product_aliases', row_number, row_errors,
            )
            candidate = {
                'vendor': values[0],
                'product': values[1],
                'vendor_aliases': vendor_aliases,
                'product_aliases': product_aliases,
                'row_number': row_number,
            }
            try:
                normalized = _normalize_row(candidate, row_number)
            except ValueError as exc:
                row_errors.append(f'Row {row_number}: {exc}.')
            if row_errors:
                errors.extend(dict.fromkeys(row_errors))
            else:
                rows.append(normalized)
    except csv.Error as exc:
        errors.append(f'CSV line {reader.line_num}: {exc}.')

    if errors:
        raise ValueError('\n'.join(errors))
    if not rows:
        raise ValueError('CSV must contain at least one data row.')

    rows, duplicate_pairs = _merge_rows(rows)
    warnings = [
        f'Rows {first} and {duplicate} contain the same vendor/product; aliases were merged.'
        for first, duplicate in duplicate_pairs
    ]
    for row in rows:
        product_keys = _row_product_keys(row)
        if not any(_is_distinctive_product(key) for key in product_keys):
            warnings.append(
                f'Row {row["row_number"]}: product and all product aliases are too '
                'generic for product-only possible matching.',
            )
    product_owners = {}
    for row in rows:
        vendor_key = _vendor_key(row['vendor'])
        for product_key in _row_product_keys(row):
            product_owners.setdefault(product_key, set()).add(vendor_key)
    for product_key, vendor_keys in sorted(product_owners.items()):
        if len(vendor_keys) > 1:
            warnings.append(
                f'Product identity "{product_key}" appears under multiple vendors; '
                'vendorless possible matches for it will be suppressed.',
            )
    normalized_filter = validate_vendor_product_filter({
        'enabled': True,
        'schema_version': SCHEMA_VERSION,
        'include_possible_matches': False,
        'rows': rows,
    })
    return normalized_filter, warnings


def _path_value(document, path):
    value = document
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _scalar_text(value):
    if isinstance(value, str):
        return value.strip()
    return ''


def _entry_value(entry, names):
    if not isinstance(entry, dict):
        return ''
    for name in names:
        text = _scalar_text(entry.get(name))
        if text:
            return text
    return ''


def _iter_structured_pairs(document):
    for vendor_path, product_path, source in _STRUCTURED_PAIR_PATHS:
        vendor = _scalar_text(_path_value(document, vendor_path))
        product = _scalar_text(_path_value(document, product_path))
        if vendor or product:
            yield source, vendor, product

    for path in _STRUCTURED_ARRAY_PATHS:
        value = _path_value(document, path)
        entries = value if isinstance(value, list) else [value]
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            vendor = _entry_value(entry, _STRUCTURED_VENDOR_FIELDS)
            product = _entry_value(entry, _STRUCTURED_PRODUCT_FIELDS)
            if vendor or product:
                yield f'{".".join(path)}[{index}]', vendor, product


def _iter_values_at_path(value, path):
    if not path:
        yield value
        return
    if isinstance(value, list):
        for item in value:
            yield from _iter_values_at_path(item, path)
        return
    if not isinstance(value, dict):
        return
    key = path[0]
    if key in value:
        yield from _iter_values_at_path(value[key], path[1:])


def _segments_from_value(value):
    if isinstance(value, str):
        text = value.strip()
        if text:
            yield text
        return
    if isinstance(value, list):
        for item in value:
            yield from _segments_from_value(item)


def _iter_fallback_segments(document):
    seen = set()
    for path in _FALLBACK_TEXT_PATHS:
        for value in _iter_values_at_path(document, path):
            for segment in _segments_from_value(value):
                key = _match_key(segment)
                if not key or key in seen:
                    continue
                seen.add(key)
                yield '.'.join(path), segment, key


def _row_vendor_keys(row):
    return tuple(dict.fromkeys(
        key for key in (_vendor_key(value) for value in [row['vendor'], *row['vendor_aliases']])
        if key
    ))


def _row_product_keys(row):
    return tuple(dict.fromkeys(
        key for key in (_match_key(value) for value in [row['product'], *row['product_aliases']])
        if key
    ))


def _is_cjk_character(char):
    return (
        '\u3040' <= char <= '\u30ff'
        or '\u31f0' <= char <= '\u31ff'
        or '\u3400' <= char <= '\u9fff'
        or '\uac00' <= char <= '\ud7af'
        or '\U00020000' <= char <= '\U0002fa1f'
    )


def _segment_contains(segment_key, phrase_key):
    if not segment_key or not phrase_key:
        return False
    if any(_is_cjk_character(char) for char in phrase_key):
        return ''.join(phrase_key.split()) in ''.join(segment_key.split())
    return f' {phrase_key} ' in f' {segment_key} '


def _first_contained(segment_key, phrase_keys):
    for phrase_key in phrase_keys:
        if _segment_contains(segment_key, phrase_key):
            return phrase_key
    return ''


def _is_distinctive_product(key):
    compact = ''.join(key.split())
    if key in _GENERIC_PRODUCT_KEYS:
        return False
    cjk_count = sum(
        1
        for char in compact
        if _is_cjk_character(char)
    )
    return len(compact) >= 4 or cjk_count >= 2


def _evidence_text(value, limit=240):
    text = re.sub(r'\s+', ' ', str(value or '')).strip()
    if len(text) <= limit:
        return text
    return text[:limit - 1].rstrip() + '…'


def _match_metadata(confidence, row, evidence):
    return {
        'confidence': confidence,
        'matched_vendor': row['vendor'],
        'matched_product': row['product'],
        'row_number': row['row_number'],
        'evidence': evidence,
    }


def _compile_match_rows(normalized):
    compiled = []
    product_owners = {}
    for row in normalized['rows']:
        vendor_keys = _row_vendor_keys(row)
        product_keys = _row_product_keys(row)
        owner = _vendor_key(row['vendor'])
        for product_key in product_keys:
            product_owners.setdefault(product_key, set()).add(owner)
        compiled.append({
            'row': row,
            'vendor_keys': vendor_keys,
            'vendor_key_set': frozenset(vendor_keys),
            'product_keys': product_keys,
            'product_key_set': frozenset(product_keys),
        })
    all_vendor_keys = tuple(dict.fromkeys(
        key
        for item in compiled
        for key in item['vendor_keys']
    ))
    for item in compiled:
        possible_product_keys = tuple(
            key
            for key in item['product_keys']
            if len(product_owners.get(key, ())) == 1 and _is_distinctive_product(key)
        )
        item['possible_product_keys'] = possible_product_keys
        item['possible_product_key_set'] = frozenset(possible_product_keys)
        item['conflicting_vendor_keys'] = tuple(
            key for key in all_vendor_keys if key not in item['vendor_key_set']
        )
    return tuple(compiled)


def _classify_vendor_product_match(document, normalized, compiled_rows):
    if not normalized['enabled'] or not isinstance(document, dict):
        return None

    structured_pairs = list(_iter_structured_pairs(document))
    fallback_segments = list(_iter_fallback_segments(document))
    has_complete_structured_identity = any(
        _vendor_key(vendor) not in _UNKNOWN_VENDOR_KEYS
        and _match_key(product) not in _UNKNOWN_PRODUCT_KEYS
        for _, vendor, product in structured_pairs
        if _vendor_key(vendor) and _match_key(product)
    )

    for compiled in compiled_rows:
        row = compiled['row']
        vendor_keys = compiled['vendor_key_set']
        product_keys = compiled['product_key_set']
        for source, vendor, product in structured_pairs:
            vendor_key = _vendor_key(vendor)
            product_key = _match_key(product)
            if (
                vendor_key not in _UNKNOWN_VENDOR_KEYS
                and product_key not in _UNKNOWN_PRODUCT_KEYS
                and vendor_key in vendor_keys
                and product_key in product_keys
            ):
                return _match_metadata('confirmed', row, {
                    'type': 'structured_pair',
                    'source': source,
                    'vendor': vendor,
                    'product': product,
                })

    if not has_complete_structured_identity:
        for compiled in compiled_rows:
            row = compiled['row']
            vendor_keys = compiled['vendor_keys']
            product_keys = compiled['product_keys']
            for source, segment, segment_key in fallback_segments:
                if (
                    _first_contained(segment_key, vendor_keys)
                    and _first_contained(segment_key, product_keys)
                ):
                    return _match_metadata('probable', row, {
                        'type': 'fallback_segment',
                        'source': source,
                        'text': _evidence_text(segment),
                    })

    if not normalized['include_possible_matches']:
        return None
    structured_vendor_evidence = any(
        _vendor_key(vendor) not in _UNKNOWN_VENDOR_KEYS
        for _, vendor, _ in structured_pairs
        if _vendor_key(vendor)
    )
    if structured_vendor_evidence:
        return None

    for compiled in compiled_rows:
        row = compiled['row']
        product_keys = compiled['possible_product_keys']
        for source, _, product in structured_pairs:
            product_key = _match_key(product)
            if product_key in compiled['possible_product_key_set']:
                return _match_metadata('possible', row, {
                    'type': 'structured_product_without_vendor',
                    'source': source,
                    'product': product,
                })
        for source, segment, segment_key in fallback_segments:
            product_key = _first_contained(segment_key, product_keys)
            if (
                product_key
                and not _first_contained(
                    segment_key, compiled['conflicting_vendor_keys'],
                )
            ):
                return _match_metadata('possible', row, {
                    'type': 'product_without_structured_vendor',
                    'source': source,
                    'text': _evidence_text(segment),
                })
    return None


def compile_vendor_product_matcher(filter_value):
    """Validate and compile an inventory once, then classify many CVE documents."""
    normalized = validate_vendor_product_filter(filter_value, check_query_size=False)
    compiled_rows = _compile_match_rows(normalized)

    def matcher(document):
        return _classify_vendor_product_match(document, normalized, compiled_rows)

    return matcher


def classify_vendor_product_match(document, filter_value):
    return compile_vendor_product_matcher(filter_value)(document)


def _mongo_phrase_patterns(values, key_function):
    phrases = []
    seen = set()
    for value in values:
        normalized_key = key_function(value)
        normalized_tokens = tuple(normalized_key.split())
        token_variants = [normalized_tokens]
        raw_text = unicodedata.normalize('NFC', str(value or '')).replace('&', ' ')
        raw_forms = dict.fromkeys((
            raw_text,
            unicodedata.normalize('NFC', raw_text.upper()),
            unicodedata.normalize('NFC', raw_text.title()),
        ))
        for raw_form in raw_forms:
            raw_tokens = tuple(
                token
                for token in re.split(r'[\W_]+', raw_form, flags=re.UNICODE)
                if token
            )
            raw_lower_tokens = tuple(token.lower() for token in raw_tokens)
            if raw_tokens and raw_lower_tokens != normalized_tokens:
                token_variants.append(raw_tokens)
        for tokens in token_variants:
            if tokens and tokens not in seen:
                seen.add(tokens)
                phrases.append(tokens)
    patterns = []
    for start in range(0, len(phrases), MAX_REGEX_ALTERNATIVES):
        alternatives = []
        for tokens in phrases[start:start + MAX_REGEX_ALTERNATIVES]:
            token_pattern = r'[\W_]+'.join(re.escape(token) for token in tokens)
            if any(_is_cjk_character(char) for token in tokens for char in token):
                alternatives.append(token_pattern)
            else:
                alternatives.append(rf'(?:^|[\W_]){token_pattern}(?:$|[\W_])')
        patterns.append({
            '$regex': '(?:' + '|'.join(alternatives) + ')',
            '$options': 'i',
        })
    return patterns


def _candidate_inventory_clause(rows):
    product_patterns = _mongo_phrase_patterns(
        [
            value
            for row in rows
            for value in (row['product'], *row['product_aliases'])
        ],
        _match_key,
    )
    fields = {'.'.join(path) for path in _FALLBACK_TEXT_PATHS}
    fields.update(
        '.'.join(product_path)
        for _, product_path, _ in _STRUCTURED_PAIR_PATHS
    )
    fields.update(
        f'{".".join(path)}.{name}'
        for path in _STRUCTURED_ARRAY_PATHS
        for name in _STRUCTURED_PRODUCT_FIELDS
    )
    # Product evidence alone is sufficient for a lossless candidate pass.
    # Vendor/product pairing and confidence are enforced by the classifier,
    # keeping this BSON query compact for large inventories.
    return {'$or': [
        {field: product_pattern}
        for field in sorted(fields)
        for product_pattern in product_patterns
    ]}


def _build_candidate_clause(normalized):
    if not normalized['enabled']:
        return {}
    # The Mongo clause is intentionally broad: it combines inventory vendor
    # and product terms to keep the query compact, while the Python classifier
    # below still enforces the original row pairing before accepting a CVE.
    return _candidate_inventory_clause(normalized['rows'])


def _ensure_candidate_query_size(clause):
    encoded_size = len(BSON.encode({'vendor_product_filter': clause}))
    if encoded_size > MAX_CANDIDATE_QUERY_BYTES:
        raise ValueError(
            'Vendor/product filter is too complex to query safely; '
            'reduce the number of rows or aliases.',
        )


def build_vendor_product_candidate_clause(filter_value):
    normalized = validate_vendor_product_filter(filter_value, check_query_size=False)
    clause = _build_candidate_clause(normalized)
    if clause:
        _ensure_candidate_query_size(clause)
    return clause
