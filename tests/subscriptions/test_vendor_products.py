import re

import pytest

from subscriptions.vendor_products import (
    CSV_COLUMNS,
    DEFAULT_VENDOR_PRODUCT_FILTER,
    MAX_ALIASES_PER_FIELD,
    MAX_CELL_CHARS,
    MAX_CSV_BYTES,
    MAX_FILTER_TEXT_CHARS,
    MAX_ROW_NUMBER,
    MAX_VENDOR_PRODUCT_ROWS,
    build_vendor_product_candidate_clause,
    classify_vendor_product_match,
    parse_vendor_product_csv,
    validate_vendor_product_filter,
)


def _filter(*rows, include_possible=False):
    return validate_vendor_product_filter({
        'enabled': True,
        'schema_version': 1,
        'include_possible_matches': include_possible,
        'rows': list(rows),
    })


def _row(vendor='Microsoft', product='Exchange Server', **overrides):
    return {
        'vendor': vendor,
        'product': product,
        'vendor_aliases': [],
        'product_aliases': [],
        **overrides,
    }


def test_default_filter_is_disabled_and_validation_returns_a_copy():
    first = validate_vendor_product_filter(None)
    second = validate_vendor_product_filter(None)

    assert first == DEFAULT_VENDOR_PRODUCT_FILTER
    first['rows'].append(_row())
    assert second == DEFAULT_VENDOR_PRODUCT_FILTER


def test_parse_csv_supports_utf8_bom_quoted_fields_and_aliases():
    payload = (
        '\ufeffvendor,product,vendor_aliases,product_aliases\r\n'
        '"Microsoft, Inc.",Exchange Server,"Microsoft Corp.|MSFT",'
        '"Microsoft Exchange|Exchange Server 2019"\r\n'
    ).encode('utf-8')

    parsed, warnings = parse_vendor_product_csv(payload)

    assert warnings == []
    assert parsed['enabled'] is True
    assert parsed['include_possible_matches'] is False
    assert parsed['rows'] == [{
        'vendor': 'Microsoft, Inc.',
        'product': 'Exchange Server',
        'vendor_aliases': ['MSFT'],
        'product_aliases': ['Microsoft Exchange', 'Exchange Server 2019'],
        'row_number': 2,
    }]


def test_parse_csv_merges_duplicate_pairs_and_reports_warning():
    payload = (
        'vendor,product,vendor_aliases,product_aliases\n'
        'Red Hat,Enterprise Linux,RedHat,RHEL\n'
        'red-hat,Enterprise-Linux,Red Hat Inc.,Red Hat Enterprise Linux\n'
    ).encode()

    parsed, warnings = parse_vendor_product_csv(payload)

    assert len(parsed['rows']) == 1
    assert parsed['rows'][0]['vendor_aliases'] == ['RedHat']
    assert parsed['rows'][0]['product_aliases'] == ['RHEL', 'Red Hat Enterprise Linux']
    assert warnings == [
        'Rows 2 and 3 contain the same vendor/product; aliases were merged.',
    ]


def test_parse_csv_does_not_silently_drop_aliases_while_merging_duplicates():
    first_aliases = '|'.join(f'Alias {index}' for index in range(6))
    second_aliases = '|'.join(f'Other {index}' for index in range(6))
    payload = (
        'vendor,product,vendor_aliases,product_aliases\n'
        f'Acme,Widget,{first_aliases},\n'
        f'acme,widget,{second_aliases},\n'
    ).encode()

    with pytest.raises(ValueError, match='vendor_aliases must contain at most'):
        parse_vendor_product_csv(payload)


def test_parse_csv_warns_when_no_product_value_is_safe_for_possible_matching():
    payload = (
        'vendor,product,vendor_aliases,product_aliases\n'
        'Acme,Server,,App|Tool\n'
    ).encode()

    _, warnings = parse_vendor_product_csv(payload)

    assert warnings == [
        'Row 2: product and all product aliases are too generic for product-only '
        'possible matching.',
    ]


def test_parse_csv_warns_when_vendorless_product_identity_is_ambiguous():
    payload = (
        'vendor,product,vendor_aliases,product_aliases\n'
        'Acme,Workspace,,Suite\n'
        'Contoso,Workspace,,Suite\n'
    ).encode()

    _, warnings = parse_vendor_product_csv(payload)

    assert 'Product identity "workspace" appears under multiple vendors; ' \
        'vendorless possible matches for it will be suppressed.' in warnings
    assert 'Product identity "suite" appears under multiple vendors; ' \
        'vendorless possible matches for it will be suppressed.' in warnings


def test_parse_csv_requires_the_exact_header_and_utf8_bytes():
    with pytest.raises(ValueError, match='header must be exactly'):
        parse_vendor_product_csv(b'product,vendor,vendor_aliases,product_aliases\nP,V,,\n')
    with pytest.raises(ValueError, match='UTF-8'):
        parse_vendor_product_csv(b'\xff\xfe')
    with pytest.raises(ValueError, match='NUL'):
        parse_vendor_product_csv(
            b'vendor,product,vendor_aliases,product_aliases\nAcme,Widget,\x00,\n',
        )


def test_parse_csv_reports_all_invalid_rows_without_returning_partial_data():
    payload = (
        'vendor,product,vendor_aliases,product_aliases\n'
        ',Widget,,\n'
        'Acme,,,\n'
    ).encode()

    with pytest.raises(ValueError) as raised:
        parse_vendor_product_csv(payload)

    assert 'Row 2: vendor is required.' in str(raised.value)
    assert 'Row 3: product is required.' in str(raised.value)


def test_csv_enforces_file_row_alias_and_cell_limits():
    with pytest.raises(ValueError, match='at most'):
        parse_vendor_product_csv(b'x' * (MAX_CSV_BYTES + 1))

    header = ','.join(CSV_COLUMNS) + '\n'
    too_many_rows = header + ''.join(
        f'Vendor {index},Product {index},,\n'
        for index in range(MAX_VENDOR_PRODUCT_ROWS + 1)
    )
    with pytest.raises(ValueError, match='data rows'):
        parse_vendor_product_csv(too_many_rows.encode())

    aliases = '|'.join(f'Alias {index}' for index in range(MAX_ALIASES_PER_FIELD + 1))
    with pytest.raises(ValueError, match='aliases'):
        parse_vendor_product_csv((header + f'Acme,Widget,{aliases},\n').encode())

    long_vendor = 'v' * (MAX_CELL_CHARS + 1)
    with pytest.raises(ValueError, match='vendor must be at most'):
        parse_vendor_product_csv((header + f'{long_vendor},Widget,,\n').encode())


def test_validate_filter_is_strict_and_normalizes_aliases():
    normalized = _filter(_row(
        vendor='  Acme   Corporation ',
        product=' Widget-Pro ',
        vendor_aliases=['ACME CORP', 'acme corp', 'Acme Corporation'],
        product_aliases=['Widget Pro', 'WIDGET-PRO', 'WP'],
    ))

    assert normalized['rows'][0] == {
        'vendor': 'Acme Corporation',
        'product': 'Widget-Pro',
        'vendor_aliases': [],
        'product_aliases': ['WP'],
        'row_number': 2,
    }
    with pytest.raises(ValueError, match='requires at least one row'):
        validate_vendor_product_filter({'enabled': True, 'rows': []})
    with pytest.raises(ValueError, match='unknown field'):
        validate_vendor_product_filter({'enabled': False, 'unexpected': True})
    with pytest.raises(ValueError, match='row_number'):
        _filter(_row(row_number=MAX_ROW_NUMBER + 1))
    with pytest.raises(ValueError, match='usable, non-placeholder identity'):
        _filter(_row(product='+++'))
    with pytest.raises(ValueError, match='usable, non-placeholder identity'):
        _filter(_row(vendor='Unknown'))
    with pytest.raises(ValueError, match='placeholder values'):
        _filter(_row(vendor_aliases=['N/A']))

    oversized_rows = [
        _row(
            vendor=f'Vendor {index} ' + ('v' * 100),
            product=f'Product {index} ' + ('p' * 100),
        )
        for index in range(MAX_VENDOR_PRODUCT_ROWS)
    ]
    assert sum(
        len(row['vendor']) + len(row['product']) for row in oversized_rows
    ) > MAX_FILTER_TEXT_CHARS
    with pytest.raises(ValueError, match='filter text is too large'):
        _filter(*oversized_rows)


def test_validate_filter_rejects_a_candidate_query_that_is_too_complex():
    rows = [
        _row(
            vendor=f'V{index}',
            product=f'P{index}',
            product_aliases=[('a-' * 70) + str(index)],
        )
        for index in range(MAX_VENDOR_PRODUCT_ROWS)
    ]

    with pytest.raises(ValueError, match='too complex to query safely'):
        _filter(*rows, include_possible=True)


def test_candidate_clause_is_disabled_when_filter_is_disabled():
    assert build_vendor_product_candidate_clause(DEFAULT_VENDOR_PRODUCT_FILTER) == {}


def test_candidate_clause_uses_escaped_bounded_product_patterns():
    clause = build_vendor_product_candidate_clause(_filter(
        _row(vendor='Acme (Global)', product='Widget+Pro'),
    ))

    row_clauses = clause['$or']
    affected = next(item for item in row_clauses if 'details.affected.product' in item)
    product_pattern = affected['details.affected.product']
    assert product_pattern['$options'] == 'i'
    assert r'widget[\W_]+pro' in product_pattern['$regex']


def test_candidate_clause_covers_alternate_structured_keys_and_nested_description_values():
    clause_text = str(build_vendor_product_candidate_clause(_filter(_row())))

    assert 'details.containers.cna.affected.product' in clause_text
    assert 'details.containers.cna.affected.product_name' in clause_text
    assert 'details.descriptions.value' in clause_text


def test_unicode_source_variants_are_explicit_aliases_and_preserve_prefilter_parity():
    product_filter = _filter(_row(
        product='Straße',
        product_aliases=['Ｗｉｄｇｅｔ'],
    ))
    clause = build_vendor_product_candidate_clause(product_filter)
    patterns = [
        item['details.affected.product']['$regex']
        for item in clause['$or']
        if 'details.affected.product' in item
    ]

    assert any(re.search(pattern, 'Straße', re.IGNORECASE) for pattern in patterns)
    assert any(re.search(pattern, 'Ｗｉｄｇｅｔ', re.IGNORECASE) for pattern in patterns)
    assert classify_vendor_product_match({
        'details': {'affected': [{'vendor': 'Microsoft', 'product': 'Straße'}]},
    }, product_filter)['confidence'] == 'confirmed'
    assert classify_vendor_product_match({
        'details': {'affected': [{'vendor': 'Microsoft', 'product': 'Ｗｉｄｇｅｔ'}]},
    }, product_filter)['confidence'] == 'confirmed'

    dotted_i_filter = _filter(_row(product='İstanbul'))
    dotted_i_patterns = [
        item['details.affected.product']['$regex']
        for item in build_vendor_product_candidate_clause(dotted_i_filter)['$or']
        if 'details.affected.product' in item
    ]
    assert any(re.search(pattern, 'İstanbul', re.IGNORECASE) for pattern in dotted_i_patterns)
    assert classify_vendor_product_match({
        'details': {'affected': [{'vendor': 'Microsoft', 'product': 'İstanbul'}]},
    }, dotted_i_filter)['confidence'] == 'confirmed'

    decomposed_i_filter = _filter(_row(product='i\u0307stanbul'))
    decomposed_i_patterns = [
        item['details.affected.product']['$regex']
        for item in build_vendor_product_candidate_clause(decomposed_i_filter)['$or']
        if 'details.affected.product' in item
    ]
    assert any(
        re.search(pattern, 'İstanbul', re.IGNORECASE)
        for pattern in decomposed_i_patterns
    )
    assert classify_vendor_product_match({
        'details': {'affected': [{'vendor': 'Microsoft', 'product': 'İstanbul'}]},
    }, decomposed_i_filter)['confidence'] == 'confirmed'


def test_confirmed_match_requires_vendor_and_product_in_same_structured_entry():
    product_filter = _filter(_row(vendor='Acme', product='Widget'))
    confirmed = classify_vendor_product_match({
        'details': {'affected': [
            {'vendor': 'Other', 'product': 'Other Product'},
            {'vendor': 'ACME, INC.', 'product': 'Widget'},
        ]},
    }, product_filter)

    assert confirmed['confidence'] == 'confirmed'
    assert confirmed['row_number'] == 2
    assert confirmed['evidence']['source'] == 'details.affected[1]'

    cross_entry = classify_vendor_product_match({
        'details': {'affected': [
            {'vendor': 'Acme', 'product': 'Different Product'},
            {'vendor': 'Different Vendor', 'product': 'Widget'},
        ]},
    }, product_filter)
    assert cross_entry is None


def test_confirmed_match_accepts_explicit_aliases_after_normalization():
    product_filter = _filter(_row(
        vendor='Red Hat',
        product='Enterprise Linux',
        vendor_aliases=['RedHat'],
        product_aliases=['RHEL'],
    ))

    match = classify_vendor_product_match({
        'affected_products': [{'vendor': 'REDHAT', 'product': 'rhel'}],
    }, product_filter)

    assert match['confidence'] == 'confirmed'
    assert match['matched_vendor'] == 'Red Hat'
    assert match['matched_product'] == 'Enterprise Linux'


def test_nested_cve5_affected_and_descriptions_are_matched():
    product_filter = _filter(_row(vendor='Acme', product='Widget'))
    confirmed = classify_vendor_product_match({
        'details': {'containers': {'cna': {
            'affected': [{'vendor': 'Acme', 'product': 'Widget'}],
        }}},
    }, product_filter)
    probable = classify_vendor_product_match({
        'details': {'containers': {'cna': {
            'descriptions': [{'lang': 'en', 'value': 'Acme Widget is affected.'}],
        }}},
    }, product_filter)

    assert confirmed['confidence'] == 'confirmed'
    assert confirmed['evidence']['source'] == 'details.containers.cna.affected[0]'
    assert probable['confidence'] == 'probable'
    assert probable['evidence']['source'] == 'details.containers.cna.descriptions.value'


def test_probable_requires_vendor_and_product_in_one_fallback_segment():
    product_filter = _filter(_row(vendor='Microsoft', product='Exchange Server'))

    probable = classify_vendor_product_match({
        'affected': ['Microsoft Exchange Server 2019 and 2016'],
    }, product_filter)
    assert probable['confidence'] == 'probable'
    assert probable['evidence']['source'] == 'affected'

    split = classify_vendor_product_match({
        'affected': ['Microsoft products', 'Exchange Server deployments'],
    }, product_filter)
    assert split is None

    unsupported_nested_shape = classify_vendor_product_match({
        'description': {'text': 'Microsoft Exchange Server advisory'},
    }, product_filter)
    assert unsupported_nested_shape is None


def test_probable_rejects_fallback_text_that_conflicts_with_complete_structured_identity():
    product_filter = _filter(_row(vendor='Acme', product='Widget'))

    match = classify_vendor_product_match({
        'details': {'affected': [{'vendor': 'Contoso', 'product': 'Foo'}]},
        'title': 'Acme Widget security advisory',
    }, product_filter)

    assert match is None


def test_possible_match_requires_opt_in_and_absent_structured_vendor_evidence():
    row = _row(vendor='Microsoft', product='Exchange Server')
    document = {'description': 'Update guidance for Exchange Server deployments.'}

    assert classify_vendor_product_match(document, _filter(row)) is None
    possible = classify_vendor_product_match(
        document, _filter(row, include_possible=True),
    )
    assert possible['confidence'] == 'possible'
    assert possible['evidence']['type'] == 'product_without_structured_vendor'

    conflicting_vendor = {
        'details': {'affected': [{'vendor': 'Contoso', 'product': 'Something Else'}]},
        'description': 'Exchange Server update guidance.',
    }
    assert classify_vendor_product_match(
        conflicting_vendor, _filter(row, include_possible=True),
    ) is None


def test_possible_match_accepts_structured_product_with_unknown_vendor():
    match = classify_vendor_product_match({
        'details': {'affected': [{'vendor': 'Unknown', 'product': 'Exchange Server'}]},
    }, _filter(_row(), include_possible=True))

    assert match['confidence'] == 'possible'
    assert match['evidence']['type'] == 'structured_product_without_vendor'


def test_unknown_structured_identity_is_never_confirmed():
    product_filter = _filter(_row(), include_possible=True)

    match = classify_vendor_product_match({
        'details': {'affected': [{'vendor': 'Unknown', 'product': 'Exchange Server'}]},
    }, product_filter)

    assert match['confidence'] == 'possible'


def test_possible_match_suppresses_ambiguous_products_and_known_conflicting_vendors():
    ambiguous_filter = _filter(
        _row(vendor='Acme', product='Workspace'),
        _row(vendor='Contoso', product='Workspace'),
        include_possible=True,
    )
    conflicting_filter = _filter(
        _row(vendor='Microsoft', product='Exchange Server'),
        _row(vendor='Contoso', product='Other Product'),
        include_possible=True,
    )

    assert classify_vendor_product_match(
        {'description': 'Workspace security update.'}, ambiguous_filter,
    ) is None
    assert classify_vendor_product_match(
        {'description': 'Contoso Exchange Server security advisory.'},
        conflicting_filter,
    ) is None


def test_numeric_source_identity_is_not_accepted_when_mongo_regex_cannot_match_it():
    assert classify_vendor_product_match({
        'details': {'affected': [{'vendor': 'Acme', 'product': 1234}]},
    }, _filter(_row(vendor='Acme', product='1234'))) is None


def test_possible_match_rejects_short_or_generic_product_only_hits():
    generic = _filter(_row(vendor='Acme', product='Server'), include_possible=True)
    short = _filter(_row(vendor='Acme', product='OS'), include_possible=True)

    assert classify_vendor_product_match({'description': 'A server issue.'}, generic) is None
    assert classify_vendor_product_match({'description': 'An OS issue.'}, short) is None


def test_possible_match_uses_a_script_aware_threshold_for_cjk_products():
    distinctive = _filter(
        _row(vendor='Tencent', product='微信'), include_possible=True,
    )
    generic = _filter(
        _row(vendor='Acme', product='软件'), include_possible=True,
    )

    assert classify_vendor_product_match(
        {'description': '微信存在安全更新。'}, distinctive,
    )['confidence'] == 'possible'
    candidate_patterns = [
        item['description']['$regex']
        for item in build_vendor_product_candidate_clause(distinctive)['$or']
        if 'description' in item
    ]
    assert any(re.search(pattern, '微信存在安全更新。') for pattern in candidate_patterns)
    assert classify_vendor_product_match(
        {'description': '软件存在安全更新。'}, generic,
    ) is None
