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
        _row(vendor='Acme (Global)', product='Widget+Pro', product_aliases=['Widget Pro']),
    ))

    row_clauses = clause['$or']
    affected = next(item for item in row_clauses if 'details.affected.product' in item)
    product_pattern = affected['details.affected.product']
    assert product_pattern['$options'] == 'i'
    # '+' is a significant identity symbol (C++, Widget+Pro) and is escaped
    # literally; a spaced alias still produces the token-boundary pattern.
    assert r'widget\+pro' in product_pattern['$regex']
    assert r'widget[\W_]+pro' in product_pattern['$regex']


def test_candidate_clause_skips_degenerate_single_character_products():
    clause = build_vendor_product_candidate_clause(_filter(
        _row(vendor='Acme', product='C'),
    ))

    # A single-letter product cannot match safely; the clause stays empty
    # instead of matching every advisory containing a standalone letter.
    assert clause == {}


def test_candidate_clause_covers_cpe_identity_fields():
    clause_text = str(build_vendor_product_candidate_clause(_filter(_row())))

    assert 'details.configurations.nodes.cpeMatch.criteria' in clause_text
    assert 'details.affected.cpes' in clause_text


def test_candidate_clause_covers_alternate_structured_keys_and_nested_description_values():
    clause_text = str(build_vendor_product_candidate_clause(_filter(_row())))

    assert 'details.containers.cna.affected.product' in clause_text
    assert 'details.containers.cna.affected.product_name' in clause_text
    assert 'details.descriptions.value' in clause_text
    assert 'details.affected_software.product' in clause_text
    assert 'details.systems_affected' in clause_text
    assert 'details.product_names' in clause_text
    assert 'details.product_statuses.product_names' in clause_text
    assert 'details.notes.value' in clause_text
    assert 'details.vulnerabilities.package.name' in clause_text
    assert 'details.affectedVendor' in clause_text
    assert 'details.productName' in clause_text
    assert 'details.description.vulnerability_information.product' in clause_text


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


def test_avd_affected_software_is_confirmed():
    product_filter = _filter(_row(vendor='Apache', product='ActiveMQ'))
    match = classify_vendor_product_match({
        'details': {
            'affected_software': [{
                'vendor': 'apache',
                'product': 'activemq',
                'version': '*',
                'impact': 'Up to 5.19.7',
            }],
        },
    }, product_filter)

    assert match['confidence'] == 'confirmed'
    assert match['evidence']['source'] == 'details.affected_software[0]'


def test_hkcert_systems_affected_supports_probable_and_possible_matches():
    product_filter = _filter(_row(vendor='Microsoft', product='Exchange Server'))
    probable = classify_vendor_product_match({
        'details': {
            'systems_affected': ['Microsoft Exchange Server 2019'],
        },
    }, product_filter)
    possible = classify_vendor_product_match({
        'details': {
            'systems_affected': ['Exchange Server deployments'],
        },
    }, _filter(_row(), include_possible=True))

    assert probable['confidence'] == 'probable'
    assert probable['evidence']['source'] == 'details.systems_affected'
    assert possible['confidence'] == 'possible'
    assert possible['evidence']['source'] == 'details.systems_affected'


def test_cisco_product_names_and_paloalto_products_are_matched():
    cisco = classify_vendor_product_match({
        'details': {'product_names': ['Cisco IOS XE Software']},
    }, _filter(_row(vendor='Cisco', product='IOS XE')))
    palo = classify_vendor_product_match({
        'details': {'products': ['PAN-OS']},
    }, _filter(_row(vendor='Palo Alto', product='PAN-OS'), include_possible=True))

    assert cisco['confidence'] == 'probable'
    assert cisco['evidence']['source'] == 'details.product_names'
    assert palo['confidence'] == 'possible'
    assert palo['evidence']['source'] == 'details.products'


def test_cnnvd_and_qianxin_structured_pairs_are_confirmed():
    cnnvd = classify_vendor_product_match({
        'details': {
            'affectedVendor': 'Acme',
            'affectedProduct': 'Widget',
            'affectedSystem': 'Widget OS',
        },
    }, _filter(_row(vendor='Acme', product='Widget')))
    qianxin = classify_vendor_product_match({
        'details': {
            'description': {
                'vulnerability_information': {
                    'vendor': 'Acme',
                    'product': 'Widget',
                },
            },
        },
    }, _filter(_row(vendor='Acme', product='Widget')))

    assert cnnvd['confidence'] == 'confirmed'
    assert cnnvd['evidence']['source'] == 'details.affectedVendor/affectedProduct'
    assert qianxin['confidence'] == 'confirmed'
    assert qianxin['evidence']['source'] == (
        'details.description.vulnerability_information.vendor/product'
    )


def test_github_advisory_package_entries_are_confirmed():
    match = classify_vendor_product_match({
        'details': {
            'vulnerabilities': [{
                'package': {'ecosystem': 'npm', 'name': 'lodash'},
                'vulnerable_version_range': '< 4.17.21',
            }],
        },
    }, _filter(_row(vendor='npm', product='lodash')))

    assert match['confidence'] == 'confirmed'
    assert match['evidence']['source'] == 'details.vulnerabilities[0]'


def test_govcert_affected_systems_and_fortiguard_affected_field_are_matched():
    govcert = classify_vendor_product_match({
        'details': {
            'affected_systems': ['Acme Widget appliances'],
        },
    }, _filter(_row(vendor='Acme', product='Widget')))
    fortiguard = classify_vendor_product_match({
        'details': {
            'affected_products': [
                {'version': '7.0', 'affected': 'FortiOS', 'solution': 'Upgrade'},
            ],
        },
    }, _filter(_row(vendor='Fortinet', product='FortiOS'), include_possible=True))

    assert govcert['confidence'] == 'probable'
    assert govcert['evidence']['source'] == 'details.affected_systems'
    assert fortiguard['confidence'] == 'possible'
    assert fortiguard['evidence']['type'] == 'structured_product_without_vendor'


def test_cpe_criteria_strings_are_confirmed_structured_evidence():
    match = classify_vendor_product_match({
        'title': 'novel-plus Missing Authorization Vulnerability',
        'details': {
            'configurations': [{'nodes': [{'cpeMatch': [{
                'criteria': 'cpe:2.3:a:xxyopen:novel-plus:*:*:*:*:*:*:*:*',
            }]}]}],
        },
    }, _filter(_row(vendor='XXYOPEN', product='novel-plus')))

    assert match['confidence'] == 'confirmed'
    assert match['evidence']['type'] == 'structured_pair'
    assert match['evidence']['source'] == 'cpe'


def test_cpe_legacy_format_and_hardware_parts_are_confirmed():
    legacy = classify_vendor_product_match({
        'details': {'affected': [{'cpes': ['cpe:/a:apache:http_server:2.4.49']}]},
    }, _filter(_row(vendor='Apache', product='HTTP Server')))

    hardware = classify_vendor_product_match({
        'details': {'affected': [{'cpes': ['cpe:2.3:h:fortinet:fortigate:-']}]},
    }, _filter(_row(vendor='Fortinet', product='FortiGate')))

    assert legacy['confidence'] == 'confirmed'
    assert hardware['confidence'] == 'confirmed'


def test_cpe_wildcard_or_na_components_never_match():
    wildcard_vendor = classify_vendor_product_match({
        'details': {'affected': [{'cpes': ['cpe:2.3:a:*:novel-plus:*:*:*:*:*:*:*:*']}]},
    }, _filter(_row(vendor='XXYOPEN', product='novel-plus')))
    na_product = classify_vendor_product_match({
        'details': {'affected': [{'cpes': ['cpe:2.3:a:xxyopen:-:*:*:*:*:*:*:*:*']}]},
    }, _filter(_row(vendor='XXYOPEN', product='novel-plus')))

    assert wildcard_vendor is None
    assert na_product is None


def test_structured_pairs_match_through_phrase_containment():
    family_row = _filter(_row(vendor='Linux', product='Linux kernel'))
    specific_doc = classify_vendor_product_match({
        'details': {'affected': [{'vendor': 'Linux', 'product': 'Linux'}]},
    }, family_row)
    aliased_vendor = classify_vendor_product_match({
        'details': {'affected': [{
            'vendor': 'Apache Software Foundation',
            'product': 'Apache HTTP Server',
        }]},
    }, _filter(_row(vendor='Apache', product='HTTP Server', vendor_aliases=['Apache Software Foundation'])))

    assert specific_doc['confidence'] == 'confirmed'
    assert aliased_vendor['confidence'] == 'confirmed'


def test_plus_and_hash_symbols_survive_identity_normalization():
    cpp = classify_vendor_product_match({
        'title': 'Buffer overflow in Acme C++ library',
        'details': {'description': 'The C++ parser in Acme C++ crashes.'},
    }, _filter(_row(vendor='Acme', product='C++')))
    csharp = classify_vendor_product_match({
        'title': 'Acme C# compiler rejects valid programs',
    }, _filter(_row(vendor='Acme', product='C#')))

    assert cpp['confidence'] == 'probable'
    assert csharp['confidence'] == 'probable'


def test_single_letter_product_never_matches_unrelated_text():
    match = classify_vendor_product_match({
        'title': 'Acme toolkit buffer overflow',
        'details': {
            'description': 'The CVSS vector is AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H.',
            'affected': [{'programFiles': ['bin/foo.c']}],
        },
    }, _filter(_row(vendor='Acme', product='C')))

    assert match is None


def test_cnnvd_vendor_and_product_names_are_confirmed():
    match = classify_vendor_product_match({
        'title': 'Linux kernel 安全漏洞',
        'details': {
            'vendorName': 'Linux',
            'productName': 'Linux kernel',
            'productSummary': 'Linux kernel是美国Linux基金会开源的一个操作系统内核。',
            'vulDesc': 'Linux kernel 存在安全漏洞。',
        },
    }, _filter(_row(vendor='Linux', product='Linux kernel')))

    assert match['confidence'] == 'confirmed'
    assert match['evidence']['source'] == 'details.vendorName/productName'


def test_msrc_product_names_are_probable_evidence():
    match = classify_vendor_product_match({
        'title': 'Chromium: CVE-2026-3063 Inappropriate implementation in DevTools',
        'details': {
            'product_statuses': [{'product_names': ['Microsoft Edge (Chromium-based)']}],
            'threats': [{'product_names': ['Microsoft Edge (Chromium-based)']}],
            'notes': [{'title': 'Chrome', 'value': 'Insufficient policy enforcement.'}],
        },
    }, _filter(_row(vendor='Microsoft', product='Edge')))

    assert match['confidence'] == 'probable'
    assert match['evidence']['source'] == 'details.product_statuses.product_names'


def test_probable_gating_survives_containment_for_unrelated_structured_identity():
    # Real-world shape (GitHub .NET advisory): the description boilerplate
    # mentions Microsoft, but the structured identity is an unrelated nuget
    # package. Text-only evidence for a different product must stay rejected.
    match = classify_vendor_product_match({
        'title': 'Microsoft Security Advisory CVE-2026-62900 – .NET Information Disclosure Vulnerability',
        'details': {
            'vulnerabilities': [{
                'package': {'ecosystem': 'nuget', 'name': 'Microsoft.Build.Tasks.Git'},
            }],
            'description': (
                'Microsoft is releasing this security advisory to provide information '
                'about a vulnerability in Microsoft.Build.Tasks.Git. This guidance also '
                'covers supported versions of Microsoft Windows.'
            ),
        },
    }, _filter(_row(vendor='Microsoft', product='Windows')))

    assert match is None


def test_structured_vendor_with_text_product_upgrades_to_probable():
    # Real-world shape (Qianxin Windows advisory): the structured product is a
    # Chinese category string, but the structured vendor matches the row and
    # the title names the product. The unrelated-identity gate must not bury it.
    match = classify_vendor_product_match({
        'title': 'Windows HTTP.sys 整数溢出漏洞(CVE-2026-62735)安全风险通告',
        'details': {
            'description': {
                'vulnerability_information': {
                    'vendor': 'Microsoft',
                    'product': '桌面操作系统，服务器操作系统',
                },
                'recommendations': 'Windows 系统默认启用 Microsoft Update。',
            },
        },
    }, _filter(_row(vendor='Microsoft', product='Windows')))

    assert match['confidence'] == 'probable'
    assert match['evidence']['type'] == 'structured_vendor_with_text_product'


def test_unrelated_structured_vendor_never_upgrades_text_product():
    # GitHub .NET advisory: structured vendor is nuget, not Microsoft, so the
    # description boilerplate mentioning Windows must stay unmatched.
    match = classify_vendor_product_match({
        'title': 'Microsoft Security Advisory CVE-2026-62900 – .NET Information Disclosure Vulnerability',
        'details': {
            'vulnerabilities': [{
                'package': {'ecosystem': 'nuget', 'name': 'Microsoft.Build.Tasks.Git'},
            }],
            'description': (
                'Microsoft is releasing this security advisory. This guidance also '
                'covers supported versions of Microsoft Windows.'
            ),
        },
    }, _filter(_row(vendor='Microsoft', product='Windows')))

    assert match is None


def test_msrc_remediation_descriptions_are_probable_evidence():
    match = classify_vendor_product_match({
        'title': 'Host Process for Windows Tasks Elevation of Privilege Vulnerability',
        'details': {
            'remediations': [{
                'description': '<p>Microsoft strongly recommends that you install the '
                               'updates. Customers running Windows should apply them.</p>',
            }],
        },
    }, _filter(_row(vendor='Microsoft', product='Windows')))

    assert match['confidence'] == 'probable'
    assert match['evidence']['source'] == 'details.remediations.description'


def test_solution_fields_are_probable_evidence():
    both = classify_vendor_product_match({
        'details': {
            'solution': 'CodeAstro has released a fix; upgrade Patient Record '
                        'Management System to the latest version.',
        },
    }, _filter(_row(vendor='CodeAstro', product='Patient Record Management System')))
    product_only = classify_vendor_product_match({
        'details': {
            'solution': 'Upgrade Patient Record Management System to the latest version.',
        },
    }, _filter(_row(vendor='CodeAstro', product='Patient Record Management System')))

    assert both['confidence'] == 'probable'
    assert both['evidence']['source'] == 'details.solution'
    # Product-only text without the vendor stays unmatched at probable tier.
    assert product_only is None


def test_cnnvd_product_alias_text_is_probable_evidence():
    match = classify_vendor_product_match({
        'title': 'Linux kernel 安全漏洞',
        'details': {
            'vendorName': 'Linux',
            'productName': 'Linux kernel',
            'vulAlias': 'linux kernel 安全漏洞',
        },
    }, _filter(_row(vendor='Linux', product='Linux kernel')))

    assert match['confidence'] == 'confirmed'


def test_cjk_latin_junctions_are_word_boundaries():
    # Source text glues CJK and Latin together ("...System是CodeAstro公司的...");
    # Mongo's ASCII \w sees boundaries there, so Python must too.
    match = classify_vendor_product_match({
        'details': {
            'description': 'Patient Record Management System是CodeAstro公司的一个病历管理系统。',
            'affected_products': ['Patient Record Management System v1.0'],
        },
    }, _filter(_row(vendor='CodeAstro', product='Patient Record Management System')))

    assert match['confidence'] == 'probable'


def test_platform_qualifier_for_product_is_not_possible_evidence():
    # Real-world shape (CNVD): "Zoom Rooms for Windows" is a Zoom advisory;
    # the OS name after 'for' is a platform qualifier, not the affected product.
    match = classify_vendor_product_match({
        'title': 'Zoom Rooms for Windows权限管理不当漏洞',
    }, _filter(_row(vendor='Microsoft', product='Windows'), include_possible=True))

    assert match is None


def test_platform_qualifier_does_not_suppress_specific_products():
    # Multi-token products ("Windows 11 Version 24H2") and non-qualifier
    # mentions keep their possible-tier evidence.
    match = classify_vendor_product_match({
        'details': {'product_statuses': [{'product_names': [
            'Windows 11 Version 24H2 for ARM64-based Systems',
        ]}]},
    }, _filter(_row(vendor='Microsoft', product='Windows 11 Version 24H2'), include_possible=True))

    assert match['confidence'] == 'possible'


def test_vendor_consistent_upgrade_ignores_narrative_fields():
    # Real-world shape (CNNVD SQL Server): productSummary boilerplate mentions
    # Microsoft Windows as the platform; that must not match a Windows row.
    match = classify_vendor_product_match({
        'title': 'Microsoft SQL Server 缓冲区错误漏洞',
        'details': {
            'vendorName': 'Microsoft',
            'productName': 'SQL Server',
            'productSummary': 'Microsoft SQL Server是美国Microsoft公司的一套应用在Microsoft Windows系统下的大型商业数据库系统。',
        },
    }, _filter(_row(vendor='Microsoft', product='Windows')))

    assert match is None


def test_vendor_consistent_upgrade_still_trusts_product_name_fields():
    # The structured product is unrelated (Visual Studio), so only the title's
    # product-name evidence can upgrade this Microsoft-vendor document.
    match = classify_vendor_product_match({
        'title': 'Windows OLE DB Information Disclosure Vulnerability',
        'details': {
            'vendorName': 'Microsoft',
            'productName': 'Visual Studio',
        },
    }, _filter(_row(vendor='Microsoft', product='Windows')))

    assert match['confidence'] == 'probable'
    assert match['evidence']['type'] == 'structured_vendor_with_text_product'
