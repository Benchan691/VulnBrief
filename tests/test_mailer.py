from mailer import prepare_html_for_email


def test_prepare_html_for_email_inlines_styles():
    html = (
        '<html><head><style>'
        '.item-table th { background: #f4f0ff; }'
        '</style></head><body>'
        '<table class="item-table"><tr><th>Title</th></tr></table>'
        '</body></html>'
    )
    prepared = prepare_html_for_email(html)
    assert 'style=' in prepared
    assert 'background' in prepared
    assert 'Title' in prepared


def test_prepare_html_for_email_inlines_enriched_card_tables():
    html = (
        '<html><head><style>'
        '.vulnerability-card td { border-left: 4px solid #0f766e; background: #f7faf9; }'
        '</style></head><body>'
        '<table class="vulnerability-card"><tr><td>Card body</td></tr></table>'
        '</body></html>'
    )
    prepared = prepare_html_for_email(html)
    assert 'border-left' in prepared
    assert 'background' in prepared
    assert 'Card body' in prepared
