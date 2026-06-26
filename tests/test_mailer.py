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
