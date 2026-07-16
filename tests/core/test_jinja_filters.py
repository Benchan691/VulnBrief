from core.templating import nl2br


def test_nl2br_converts_newlines_to_breaks():
    result = nl2br('Line one\nLine two')
    assert '<br>' in result
    assert 'Line one' in result
    assert 'Line two' in result


def test_nl2br_escapes_html():
    result = nl2br('<script>alert(1)</script>\nok')
    assert '<script>' not in result
    assert '&lt;script&gt;' in result
    assert '<br>' in result
