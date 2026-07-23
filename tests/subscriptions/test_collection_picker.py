from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_newsletter_collection_picker_uses_dynamic_all_mode():
    picker = (ROOT / 'static/js/shared/collection-picker.js').read_text()
    subscriptions_ui = (ROOT / 'static/js/subscriptions/index.js').read_text()
    feed_ui = (ROOT / 'static/js/newsletters/feed.js').read_text()

    assert 'this.emptySelectionMeansAll = options.emptySelectionMeansAll === true;' in picker
    assert 'this.allMode = this.emptySelectionMeansAll && selected.length === 0;' in picker
    assert 'if (this.allMode) return [];' in picker
    assert "new CollectionPicker('newsletter', {emptySelectionMeansAll: true})" in subscriptions_ui
    assert 'data-action="reset">Reset to all</button>' in subscriptions_ui
    assert "new CollectionPicker('feed')" in feed_ui
