from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_newsletter_collection_picker_defaults_to_no_collections_and_can_clear_all():
    picker = (ROOT / 'static/js/shared/collection-picker.js').read_text()
    subscriptions_ui = (ROOT / 'static/js/subscriptions/index.js').read_text()

    assert 'this.emptySelectionMeansAll = options.emptySelectionMeansAll === true;' in picker
    assert "this.emptySelectionLabel = options.emptySelectionLabel || 'No collections';" in picker
    assert "this.allMode = typeof renderOptions.allMode === 'boolean'" in picker
    assert 'if (this.allMode) return [];' in picker
    assert "t(this.allMode ? 'All collections' : this.emptySelectionLabel)" in picker
    assert "new CollectionPicker('newsletter', {emptySelectionLabel: 'No collections'})" in subscriptions_ui
    assert 'data-action="clear"' in subscriptions_ui
    assert "t('Clear all')" in subscriptions_ui
    assert "t('No collections')" in subscriptions_ui
    assert "collection_selection:newsletterCollections.allMode ? 'all' : 'selected'" in subscriptions_ui
