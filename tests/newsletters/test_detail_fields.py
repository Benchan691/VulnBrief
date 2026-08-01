from newsletters.detail_fields import (
    discover_detail_fields,
    extract_detail_path,
    table_values,
)


class FakeCollection:
    def __init__(self, documents):
        self.documents = documents

    def find(self, query=None, projection=None):
        return FakeCursor(self.documents)


class FakeCursor:
    def __init__(self, documents):
        self.documents = documents

    def batch_size(self, size):
        return self

    def __iter__(self):
        return iter(self.documents)


class FakeDatabase:
    def __init__(self, documents):
        self.collection = FakeCollection(documents)

    def __getitem__(self, name):
        return self.collection


def test_discover_detail_fields_groups_nested_values_and_marks_internal_paths():
    fields = discover_detail_fields(FakeDatabase([
        {'details': {
            'affected': [
                {'vendor': 'Acme', 'versions': [{'version': '1.0'}]},
                {'vendor': 'Beta', 'versions': [{'version': '2.0'}]},
            ],
            'tags': ['security', 'remote'],
            '_internal': 'hidden',
        }},
        {'details': {'tags': ['security']}},
    ]), 'source')

    by_id = {field['id']: field for field in fields}
    assert by_id['details.affected']['type'] == 'table'
    assert by_id['details.affected[].vendor']['coverage'] == 1
    assert by_id['details.tags']['type'] == 'list'
    assert by_id['details._internal']['advanced'] is True
    assert by_id['details.tags']['coverage_percent'] == 100.0


def test_extract_detail_path_and_table_values_keep_nested_records_readable():
    details = {
        'affected': [
            {'vendor': 'Acme', 'product': 'Widget'},
            {'vendor': 'Beta', 'product': 'Gadget'},
        ],
    }

    assert extract_detail_path(details, 'details.affected[].vendor') == ['Acme', 'Beta']
    assert table_values(details['affected']) == {
        'headers': ['vendor', 'product'],
        'rows': [['Acme', 'Widget'], ['Beta', 'Gadget']],
    }
