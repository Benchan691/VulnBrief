"""Discovery and extraction helpers for source document details fields."""

from collections import defaultdict

from pymongo.errors import OperationFailure


DETAIL_PREFIX = 'details.'


def is_detail_path(value):
    """Return whether a value is a safe, supported details path."""
    if not isinstance(value, str) or not value.startswith(DETAIL_PREFIX):
        return False
    parts = value[len(DETAIL_PREFIX):].split('.')
    if not parts or any(not part for part in parts):
        return False
    for part in parts:
        name = part[:-2] if part.endswith('[]') else part
        if not name or name.startswith('$'):
            return False
    return True


def _path_label(path):
    parts = path[len(DETAIL_PREFIX):].split('.')
    labels = []
    for part in parts:
        part = part.removesuffix('[]')
        if not part:
            continue
        words = []
        current = ''
        for char in part.replace('_', ' ').replace('-', ' '):
            if current and char.isupper() and current[-1].islower():
                words.append(current)
                current = ''
            current += char
        if current:
            words.append(current)
        labels.append(' '.join(words).capitalize())
    return ' · '.join(labels)


def detail_field_label(path):
    return _path_label(path)


def _group_name(path):
    first = path[len(DETAIL_PREFIX):].split('.', 1)[0].removesuffix('[]')
    return first or 'Details'


def _type_name(value):
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'boolean'
    if isinstance(value, dict):
        return 'object'
    if isinstance(value, list):
        return 'array'
    return type(value).__name__


def _field_kind(value):
    if isinstance(value, list):
        if any(isinstance(item, dict) for item in value):
            return 'table'
        return 'list'
    return 'scalar'


def _is_internal(path):
    parts = path[len(DETAIL_PREFIX):].replace('[]', '').split('.')
    return any(part.startswith('_') for part in parts)


def _record(stats, path, value, document_paths):
    if path in document_paths:
        return
    document_paths.add(path)
    item = stats[path]
    item['coverage'] += 1
    item['types'].add(_type_name(value))
    item['kinds'].add(_field_kind(value))


def _walk_value(value, path, stats, document_paths):
    if isinstance(value, dict):
        if not value:
            return
        for key, child in value.items():
            _walk_value(child, f'{path}.{key}', stats, document_paths)
        return

    if isinstance(value, list):
        _record(stats, path, value, document_paths)
        if not value or all(not isinstance(item, (dict, list)) for item in value):
            return
        if all(isinstance(item, dict) for item in value):
            for item in value:
                for key, child in item.items():
                    _walk_value(child, f'{path}[].{key}', stats, document_paths)
        return

    _record(stats, path, value, document_paths)


def _build_fields(stats, document_count):
    fields = []
    for path, item in stats.items():
        fields.append({
            'id': path,
            'path': path,
            'label': _path_label(path),
            'group': _group_name(path),
            'type': 'table' if 'table' in item['kinds'] else (
                'list' if 'list' in item['kinds'] else 'text'
            ),
            'value_types': sorted(item['types']),
            'coverage': item['coverage'],
            'coverage_percent': round(item['coverage'] / document_count * 100, 1)
            if document_count else 0,
            'advanced': _is_internal(path),
            'builtin': False,
        })
    return sorted(fields, key=lambda item: (
        item['group'].casefold(), item['label'].casefold(), item['path'].casefold(),
    ))


DETAIL_PATH_FUNCTION = r'''function(details) {
  var result = [];
  var seen = {};
  function add(path, type, kind) {
    if (!seen[path]) {
      seen[path] = true;
      result.push({path: path, type: type, kind: kind});
    }
  }
  function walk(value, path) {
    if (value === null || typeof value !== 'object') {
      add(path, value === null ? 'null' : typeof value, 'scalar');
      return;
    }
    if (Array.isArray(value)) {
      if (value.length === 0) {
        add(path, 'array', 'list');
        return;
      }
      var allScalars = true;
      var allObjects = true;
      for (var i = 0; i < value.length; i++) {
        var item = value[i];
        if (item !== null && typeof item === 'object') {
          allScalars = false;
          if (Array.isArray(item)) allObjects = false;
        } else {
          allObjects = false;
        }
      }
      if (allScalars) {
        add(path, 'array', 'list');
        return;
      }
      if (allObjects) {
        add(path, 'array', 'table');
        for (var j = 0; j < value.length; j++) {
          var object = value[j];
          Object.keys(object).forEach(function(key) {
            walk(object[key], path + '[].' + key);
          });
        }
        return;
      }
      add(path, 'array', 'list');
      return;
    }
    var keys = Object.keys(value);
    if (!keys.length) return;
    keys.forEach(function(key) { walk(value[key], path + '.' + key); });
  }
  walk(details, 'details');
  return result.filter(function(item) { return item.path !== 'details'; });
}'''


def _discover_detail_fields_with_aggregation(database, source_collection):
    rows = database[source_collection].aggregate([
        {'$match': {'details': {'$type': 'object'}}},
        {'$project': {
            'fields': {
                '$function': {
                    'body': DETAIL_PATH_FUNCTION,
                    'args': ['$details'],
                    'lang': 'js',
                },
            },
        }},
        {'$unwind': '$fields'},
        {'$group': {
            '_id': '$fields.path',
            'coverage': {'$sum': 1},
            'types': {'$addToSet': '$fields.type'},
            'kinds': {'$addToSet': '$fields.kind'},
        }},
    ], maxTimeMS=30000)
    stats = defaultdict(lambda: {'coverage': 0, 'types': set(), 'kinds': set()})
    for row in rows:
        field = row.get('_id')
        if not field:
            continue
        stats[field]['coverage'] = int(row.get('coverage') or 0)
        stats[field]['types'].update(row.get('types') or [])
        stats[field]['kinds'].update(row.get('kinds') or [])
    document_count = database[source_collection].count_documents({'details': {'$type': 'object'}})
    return _build_fields(stats, document_count)


def _discover_detail_fields_in_python(database, source_collection):
    """Fallback for Mongo-compatible test doubles or servers without $function."""
    stats = defaultdict(lambda: {
        'coverage': 0,
        'types': set(),
        'kinds': set(),
    })
    document_count = 0
    for document in database[source_collection].find({}, {'details': 1}).batch_size(500):
        details = document.get('details')
        if not isinstance(details, dict):
            continue
        document_count += 1
        document_paths = set()
        for key, value in details.items():
            _walk_value(value, f'{DETAIL_PREFIX}{key}', stats, document_paths)

    return _build_fields(stats, document_count)


def discover_detail_fields(database, source_collection):
    """Discover usable details paths from every document in one source collection."""
    try:
        return _discover_detail_fields_with_aggregation(database, source_collection)
    except (AttributeError, NotImplementedError, OperationFailure, TypeError):
        return _discover_detail_fields_in_python(database, source_collection)


def extract_detail_path(details, path):
    """Extract a scalar, list, or object-list from a details path."""
    if not is_detail_path(path) or not isinstance(details, dict):
        return None
    parts = path[len(DETAIL_PREFIX):].split('.')

    def walk(value, index):
        if index >= len(parts):
            return [value]
        part = parts[index]
        is_array = part.endswith('[]')
        key = part[:-2] if is_array else part
        if not isinstance(value, dict) or key not in value:
            return []
        child = value[key]
        if is_array:
            if not isinstance(child, list):
                return []
            result = []
            for item in child:
                result.extend(walk(item, index + 1))
            return result
        return walk(child, index + 1)

    values = walk(details, 0)
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    return values


def scalar_values(value):
    if value in (None, '', [], {}):
        return []
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(scalar_values(item))
        return result
    if isinstance(value, dict):
        return []
    return [str(value)]


def table_values(value):
    if not isinstance(value, list) or not value or not all(isinstance(item, dict) for item in value):
        return None
    headers = []
    for item in value:
        for key in item:
            if key not in headers:
                headers.append(key)
    if not headers:
        return None
    rows = []
    for item in value:
        rows.append([
            ', '.join(scalar_values(item.get(header)))
            for header in headers
        ])
    return {'headers': headers, 'rows': rows}


def format_type_label(field):
    type_name = field.get('type') or 'text'
    return {
        'text': 'Text',
        'list': 'List',
        'table': 'Table',
    }.get(type_name, type_name.title())
