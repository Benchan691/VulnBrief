import json


def _normalize_value(value):
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.strip()
        return normalized if normalized else None
    return str(value)


def _casefold_key(value):
    normalized = _normalize_value(value)
    return normalized.casefold() if normalized is not None else None


def load_preprocessing_priorities(path):
    try:
        with open(path, encoding='utf-8') as handle:
            raw = json.load(handle)
    except FileNotFoundError as exc:
        raise ValueError(f'Preprocessing priorities config not found: {path}') from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f'Invalid preprocessing priorities JSON in {path}: {exc}') from exc

    if not isinstance(raw, dict):
        raise ValueError('Preprocessing priorities config must be a JSON object.')

    default = raw.get('default')
    if default is not None and not isinstance(default, int):
        raise ValueError('Preprocessing priorities "default" must be an integer.')

    collections = raw.get('collections', {})
    if not isinstance(collections, dict):
        raise ValueError('Preprocessing priorities "collections" must be an object.')
    for name, priority in collections.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError('Preprocessing priorities collection names must be non-empty strings.')
        if not isinstance(priority, int):
            raise ValueError(f'Preprocessing priority for collection "{name}" must be an integer.')

    field_boosts = raw.get('field_boosts', {})
    if not isinstance(field_boosts, dict):
        raise ValueError('Preprocessing priorities "field_boosts" must be an object.')
    normalized_boosts = {}
    for field, values in field_boosts.items():
        if not isinstance(field, str) or not field.strip():
            raise ValueError('Preprocessing priorities field_boosts keys must be non-empty strings.')
        if not isinstance(values, dict):
            raise ValueError(f'Preprocessing priorities field_boosts["{field}"] must be an object.')
        normalized_values = {}
        for value, boost in values.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f'Preprocessing priorities field_boosts["{field}"] keys must be non-empty strings.',
                )
            if not isinstance(boost, int):
                raise ValueError(
                    f'Preprocessing priorities field_boosts["{field}"]["{value}"] must be an integer.',
                )
            normalized_values[value.strip().casefold()] = boost
        normalized_boosts[field] = normalized_values

    normalized_collections = {str(name): priority for name, priority in collections.items()}
    return {
        'default': default,
        'collections': normalized_collections,
        'field_boosts': normalized_boosts,
    }


def document_field_value(document, field):
    if not isinstance(document, dict):
        return None
    top_level = document.get(field)
    if top_level not in (None, ''):
        return top_level
    details = document.get('details')
    if not isinstance(details, dict):
        return None
    if field in details and details[field] not in (None, ''):
        return details[field]
    for value in details.values():
        if isinstance(value, dict) and value.get(field) not in (None, ''):
            return value[field]
    return None


def collection_base_priority(collection_name, config):
    priorities = config.get('PREPROCESSING_PRIORITIES') or {}
    collections = priorities.get('collections') or {}
    if collection_name in collections:
        return collections[collection_name]
    default = priorities.get('default')
    if default is not None:
        return default
    return config['RABBITMQ_BACKGROUND_PRIORITY']


def field_boost_total(document, config):
    priorities = config.get('PREPROCESSING_PRIORITIES') or {}
    field_boosts = priorities.get('field_boosts') or {}
    total = 0
    for field, values in field_boosts.items():
        raw_value = document_field_value(document, field)
        key = _casefold_key(raw_value)
        if key is None:
            continue
        total += values.get(key, 0)
    return total


def resolve_preprocessing_priority(collection_name, document, config):
    priority = collection_base_priority(collection_name, config) + field_boost_total(document, config)
    return max(0, min(priority, config['RABBITMQ_MAX_PRIORITY']))


def review_document_sort_key(collection_name, document, config):
    priority = resolve_preprocessing_priority(collection_name, document, config)
    scraped_at = document.get('scraped_at') or ''
    return (priority, scraped_at, str(document.get('_id', '')))


def scan_projection(config):
    projection = {'details': 1}
    priorities = config.get('PREPROCESSING_PRIORITIES') or {}
    for field in (priorities.get('field_boosts') or {}):
        projection[field] = 1
    return projection


def sorted_scan_collections(collection_names, config):
    return sorted(
        collection_names,
        key=lambda name: collection_base_priority(name, config),
        reverse=True,
    )
