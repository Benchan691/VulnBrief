from pymongo import MongoClient

_config = None
_client = None


def configure(config):
    global _config, _client
    _config = config
    if _client is None and config.get('MONGO_URI'):
        _client = MongoClient(
            config['MONGO_URI'],
            serverSelectionTimeoutMS=3000,
        )


def get_config():
    if _config is None:
        raise RuntimeError('MongoDB is not configured. Call configure() or configure_application() first.')
    return _config


def get_mongo_client():
    if _client is None:
        raise RuntimeError('MongoDB is not configured. Call configure() or configure_application() first.')
    return _client


def get_local_mongo_client():
    """Backward-compatible alias for the shared MongoDB client."""
    return get_mongo_client()


def get_web_database():
    config = get_config()
    return get_mongo_client()[config.get('WEB_DATABASE') or config['LOCAL_DATABASE']]


def get_vulnerabilities_database():
    return get_mongo_client()[get_config()['VULNERABILITIES_DATABASE']]
