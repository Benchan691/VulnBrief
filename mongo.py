from pymongo import MongoClient

_config = None
_atlas_client = None
_local_client = None


def configure(config):
    global _config, _atlas_client, _local_client
    _config = config
    if _atlas_client is None:
        _atlas_client = MongoClient(
            config['ATLAS_MONGO_URI'],
            serverSelectionTimeoutMS=3000,
        )
    if _local_client is None and config.get('LOCAL_MONGO_URI'):
        _local_client = MongoClient(
            config['LOCAL_MONGO_URI'],
            serverSelectionTimeoutMS=3000,
        )


def get_config():
    if _config is None:
        raise RuntimeError('MongoDB is not configured. Call configure() or configure_application() first.')
    return _config


def get_atlas_mongo_client():
    if _atlas_client is None:
        raise RuntimeError('MongoDB is not configured. Call configure() or configure_application() first.')
    return _atlas_client


def get_local_mongo_client():
    if _local_client is None:
        raise RuntimeError('MongoDB is not configured. Call configure() or configure_application() first.')
    return _local_client


def get_mongo_client():
    """Backward-compatible alias for the local application MongoDB client."""
    return get_local_mongo_client()


def get_web_database():
    return get_local_mongo_client()[get_config()['LOCAL_DATABASE']]


def get_vulnerabilities_database():
    return get_atlas_mongo_client()[get_config()['VULNERABILITIES_DATABASE']]
