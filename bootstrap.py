import os

from dotenv import load_dotenv

from auth_store import ensure_bootstrap_user
from configuration import load_application_config
from mongo import configure


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_env(base_dir):
    load_dotenv(os.path.join(base_dir, '.env'))


def configure_application(base_dir=None):
    base_dir = base_dir or BASE_DIR
    _load_env(base_dir)
    config = load_application_config(base_dir)
    configure(config)
    ensure_bootstrap_user(config)
    return config


def configure_worker(base_dir=None):
    base_dir = base_dir or BASE_DIR
    _load_env(base_dir)
    config = load_application_config(base_dir, require_local=False)
    configure(config)
    return config
