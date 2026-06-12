import os

from auth_store import ensure_bootstrap_user
from configuration import load_application_config
from mongo import configure


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def configure_application(base_dir=None):
    config = load_application_config(base_dir or BASE_DIR)
    configure(config)
    ensure_bootstrap_user(config)
    return config


def configure_worker(base_dir=None):
    config = load_application_config(base_dir or BASE_DIR, require_local=False)
    configure(config)
    return config
