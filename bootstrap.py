import os

from dotenv import load_dotenv

from auth_store import ensure_bootstrap_user
from configuration import load_application_config
from mongo import configure


def ensure_sub_account_collection():
    from subscription_data import ensure_sub_account_collection as migrate_collection

    migrate_collection()


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_env(base_dir):
    load_dotenv(os.path.join(base_dir, '.env'))


def configure_application(base_dir=None):
    base_dir = base_dir or BASE_DIR
    _load_env(base_dir)
    config = load_application_config(base_dir)
    configure(config)
    ensure_sub_account_collection()
    ensure_bootstrap_user(config)
    return config
