import os

from dotenv import load_dotenv

from core.config import load_application_config
from core.database import configure


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_env(base_dir):
    load_dotenv(os.path.join(base_dir, '.env'))


def configure_application(base_dir=None):
    base_dir = base_dir or BASE_DIR
    _load_env(base_dir)
    config = load_application_config(base_dir)
    configure(config)
    return config
