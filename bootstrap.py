import os

from configuration import load_application_config
from mongo import configure


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def configure_application(base_dir=None):
    config = load_application_config(base_dir or BASE_DIR)
    configure(config)
    return config
