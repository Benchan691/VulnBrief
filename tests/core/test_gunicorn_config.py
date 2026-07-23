from pathlib import Path

from gunicorn.app.base import Application
from gunicorn.config import Config
from gunicorn.workers.gthread import ThreadWorker


def test_gunicorn_uses_threaded_single_process_configuration():
    config_path = Path(__file__).resolve().parents[2] / 'gunicorn_config.py'
    application = Application.__new__(Application)
    application.cfg = Config()
    application.load_config_from_file(str(config_path))
    config = application.cfg

    assert config.bind == ['0.0.0.0:9100']
    assert config.workers == 1
    assert config.worker_class is ThreadWorker
    assert config.threads == 4
    assert config.timeout == 30
    assert config.graceful_timeout == 30
    assert config.keepalive == 5
