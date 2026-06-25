import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

from bson import ObjectId


CONFIG_ID = 'operations'
RUN_LIMIT = 100
LOG_LIMIT = 20000
CHECK_SECONDS = 60
_PERSISTED_CONFIG_KEYS = ('catch_up', 'review', 'reclassify_cve')
_processes = {}
_lock = threading.Lock()
_scheduler_started = False


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        return None


def _resolve_python_path(config):
    python_path = str(config.get('python_path') or '').strip()
    preferred = os.path.join(config.get('avd_root') or '', '.venv', 'bin', 'python')
    exists = bool(python_path) and os.path.exists(python_path)
    if os.path.exists(preferred):
        config['python_path'] = preferred
    elif not python_path or python_path in {'python', 'python3'} or (os.path.sep in python_path and not exists):
        preferred = sys.executable or 'python'
        config['python_path'] = preferred
    return config


def default_config():
    avd_root = '/cyberclawer'
    python_path = os.path.join(avd_root, '.venv', 'bin', 'python')
    if not os.path.exists(python_path):
        python_path = sys.executable or 'python'
    defaults = {
        'avd_root': avd_root,
        'python_path': python_path,
        'vuln_scrape_module': 'vuln_scraper.cli',
        'classifier_daemon_path': os.path.join(avd_root, 'vendor_product_classifier', 'classifier_daemon.py'),
        'database': 'vulnerabilities',
        'catch_up': {
            'limit': 1000,
            'batch_size': 5,
            'max_runs_per_provider': 100,
            'include_manual_verification': False,
            'browser_headed': False,
            'manual_verification_timeout_seconds': '',
            'proxy': '',
            'periodic_enabled': False,
            'interval_hours': 24,
            'next_run_at': '',
            'last_started_at': '',
        },
        'review': {'providers': ''},
        'reclassify_cve': {'limit': '', 'zero_shot': False},
    }
    return _resolve_python_path(_merge(defaults, _configured_defaults()))


def _configured_defaults():
    value = (_app_config() or {}).get('OPERATIONS_CONFIG') or {}
    return value if isinstance(value, dict) else {}


def _app_config():
    try:
        from mongo import get_config
    except Exception:
        return {}
    try:
        return get_config()
    except Exception:
        return {}


def _persisted_overlay(source):
    if not source:
        return {}
    return {
        key: source[key]
        for key in _PERSISTED_CONFIG_KEYS
        if key in source and isinstance(source.get(key), dict)
    }


def load_config(database):
    stored = database['operation_config'].find_one({'_id': CONFIG_ID}) or {}
    config = _merge(default_config(), _persisted_overlay(stored))
    return _resolve_python_path(config)


def save_config(database, data):
    config = _merge(default_config(), _persisted_overlay(data))
    config['catch_up']['limit'] = max(1, int(config['catch_up'].get('limit') or 1000))
    config['catch_up']['batch_size'] = max(1, int(config['catch_up'].get('batch_size') or 5))
    config['catch_up']['max_runs_per_provider'] = max(1, int(config['catch_up'].get('max_runs_per_provider') or 100))
    config['catch_up']['interval_hours'] = max(1, int(config['catch_up'].get('interval_hours') or 24))
    persisted = {'_id': CONFIG_ID, **{key: config[key] for key in _PERSISTED_CONFIG_KEYS}}
    database['operation_config'].replace_one({'_id': CONFIG_ID}, persisted, upsert=True)
    return config


def reset_config(database):
    database['operation_config'].delete_one({'_id': CONFIG_ID})
    return load_config(database)


def start_catch_up_schedule(database):
    database['operation_config'].update_one(
        {'_id': CONFIG_ID},
        {'$set': {
            'catch_up.periodic_enabled': True,
            'catch_up.next_run_at': '',
        }},
        upsert=True,
    )
    return load_config(database)


def stop_catch_up_schedule(database):
    database['operation_config'].update_one(
        {'_id': CONFIG_ID},
        {'$set': {'catch_up.periodic_enabled': False}},
        upsert=True,
    )
    return load_config(database)


def _merge(base, override):
    result = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def list_runs(database):
    return [_serialize_run(run) for run in database['operation_runs'].find({}).sort('started_at', -1).limit(RUN_LIMIT)]


def clear_runs(database):
    result = database['operation_runs'].delete_many({'status': {'$ne': 'running'}})
    return {'deleted': result.deleted_count}


def run_logs(database, run_id):
    run = _find_run(database, run_id)
    return {'id': str(run['_id']), 'log': run.get('log', '')}


def start_operation(database, operation, *, scheduled=False, popen=None):
    config = load_config(database)
    if _active_run(database, operation):
        raise ValueError(f'{operation} is already running.')
    command = build_command(operation, config)
    _validate_command(config, command)
    run = {
        'operation': operation,
        'command': command,
        'cwd': config['avd_root'],
        'status': 'running',
        'scheduled': bool(scheduled),
        'started_at': now_iso(),
        'updated_at': now_iso(),
        'log': '',
    }
    result = database['operation_runs'].insert_one(run)
    run_id = result.inserted_id
    thread = threading.Thread(
        target=_run_process,
        args=(database, run_id, command, config['avd_root'], _process_env(config), popen or subprocess.Popen),
        daemon=True,
    )
    thread.start()
    if operation == 'catch_up' and scheduled:
        started = datetime.now(timezone.utc)
        database['operation_config'].update_one(
            {'_id': CONFIG_ID},
            {'$set': {
                'catch_up.last_started_at': started.isoformat(),
                'catch_up.next_run_at': (started + timedelta(hours=int(config['catch_up']['interval_hours']))).isoformat(),
            }},
            upsert=True,
        )
    return _serialize_run(database['operation_runs'].find_one({'_id': run_id}))


def stop_run(database, run_id):
    run = _find_run(database, run_id)
    if run.get('status') != 'running':
        return _serialize_run(run)
    with _lock:
        process = _processes.get(str(run['_id']))
    if process is None:
        raise ValueError('Process is not owned by this webserver process.')
    process.terminate()
    database['operation_runs'].update_one(
        {'_id': run['_id']},
        {'$set': {'status': 'stopped', 'updated_at': now_iso(), 'finished_at': now_iso()}},
    )
    return _serialize_run(database['operation_runs'].find_one({'_id': run['_id']}))


def build_command(operation, config):
    python = config['python_path']
    module = config.get('vuln_scrape_module') or 'vuln_scraper.cli'
    if operation == 'catch_up':
        catch_up = config['catch_up']
        command = [
            python, '-m', module, 'catch-up',
            '--limit', str(catch_up['limit']),
            '--batch-size', str(catch_up['batch_size']),
            '--max-runs-per-provider', str(catch_up['max_runs_per_provider']),
        ]
        if catch_up.get('include_manual_verification'):
            command.append('--include-manual-verification')
        if catch_up.get('browser_headed'):
            command.append('--browser-headed')
        if catch_up.get('manual_verification_timeout_seconds'):
            command += ['--manual-verification-timeout-seconds', str(catch_up['manual_verification_timeout_seconds'])]
        if catch_up.get('proxy'):
            command += ['--proxy', str(catch_up['proxy'])]
        return command
    if operation == 'review':
        providers = [item.strip() for item in str(config.get('review', {}).get('providers') or '').split(',') if item.strip()]
        return [python, '-m', module, 'review', *providers]
    if operation == 'classifier_daemon':
        return [python, config['classifier_daemon_path']]
    if operation == 'reclassify_cve':
        reclassify = config['reclassify_cve']
        command = [python, '-m', module, 'reclassify-cve', '--database', config['database']]
        if reclassify.get('limit'):
            command += ['--limit', str(reclassify['limit'])]
        if reclassify.get('zero_shot'):
            command.append('--zero-shot')
        return command
    raise ValueError('Unknown operation.')


def _process_env(config):
    env = os.environ.copy()
    app_config = _app_config()
    mongo_uri = config.get('mongo_uri') or app_config.get('MONGO_URI') or app_config.get('LOCAL_MONGO_URI')
    if mongo_uri:
        env['MONGO_URI'] = mongo_uri
        env['AVD_MONGO_URI'] = mongo_uri
    database = config.get('database') or app_config.get('VULNERABILITIES_DATABASE')
    if database:
        env['MONGO_DB'] = database
        env['AVD_MONGO_DB'] = database
    return env


def _validate_command(config, command):
    avd_root = config['avd_root']
    avd_exists = os.path.isdir(avd_root)
    if not avd_exists:
        raise ValueError('AVD root does not exist.')
    if os.path.sep in command[0] and not os.path.exists(command[0]):
        raise ValueError('Python path does not exist.')
    if command[1:2] != ['-m'] and not os.path.exists(command[1]):
        raise ValueError('Command script does not exist.')


def _run_process(database, run_id, command, cwd, env, popen):
    process = None
    try:
        process = popen(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
            env=env,
        )
        with _lock:
            _processes[str(run_id)] = process
        database['operation_runs'].update_one({'_id': run_id}, {'$set': {'pid': process.pid}})
        for line in process.stdout or []:
            _append_log(database, run_id, line)
        code = process.wait()
        run = database['operation_runs'].find_one({'_id': run_id}) or {}
        status = run.get('status')
        if status != 'stopped':
            status = 'succeeded' if code == 0 else 'failed'
        database['operation_runs'].update_one(
            {'_id': run_id},
            {'$set': {'status': status, 'exit_code': code, 'finished_at': now_iso(), 'updated_at': now_iso()}},
        )
    except Exception as exc:
        database['operation_runs'].update_one(
            {'_id': run_id},
            {'$set': {'status': 'failed', 'error': str(exc), 'finished_at': now_iso(), 'updated_at': now_iso()}},
        )
    finally:
        with _lock:
            _processes.pop(str(run_id), None)


def _append_log(database, run_id, text):
    run = database['operation_runs'].find_one({'_id': run_id}) or {}
    log = (run.get('log') or '') + text
    if len(log) > LOG_LIMIT:
        log = log[-LOG_LIMIT:]
    database['operation_runs'].update_one({'_id': run_id}, {'$set': {'log': log, 'updated_at': now_iso()}})


def _active_run(database, operation):
    return database['operation_runs'].find_one({'operation': operation, 'status': 'running'})


def _find_run(database, run_id):
    try:
        run = database['operation_runs'].find_one({'_id': ObjectId(run_id)})
    except Exception:
        run = None
    if not run:
        raise ValueError('Run not found.')
    return run


def _serialize_run(run):
    run = dict(run)
    run['id'] = str(run.pop('_id'))
    run.pop('log', None)
    return run


def start_scheduler(app, database_factory):
    global _scheduler_started
    if _scheduler_started:
        return
    _scheduler_started = True

    def loop():
        while True:
            time.sleep(CHECK_SECONDS)
            with app.app_context():
                try:
                    tick_scheduler(database_factory(), app)
                except Exception:
                    pass

    threading.Thread(target=loop, daemon=True).start()


def tick_scheduler(database, app=None):
    did_work = False
    if app is not None:
        try:
            from subscription_scheduler import tick_retention, tick_scheduled_reports
            did_work = bool(tick_scheduled_reports(app, database)) or did_work
            did_work = tick_retention(database) is not None or did_work
        except Exception:
            pass
    config = load_config(database)
    catch_up = config['catch_up']
    if not catch_up.get('periodic_enabled'):
        return did_work
    next_run = _parse_time(catch_up.get('next_run_at'))
    if next_run and datetime.now(timezone.utc) < next_run:
        return did_work
    if _active_run(database, 'catch_up'):
        return did_work
    start_operation(database, 'catch_up', scheduled=True)
    return True
