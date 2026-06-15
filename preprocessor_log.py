def _format_fields(fields):
    if not fields:
        return ''
    return ' ' + ' '.join(f'{key}={value}' for key, value in fields.items())


def log_info(message, **fields):
    print(f'[preprocessor] {message}{_format_fields(fields)}', flush=True)


def log_error(message, **fields):
    print(f'[preprocessor] ERROR {message}{_format_fields(fields)}', flush=True)
