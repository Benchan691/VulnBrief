import bcrypt

from mongo import get_web_database

AUTH_COLLECTION = 'auth'


def normalize_login(value):
    return (value or '').strip()


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def find_user(login):
    login = normalize_login(login)
    if not login:
        return None
    return get_web_database()[AUTH_COLLECTION].find_one({
        '$or': [
            {'username': login},
            {'email': login},
        ],
    })


def verify_login(login, password):
    user = find_user(login)
    if user is None:
        return None
    hashed_password = user.get('password') or ''
    if not hashed_password.startswith('$2'):
        return None
    if not bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
        return None
    return user


def upsert_user(username, password, email=None):
    username = normalize_login(username)
    if not username or not password:
        raise ValueError('Username and password are required.')
    document = {
        'username': username,
        'password': hash_password(password),
    }
    if email:
        document['email'] = normalize_login(email)
    get_web_database()[AUTH_COLLECTION].update_one(
        {'username': username},
        {'$set': document},
        upsert=True,
    )
    return document


def ensure_bootstrap_user(config):
    collection = get_web_database()[AUTH_COLLECTION]
    if collection.count_documents({}) > 0:
        return False
    username = normalize_login(config.get('WEB_AUTH_BOOTSTRAP_USERNAME', ''))
    password = config.get('WEB_AUTH_BOOTSTRAP_PASSWORD', '')
    if not username or not password:
        print(
            'WEB AUTH: web.auth is empty and bootstrap credentials are not configured.',
            flush=True,
        )
        return False
    upsert_user(username, password)
    print(
        f"WEB AUTH: created bootstrap user {username!r}. "
        'Change the password after first login.',
        flush=True,
    )
    return True
