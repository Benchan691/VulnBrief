import re
from datetime import datetime, timezone

import bcrypt
from bson import ObjectId

from core.database import get_web_database


AUTH_COLLECTION = 'auth'
ROLE_ADMIN = 'admin'
ROLE_USER = 'user'
VALID_ROLES = {ROLE_ADMIN, ROLE_USER}
LEGACY_DEFAULT_PASSWORD = '1234'
MAX_PASSWORD_LENGTH = 256
MAX_PASSWORD_BYTES = 72
BCRYPT_HASH_PATTERN = re.compile(r'^\$2[aby]\$(0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}$')


def normalize_login(value):
    return value.strip() if isinstance(value, str) else ''


def _validate_password(password):
    if not isinstance(password, str) or not password:
        raise ValueError('Password is required.')
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f'Password must be {MAX_PASSWORD_LENGTH} characters or fewer.')
    if len(password.encode('utf-8')) > MAX_PASSWORD_BYTES:
        raise ValueError(f'Password must be {MAX_PASSWORD_BYTES} bytes or fewer.')
    return password


def validate_password(password):
    _validate_password(password)


def hash_password(password):
    return bcrypt.hashpw(
        _validate_password(password).encode('utf-8'),
        bcrypt.gensalt(),
    ).decode('utf-8')


def is_password_hash(value):
    return isinstance(value, str) and bool(BCRYPT_HASH_PATTERN.fullmatch(value))


def verify_password(user, password):
    hashed_password = user.get('password') or ''
    if not is_password_hash(hashed_password) or not isinstance(password, str):
        return False
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except (ValueError, TypeError):
        return False


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


def find_user_by_id(user_id):
    if not user_id:
        return None
    query_id = user_id
    try:
        query_id = ObjectId(str(user_id))
    except (TypeError, ValueError):
        pass
    return get_web_database()[AUTH_COLLECTION].find_one({'_id': query_id})


def verify_login(login, password):
    user = find_user(login)
    if user is None or not verify_password(user, password):
        return None
    return user


def public_user(user):
    if not user:
        return None
    return {
        'id': str(user.get('_id')) if user.get('_id') is not None else '',
        'username': user.get('username') or '',
        'email': user.get('email') or '',
        'role': user.get('role') or ROLE_USER,
        'must_change_password': bool(user.get('must_change_password')),
    }


def upsert_user(
    username,
    password,
    email=None,
    *,
    role=ROLE_USER,
    must_change_password=False,
):
    username = normalize_login(username)
    if not username:
        raise ValueError('Username is required.')
    if role not in VALID_ROLES:
        raise ValueError('Invalid user role.')
    now = datetime.now(timezone.utc)
    document = {
        'username': username,
        'password': hash_password(password),
        'role': role,
        'must_change_password': bool(must_change_password),
        'updated_at': now,
    }
    email = normalize_login(email)
    if email:
        document['email'] = email
    get_web_database()[AUTH_COLLECTION].update_one(
        {'username': username},
        {'$set': document, '$setOnInsert': {'created_at': now}},
        upsert=True,
    )


def update_user_password(user, password, *, must_change_password=False):
    password = _validate_password(password)
    user_id = user.get('_id') if isinstance(user, dict) else user
    if user_id is None:
        raise ValueError('User not found.')
    get_web_database()[AUTH_COLLECTION].update_one(
        {'_id': user_id},
        {'$set': {
            'password': hash_password(password),
            'must_change_password': bool(must_change_password),
            'updated_at': datetime.now(timezone.utc),
        }},
    )


def ensure_subscription_user(email, password):
    email = normalize_login(email)
    password = _validate_password(password)
    if not email:
        raise ValueError('Email is required.')

    collection = get_web_database()[AUTH_COLLECTION]
    user = collection.find_one({'$or': [{'email': email}, {'username': email}]})
    if user is not None and user.get('role') == ROLE_ADMIN:
        raise ValueError('Email is already used by the administrator.')

    now = datetime.now(timezone.utc)
    updates = {
        'password': hash_password(password),
        'email': email,
        'role': ROLE_USER,
        'must_change_password': False,
        'updated_at': now,
    }
    if user is None:
        updates.update({
            'username': email,
            'created_at': now,
        })
        collection.insert_one(updates)
        return

    collection.update_one({'_id': user['_id']}, {'$set': updates})


def ensure_bootstrap_user(config):
    collection = get_web_database()[AUTH_COLLECTION]
    username = normalize_login(config.get('WEB_AUTH_BOOTSTRAP_USERNAME', ''))
    password = config.get('WEB_AUTH_BOOTSTRAP_PASSWORD', '')
    now = datetime.now(timezone.utc)
    created = False

    admin = collection.find_one({'role': ROLE_ADMIN})
    if admin is None:
        admin = collection.find_one({'username': username}) if username else None
        if admin is not None:
            collection.update_one({'_id': admin['_id']}, {'$set': {
                'role': ROLE_ADMIN,
                'must_change_password': False,
                'updated_at': now,
            }})
        elif username and password:
            upsert_user(
                username,
                password,
                role=ROLE_ADMIN,
                must_change_password=False,
            )
            admin = collection.find_one({'username': username})
            created = True
        else:
            admin = collection.find_one({})
            if admin is not None:
                collection.update_one({'_id': admin['_id']}, {'$set': {
                    'role': ROLE_ADMIN,
                    'must_change_password': False,
                    'updated_at': now,
                }})
            else:
                print(
                    'WEB AUTH: web.auth is empty and bootstrap credentials are not configured.',
                    flush=True,
                )
                return False

    admin_id = admin['_id']
    if not is_password_hash(admin.get('password')) and password:
        collection.update_one({'_id': admin_id}, {'$set': {
            'password': hash_password(password),
            'must_change_password': False,
            'updated_at': now,
        }})

    for user in collection.find({}):
        updates = {}
        if user['_id'] == admin_id:
            if user.get('role') != ROLE_ADMIN:
                updates['role'] = ROLE_ADMIN
            if 'must_change_password' not in user:
                updates['must_change_password'] = False
        else:
            if user.get('role') != ROLE_USER:
                updates['role'] = ROLE_USER
            if not is_password_hash(user.get('password')):
                updates.update({
                    'password': hash_password(LEGACY_DEFAULT_PASSWORD),
                    'must_change_password': True,
                })
            elif 'must_change_password' not in user:
                updates['must_change_password'] = False
        if updates:
            updates['updated_at'] = now
            collection.update_one({'_id': user['_id']}, {'$set': updates})

    if created:
        print(
            f"WEB AUTH: created bootstrap user {username!r}. "
            'Change the password after first login.',
            flush=True,
        )
    return created


def ensure_legacy_subscription_users():
    web_database = get_web_database()
    auth_collection = web_database[AUTH_COLLECTION]
    now = datetime.now(timezone.utc)
    for subscription in web_database['sub_account'].find({}, {'email': 1}):
        email = normalize_login(subscription.get('email'))
        if not email:
            continue
        user = auth_collection.find_one({
            '$or': [{'email': email}, {'username': email}],
        })
        if user is None:
            auth_collection.insert_one({
                'username': email,
                'email': email,
                'password': hash_password(LEGACY_DEFAULT_PASSWORD),
                'role': ROLE_USER,
                'must_change_password': True,
                'created_at': now,
                'updated_at': now,
            })
            continue
        if user.get('role') == ROLE_ADMIN:
            continue
        updates = {}
        if user.get('role') != ROLE_USER:
            updates['role'] = ROLE_USER
        if not is_password_hash(user.get('password')):
            updates.update({
                'password': hash_password(LEGACY_DEFAULT_PASSWORD),
                'must_change_password': True,
            })
        elif 'must_change_password' not in user:
            updates['must_change_password'] = False
        if updates:
            updates['updated_at'] = now
            auth_collection.update_one({'_id': user['_id']}, {'$set': updates})
