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


def normalize_username(value):
    return normalize_login(value)


def username_key(value):
    return normalize_username(value).casefold()


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
    login = normalize_username(login)
    key = username_key(login)
    if not key:
        return None
    collection = get_web_database()[AUTH_COLLECTION]
    user = collection.find_one({'username_key': key})
    if user is not None:
        return user
    return collection.find_one({'username': login})


def _find_user_by_username(username):
    return find_user(username)


def find_user_by_email(email):
    email = normalize_login(email)
    if not email:
        return None
    return get_web_database()[AUTH_COLLECTION].find_one({'email': email.casefold()})


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
    username = normalize_username(username)
    if not username:
        raise ValueError('Username is required.')
    if role not in VALID_ROLES:
        raise ValueError('Invalid user role.')
    now = datetime.now(timezone.utc)
    document = {
        'username': username,
        'username_key': username_key(username),
        'password': hash_password(password),
        'role': role,
        'must_change_password': bool(must_change_password),
        'updated_at': now,
    }
    email = normalize_login(email)
    if email:
        document['email'] = email.casefold()
    collection = get_web_database()[AUTH_COLLECTION]
    existing = _find_user_by_username(username)
    if existing is not None and existing.get('role') == ROLE_ADMIN and role != ROLE_ADMIN:
        raise ValueError('Username is already used by the administrator.')
    query = {'_id': existing['_id']} if existing is not None else {'username_key': username_key(username)}
    collection.update_one(
        query,
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


def ensure_subscription_user(username, password=None, email=None, *, user_id=None):
    username = normalize_username(username)
    if not username:
        raise ValueError('Username is required.')
    collection = get_web_database()[AUTH_COLLECTION]
    user = find_user_by_id(user_id) if user_id else None
    matching = _find_user_by_username(username)
    if matching is not None and (user is None or matching['_id'] != user['_id']):
        user = matching
        if user_id and str(user['_id']) != str(user_id):
            raise ValueError('Username is already in use.')
    if user is not None and user.get('role') == ROLE_ADMIN:
        raise ValueError('Username is already used by the administrator.')
    if user_id and user is None:
        raise ValueError('User not found.')
    if user is None and password is None:
        raise ValueError('Password is required.')
    if password is not None and password != '':
        password = _validate_password(password)

    now = datetime.now(timezone.utc)
    password_configured = password is not None and password != ''
    updates = {
        'username': username,
        'username_key': username_key(username),
        'role': ROLE_USER,
        'must_change_password': (
            False
            if password_configured or user is None
            else bool(user.get('must_change_password'))
        ),
        'updated_at': now,
    }
    email = normalize_login(email)
    if email:
        updates['email'] = email.casefold()
    if password_configured:
        updates['password'] = hash_password(password)
    if user is None:
        updates.update({
            'created_at': now,
        })
        collection.insert_one(updates)
        return collection.find_one({'username_key': username_key(username)})

    collection.update_one({'_id': user['_id']}, {'$set': updates})
    return collection.find_one({'_id': user['_id']})


def ensure_bootstrap_user(config):
    collection = get_web_database()[AUTH_COLLECTION]
    username = normalize_username(config.get('WEB_AUTH_BOOTSTRAP_USERNAME', ''))
    password = config.get('WEB_AUTH_BOOTSTRAP_PASSWORD', '')
    now = datetime.now(timezone.utc)
    created = False

    admin = collection.find_one({'role': ROLE_ADMIN})
    if admin is None:
        admin = _find_user_by_username(username) if username else None
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
        if user.get('username') and user.get('username_key') != username_key(user['username']):
            updates['username_key'] = username_key(user['username'])
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
    for subscription in web_database['sub_account'].find({}):
        emails = subscription.get('emails')
        if not isinstance(emails, list):
            emails = [subscription.get('email')]
        emails = [normalize_login(email).casefold() for email in emails if normalize_login(email)]
        if not emails:
            continue
        username = normalize_username(subscription.get('username'))
        owner_id = subscription.get('owner_user_id')
        user = find_user_by_id(owner_id) if owner_id else None
        if user is None and username:
            user = _find_user_by_username(username)
        if user is None:
            user = auth_collection.find_one({'username': emails[0]})
        if user is None:
            user = auth_collection.find_one({'email': emails[0]})
        if user is None:
            username = username or emails[0]
            result = auth_collection.insert_one({
                'username': username,
                'username_key': username_key(username),
                'email': emails[0],
                'password': hash_password(LEGACY_DEFAULT_PASSWORD),
                'role': ROLE_USER,
                'must_change_password': True,
                'created_at': now,
                'updated_at': now,
            })
            user = auth_collection.find_one({'_id': result.inserted_id})
        if user.get('role') == ROLE_ADMIN:
            continue
        updates = {}
        if not user.get('username'):
            username = username or emails[0]
            updates.update({
                'username': username,
                'username_key': username_key(username),
            })
        elif user.get('username_key') != username_key(user['username']):
            updates['username_key'] = username_key(user['username'])
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
        delivery_mode = subscription.get('delivery_mode')
        if not isinstance(delivery_mode, str) or delivery_mode not in {'individual', 'grouped'}:
            delivery_mode = 'individual'
        web_database['sub_account'].update_one(
            {'_id': subscription['_id']},
            {'$set': {
                'username': user.get('username') or username or emails[0],
                'owner_user_id': user['_id'],
                'emails': emails,
                'email': emails[0],
                'delivery_mode': delivery_mode,
                'updated_at': subscription.get('updated_at') or now,
            }},
        )
