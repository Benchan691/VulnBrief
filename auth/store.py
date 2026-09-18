import re
from datetime import datetime, timezone

import bcrypt
from bson import ObjectId
from flask import current_app

from core.database import get_config, get_web_database


AUTH_COLLECTION = 'auth'
AUTH_SOURCE_LOCAL = 'local'
AUTH_SOURCE_ACCOUNT_HUB = 'account_hub'
ROLE_ADMIN = 'admin'
ROLE_SUB_ADMIN = 'sub_admin'
ROLE_USER = 'user'
ADMIN_ROLES = {ROLE_ADMIN, ROLE_SUB_ADMIN}
VALID_ROLES = ADMIN_ROLES | {ROLE_USER}
LEGACY_DEFAULT_PASSWORD = '1234'
MAX_PASSWORD_LENGTH = 256
MAX_PASSWORD_BYTES = 72
BCRYPT_HASH_PATTERN = re.compile(r'^\$2[aby]\$(0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}$')
EMAIL_PATTERN = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
_UNSET = object()


def _account_hub_enabled():
    """Read the active Flask setting, falling back to the database config."""
    try:
        return bool(current_app.config.get('ACCOUNT_HUB_ENABLED'))
    except RuntimeError:
        return bool(get_config().get('ACCOUNT_HUB_ENABLED'))


def normalize_login(value):
    return value.strip() if isinstance(value, str) else ''


def normalize_username(value):
    return normalize_login(value)


def normalize_email(value):
    return normalize_login(value).casefold()


def validate_email(value):
    if value is not None and not isinstance(value, str):
        raise ValueError('Invalid email address.')
    email = normalize_email(value)
    if email and not EMAIL_PATTERN.fullmatch(email):
        raise ValueError('Invalid email address.')
    return email


def username_key(value):
    return normalize_username(value).casefold()


def account_hub_uid_key(value):
    if value is None or isinstance(value, bool):
        return ''
    return str(value).strip()


def _configured_bootstrap_username(username=None):
    if username is not None:
        return normalize_username(username)
    try:
        configured = current_app.config.get('WEB_AUTH_BOOTSTRAP_USERNAME')
    except RuntimeError:
        configured = get_config().get('WEB_AUTH_BOOTSTRAP_USERNAME')
    return normalize_username(configured)


def is_bootstrap_username(value, username=None):
    """Return whether ``value`` is the configured bootstrap username."""
    return bool(
        username_key(value)
        and username_key(value) == username_key(_configured_bootstrap_username(username))
    )


def is_local_bootstrap_user(user, username=None):
    """Return whether a record is the reserved local top administrator."""
    if not isinstance(user, dict):
        return False
    expected = _configured_bootstrap_username(username)
    source = user.get('auth_source')
    if source is None and 'auth_source' not in user:
        # Legacy rows omitted the field entirely.  An explicitly empty or
        # unknown value is malformed and must fail closed instead.
        source = AUTH_SOURCE_LOCAL if user.get('role') == ROLE_ADMIN else ''
    return (
        source == AUTH_SOURCE_LOCAL
        and user.get('role') == ROLE_ADMIN
        and username_key(user.get('username')) == username_key(expected)
    )


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
    username = normalize_username(username)
    user = find_user(username)
    if user is not None:
        return user
    if not username:
        return None
    return get_web_database()[AUTH_COLLECTION].find_one({
        'username': {
            '$regex': f'^{re.escape(username)}$',
            '$options': 'i',
        },
    })


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


def find_user_by_account_hub_uid(uid):
    uid = account_hub_uid_key(uid)
    if not uid:
        return None
    return get_web_database()[AUTH_COLLECTION].find_one({
        'account_hub_uid': uid,
    })


def verify_login(login, password):
    user = find_user(login)
    if user is None or user.get('disabled') or not verify_password(user, password):
        return None
    return user


def public_user(user):
    if not user:
        return None
    result = {
        'id': str(user.get('_id')) if user.get('_id') is not None else '',
        'username': user.get('username') or '',
        'email': user.get('email') or '',
        'role': user.get('role') or ROLE_USER,
        'must_change_password': bool(user.get('must_change_password')),
        'disabled': bool(user.get('disabled')),
        'pause_managed_subscriptions_when_disabled': bool(
            user.get('pause_managed_subscriptions_when_disabled')
        ),
    }
    result.update({
        'auth_source': user.get('auth_source') or AUTH_SOURCE_LOCAL,
        'account_hub_uid': str(user.get('account_hub_uid'))
        if user.get('account_hub_uid') not in (None, '') else '',
        'account_hub_username': user.get('account_hub_username') or '',
        'account_hub_bound': bool(user.get('account_hub_uid')),
    })
    for field in ('created_at', 'updated_at', 'last_account_hub_sync_at'):
        if user.get(field) is not None and hasattr(user[field], 'isoformat'):
            result[field] = user[field].isoformat()
    return result


def is_admin_role(role_or_user):
    role = role_or_user.get('role') if isinstance(role_or_user, dict) else role_or_user
    return role in ADMIN_ROLES


def ensure_account_hub_user(username, email=None):
    """Create or update a local Hub identity without a password."""
    username = normalize_username(username)
    if not username:
        raise ValueError('Username is required.')
    if is_bootstrap_username(username):
        raise ValueError('Username is reserved for the local administrator.')
    email = validate_email(email)
    collection = get_web_database()[AUTH_COLLECTION]
    user = _find_user_by_username(username)
    if user is not None and (
        user.get('auth_source') == AUTH_SOURCE_LOCAL
        or (not user.get('auth_source') and user.get('role') == ROLE_ADMIN)
    ):
        raise ValueError('Username is reserved for the local administrator.')
    now = datetime.now(timezone.utc)
    updates = {
        'username': username,
        'username_key': username_key(username),
        'auth_source': AUTH_SOURCE_ACCOUNT_HUB,
        'must_change_password': False,
        'updated_at': now,
    }
    if user is None or user.get('role') not in (ROLE_USER, ROLE_SUB_ADMIN):
        # A new or malformed row starts as a regular portal user.
        updates['role'] = ROLE_USER
    if email:
        updates['email'] = email
    if user is None:
        updates.update({
            'disabled': False,
            'pause_managed_subscriptions_when_disabled': False,
            'created_at': now,
        })
        result = collection.insert_one(updates)
        return collection.find_one({'_id': result.inserted_id})
    collection.update_one(
        {'_id': user['_id']},
        {'$set': updates, '$unset': {'password': ''}},
    )
    return collection.find_one({'_id': user['_id']})


def list_account_hub_users():
    return list(get_web_database()[AUTH_COLLECTION].find({
        'auth_source': AUTH_SOURCE_ACCOUNT_HUB,
    }).sort('username_key', 1))


def update_account_hub_user(
    user_id,
    *,
    email=_UNSET,
    role=_UNSET,
    disabled=_UNSET,
    pause_managed_subscriptions_when_disabled=_UNSET,
):
    user = find_user_by_id(user_id)
    if user is None or user.get('auth_source') != AUTH_SOURCE_ACCOUNT_HUB:
        raise LookupError('Account Hub user not found.')
    updates = {'updated_at': datetime.now(timezone.utc)}
    if role is not _UNSET:
        if role not in (ROLE_USER, ROLE_SUB_ADMIN):
            raise ValueError('Invalid user role.')
        updates['role'] = role
    elif user.get('role') not in (ROLE_USER, ROLE_SUB_ADMIN):
        updates['role'] = ROLE_USER
    if email is not _UNSET:
        email = validate_email(email)
        updates['email'] = email or None
    if disabled is not _UNSET:
        updates['disabled'] = bool(disabled)
    if pause_managed_subscriptions_when_disabled is not _UNSET:
        updates['pause_managed_subscriptions_when_disabled'] = bool(
            pause_managed_subscriptions_when_disabled
        )
    get_web_database()[AUTH_COLLECTION].update_one(
        {'_id': user['_id']},
        {'$set': updates, '$unset': {'password': ''}},
    )
    return find_user_by_id(user['_id'])


def find_account_hub_user(uid, username):
    user = find_user_by_account_hub_uid(uid)
    if user is not None:
        if user.get('auth_source') != AUTH_SOURCE_ACCOUNT_HUB:
            return None
        return user
    user = _find_user_by_username(username)
    if user is None or user.get('auth_source') != AUTH_SOURCE_ACCOUNT_HUB:
        return None
    return user


def sync_account_hub_user(user, claims):
    uid = account_hub_uid_key(claims.get('uid'))
    username = normalize_username(claims.get('username'))
    if not uid or not username:
        raise ValueError('Account Hub identity is incomplete.')
    if is_bootstrap_username(username):
        raise ValueError('Account Hub identity cannot use the local administrator username.')
    if user.get('auth_source') == AUTH_SOURCE_LOCAL or (
        not user.get('auth_source') and user.get('role') == ROLE_ADMIN
    ):
        raise ValueError('Account Hub cannot replace the local administrator.')
    bound_uid = account_hub_uid_key(user.get('account_hub_uid'))
    if bound_uid and bound_uid != uid:
        raise ValueError('Account Hub identity does not match the local user.')
    by_uid = find_user_by_account_hub_uid(uid)
    if by_uid is not None and by_uid['_id'] != user['_id']:
        raise ValueError('Account Hub identity is already linked to another user.')
    now = datetime.now(timezone.utc)
    updates = {
        'auth_source': AUTH_SOURCE_ACCOUNT_HUB,
        'account_hub_uid': uid,
        'account_hub_username': username,
        'role': user.get('role') if user.get('role') in (ROLE_USER, ROLE_SUB_ADMIN) else ROLE_USER,
        'must_change_password': False,
        'last_account_hub_sync_at': now,
        'updated_at': now,
    }
    get_web_database()[AUTH_COLLECTION].update_one(
        {'_id': user['_id']},
        {'$set': updates, '$unset': {'password': ''}},
    )
    return find_user_by_id(user['_id'])


def login_account_hub_user(claims):
    """Create a local profile after Hub authentication, preserving local roles."""
    uid = account_hub_uid_key(claims.get('uid'))
    username = normalize_username(claims.get('username'))
    if not uid or not username or is_bootstrap_username(username):
        raise ValueError('Account Hub identity is incomplete.')
    user = find_account_hub_user(uid, username)
    if user is None:
        # A matching local password account or an existing UID binding must
        # never be silently taken over by a newly authenticated Hub identity.
        if _find_user_by_username(username) is not None or find_user_by_account_hub_uid(uid) is not None:
            raise ValueError('Account Hub identity conflicts with a local user.')
        user = ensure_account_hub_user(username, claims.get('email'))
    if user.get('disabled'):
        raise ValueError('This portal account is disabled.')
    return sync_account_hub_user(user, claims)


def upsert_user(
    username,
    password,
    email=None,
    *,
    role=ROLE_USER,
    must_change_password=False,
    auth_source=AUTH_SOURCE_LOCAL,
):
    username = normalize_username(username)
    if not username:
        raise ValueError('Username is required.')
    if role not in VALID_ROLES:
        raise ValueError('Invalid user role.')
    if auth_source not in {AUTH_SOURCE_LOCAL, AUTH_SOURCE_ACCOUNT_HUB}:
        raise ValueError('Invalid authentication source.')
    now = datetime.now(timezone.utc)
    document = {
        'username': username,
        'username_key': username_key(username),
        'password': hash_password(password),
        'role': role,
        'must_change_password': bool(must_change_password),
        'auth_source': auth_source,
        'updated_at': now,
    }
    email = validate_email(email)
    if email:
        document['email'] = email.casefold()
    if role == ROLE_SUB_ADMIN:
        document.update({
            'disabled': False,
            'pause_managed_subscriptions_when_disabled': False,
        })
    collection = get_web_database()[AUTH_COLLECTION]
    existing = _find_user_by_username(username)
    if existing is not None and is_admin_role(existing) and existing.get('role') != role:
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
    account_hub_enabled = _account_hub_enabled()
    if account_hub_enabled and is_bootstrap_username(username):
        raise ValueError('Username is reserved for the local administrator.')
    collection = get_web_database()[AUTH_COLLECTION]
    user = find_user_by_id(user_id) if user_id else None
    matching = _find_user_by_username(username)
    if matching is not None and (user is None or matching['_id'] != user['_id']):
        user = matching
        if user_id and str(user['_id']) != str(user_id):
            raise ValueError('Username is already in use.')
    if user is not None and is_admin_role(user):
        raise ValueError('Username is already used by the administrator.')
    if user_id and user is None:
        raise ValueError('User not found.')
    if account_hub_enabled:
        if password not in (None, ''):
            raise ValueError('Account Hub users do not use local passwords.')
        if user is None or user.get('auth_source') != AUTH_SOURCE_ACCOUNT_HUB:
            raise ValueError('Account Hub user must be approved before creating a subscription.')
        if username_key(user.get('username')) != username_key(username):
            raise ValueError('Account Hub user must be approved before changing its username.')
    if user is None and password is None and not account_hub_enabled:
        raise ValueError('Password is required.')
    if password is not None and password != '':
        password = _validate_password(password)

    now = datetime.now(timezone.utc)
    password_configured = password is not None and password != ''
    updates = {
        'username': username,
        'username_key': username_key(username),
        'role': ROLE_USER,
        'auth_source': AUTH_SOURCE_ACCOUNT_HUB if account_hub_enabled else (
            user.get('auth_source') if user else AUTH_SOURCE_LOCAL
        ),
        'must_change_password': (
            False
            if account_hub_enabled or password_configured or user is None
            else bool(user.get('must_change_password'))
        ),
        'updated_at': now,
    }
    email = normalize_email(email)
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

    update = {'$set': updates}
    if account_hub_enabled:
        update['$unset'] = {'password': ''}
    collection.update_one({'_id': user['_id']}, update)
    return collection.find_one({'_id': user['_id']})


def _user_has_subscription(user):
    conditions = [{'owner_user_id': user['_id']}]
    for field in ('username', 'email'):
        value = normalize_login(user.get(field))
        if value:
            conditions.append({
                field: {
                    '$regex': f'^{re.escape(value)}$',
                    '$options': 'i',
                },
            })
    email = normalize_login(user.get('email'))
    if email:
        conditions.append({
            'emails': {
                '$regex': f'^{re.escape(email)}$',
                '$options': 'i',
            },
        })
    return get_web_database()['sub_account'].find_one({'$or': conditions}) is not None


def create_sub_admin(
    username,
    password,
    email=None,
    *,
    disabled=False,
    pause_managed_subscriptions_when_disabled=False,
    parent_admin_id=None,
):
    username = normalize_username(username)
    if not username:
        raise ValueError('Username is required.')
    if is_bootstrap_username(username):
        raise ValueError('Username is reserved for the local administrator.')
    password = _validate_password(password)
    email = validate_email(email)
    collection = get_web_database()[AUTH_COLLECTION]
    existing_username = _find_user_by_username(username)
    existing_email = find_user_by_email(email) if email else None
    if existing_username is not None and existing_username.get('role') != ROLE_USER:
        raise ValueError('Username is already in use.')
    if existing_username is not None and _user_has_subscription(existing_username):
        raise ValueError('Username is already in use.')
    if existing_email is not None and existing_email.get('role') != ROLE_USER:
        raise ValueError('Email is already in use.')
    if existing_email is not None and _user_has_subscription(existing_email):
        raise ValueError('Email is already in use.')
    if (
        existing_username is not None
        and existing_email is not None
        and existing_username['_id'] != existing_email['_id']
    ):
        raise ValueError('Email is already in use.')
    existing = existing_username or existing_email
    now = datetime.now(timezone.utc)
    document = {
        'username': username,
        'username_key': username_key(username),
        'password': hash_password(password),
        'role': ROLE_SUB_ADMIN,
        'auth_source': AUTH_SOURCE_LOCAL,
        'must_change_password': False,
        'disabled': bool(disabled),
        'pause_managed_subscriptions_when_disabled': bool(
            pause_managed_subscriptions_when_disabled
        ),
        'created_at': now,
        'updated_at': now,
    }
    if email:
        document['email'] = email
    if parent_admin_id is not None:
        document['parent_admin_id'] = parent_admin_id
    if existing is not None:
        collection.update_one({'_id': existing['_id']}, {'$set': document})
        return collection.find_one({'_id': existing['_id']})
    result = collection.insert_one(document)
    return collection.find_one({'_id': result.inserted_id})


def list_sub_admins():
    return list(get_web_database()[AUTH_COLLECTION].find(
        {'role': ROLE_SUB_ADMIN},
    ).sort('username_key', 1))


def update_sub_admin(
    user_id,
    *,
    email=_UNSET,
    password=_UNSET,
    disabled=_UNSET,
    pause_managed_subscriptions_when_disabled=_UNSET,
):
    user = find_user_by_id(user_id)
    if user is None or user.get('role') != ROLE_SUB_ADMIN:
        raise LookupError('Sub-admin not found.')
    updates = {'updated_at': datetime.now(timezone.utc)}
    if email is not _UNSET:
        email = validate_email(email)
        if email:
            existing = find_user_by_email(email)
            if existing is not None and existing['_id'] != user['_id']:
                raise ValueError('Email is already in use.')
            updates['email'] = email
        else:
            updates['email'] = None
    if password is not _UNSET and password not in (None, ''):
        updates['password'] = hash_password(_validate_password(password))
        updates['must_change_password'] = False
    if disabled is not _UNSET:
        updates['disabled'] = bool(disabled)
    if pause_managed_subscriptions_when_disabled is not _UNSET:
        updates['pause_managed_subscriptions_when_disabled'] = bool(
            pause_managed_subscriptions_when_disabled
        )
    get_web_database()[AUTH_COLLECTION].update_one(
        {'_id': user['_id']}, {'$set': updates},
    )
    return find_user_by_id(user['_id'])


def remove_sub_admin(user_id, top_admin_id):
    user = find_user_by_id(user_id)
    if user is None or user.get('role') != ROLE_SUB_ADMIN:
        raise LookupError('Sub-admin not found.')
    if top_admin_id is None:
        raise ValueError('Top-level administrator not found.')
    database = get_web_database()
    for collection_name in ('sub_account', 'report_jobs', 'newsletter_deliveries'):
        database[collection_name].update_many(
            {'managed_by_user_id': user['_id']},
            {'$set': {'managed_by_user_id': top_admin_id}},
        )
    database[AUTH_COLLECTION].delete_one({'_id': user['_id']})


def managed_deliveries_paused(user_id):
    if user_id is None:
        return False
    user = find_user_by_id(user_id)
    return bool(
        user
        and user.get('role') == ROLE_SUB_ADMIN
        and user.get('disabled')
        and user.get('pause_managed_subscriptions_when_disabled')
    )


def ensure_bootstrap_user(config):
    collection = get_web_database()[AUTH_COLLECTION]
    username = normalize_username(config.get('WEB_AUTH_BOOTSTRAP_USERNAME', ''))
    password = config.get('WEB_AUTH_BOOTSTRAP_PASSWORD', '')
    now = datetime.now(timezone.utc)
    created = False

    admin = _find_user_by_username(username) if username else None
    # A stale Account Hub row must never be promoted merely because its Hub
    # username happens to match the configured local bootstrap username.
    if admin is not None:
        source = admin.get('auth_source')
        if source not in (None, AUTH_SOURCE_LOCAL):
            print(
                f"WEB AUTH: bootstrap username {username!r} is already used by "
                'a non-local identity; refusing to elevate it.',
                flush=True,
            )
            return False
    if admin is None:
        if username and password:
            # Do not overwrite a non-local identity when bootstrapping.  An
            # operator must rename/remove that allowlist row explicitly before
            # reusing the reserved local username.
            conflict = _find_user_by_username(username)
            if conflict is None:
                upsert_user(
                    username,
                    password,
                    role=ROLE_ADMIN,
                    must_change_password=False,
                    auth_source=AUTH_SOURCE_LOCAL,
                )
                admin = collection.find_one({'username_key': username_key(username)})
                created = True
            else:
                print(
                    f"WEB AUTH: bootstrap username {username!r} is already used by "
                    'a non-local identity; refusing to elevate it.',
                    flush=True,
                )
        if admin is None:
            print(
                'WEB AUTH: no usable local bootstrap record exists; configure an '
                'unused bootstrap username and password or repair the database.',
                flush=True,
            )
            return False

    admin_id = admin['_id']
    collection.update_one(
        {'_id': admin_id},
        {
            '$set': {
                'auth_source': AUTH_SOURCE_LOCAL,
                'role': ROLE_ADMIN,
                'disabled': False,
                'must_change_password': False,
                'username_key': username_key(admin.get('username') or username),
                'updated_at': now,
            },
            '$unset': {
                'account_hub_uid': '',
                'account_hub_username': '',
                'last_account_hub_sync_at': '',
            },
        },
    )
    if not is_password_hash(admin.get('password')) and password:
        collection.update_one({'_id': admin_id}, {'$set': {
            'password': hash_password(password),
            'must_change_password': False,
            'updated_at': now,
        }})

    account_hub_enabled = bool(
        config.get('ACCOUNT_HUB_ENABLED')
        if isinstance(config, dict)
        else _account_hub_enabled()
    )
    for user in collection.find({}):
        if user['_id'] == admin_id:
            continue
        if account_hub_enabled:
            # Do not silently migrate existing local identities. Hub sign-in
            # creates its own local row after remote verification.
            continue
        updates = {}
        if user.get('auth_source') != AUTH_SOURCE_LOCAL:
            # Rollback keeps legacy hashes available for local recovery while
            # the enabled mode never accepts them for ordinary sign-in.
            updates['auth_source'] = AUTH_SOURCE_LOCAL
        if user.get('username') and user.get('username_key') != username_key(user['username']):
            updates['username_key'] = username_key(user['username'])
        if user['_id'] == admin_id:
            if user.get('role') != ROLE_ADMIN:
                updates['role'] = ROLE_ADMIN
            if 'must_change_password' not in user:
                updates['must_change_password'] = False
            if user.get('disabled'):
                updates['disabled'] = False
        elif user.get('role') == ROLE_SUB_ADMIN:
            if str(user.get('parent_admin_id')) != str(admin_id):
                updates['parent_admin_id'] = admin_id
            if 'disabled' not in user:
                updates['disabled'] = False
            if 'pause_managed_subscriptions_when_disabled' not in user:
                updates['pause_managed_subscriptions_when_disabled'] = False
            if not is_password_hash(user.get('password')):
                updates.update({
                    'password': hash_password(LEGACY_DEFAULT_PASSWORD),
                    'must_change_password': True,
                })
            elif 'must_change_password' not in user:
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
    account_hub_enabled = _account_hub_enabled()
    if account_hub_enabled:
        # Hub users are created after remote verification. A legacy
        # subscription must not create an auth row on its own.
        return
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
            document = {
                'username': username,
                'username_key': username_key(username),
                'email': emails[0],
                'role': ROLE_USER,
                'auth_source': AUTH_SOURCE_LOCAL,
                'must_change_password': True,
                'created_at': now,
                'updated_at': now,
            }
            document['password'] = hash_password(LEGACY_DEFAULT_PASSWORD)
            result = auth_collection.insert_one(document)
            user = auth_collection.find_one({'_id': result.inserted_id})
        if user.get('auth_source') == AUTH_SOURCE_LOCAL and is_admin_role(user):
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
        if user.get('auth_source') != AUTH_SOURCE_LOCAL:
            updates['auth_source'] = AUTH_SOURCE_LOCAL
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


def ensure_admin_data_ownership():
    """Backfill manager ownership for records created before sub-admins existed."""
    database = get_web_database()
    bootstrap_username = _configured_bootstrap_username()
    admin = None
    if bootstrap_username:
        admin = database[AUTH_COLLECTION].find_one({
            'username_key': username_key(bootstrap_username),
            'auth_source': AUTH_SOURCE_LOCAL,
            'role': ROLE_ADMIN,
        }, {'_id': 1})
    if admin is None and not _account_hub_enabled():
        # Legacy local-only deployments may not have a normalized username_key;
        # keep their existing admin ownership until the next bootstrap repair.
        admin = database[AUTH_COLLECTION].find_one({
            'role': ROLE_ADMIN,
            'auth_source': {'$in': [None, AUTH_SOURCE_LOCAL]},
        }, {'_id': 1})
    if admin is None:
        return False
    manager_id = admin['_id']
    for collection_name in ('sub_account', 'report_jobs', 'newsletter_deliveries'):
        database[collection_name].update_many(
            {'$or': [
                {'managed_by_user_id': {'$exists': False}},
                {'managed_by_user_id': None},
                {'managed_by_user_id': ''},
            ]},
            {'$set': {'managed_by_user_id': manager_id}},
        )
    return True


def ensure_account_hub_indexes():
    """Keep one local identity row per Account Hub UID."""
    get_web_database()[AUTH_COLLECTION].create_index(
        'account_hub_uid', unique=True, sparse=True,
    )
