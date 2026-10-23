"""
ByteENDE · authentication & API-key management
- Owner login: username + PBKDF2-hashed password, stored in data/owner.json
- API keys: random 32-byte token, only its SHA-256 hash is ever stored.
  The raw token is shown once at creation time, exactly like a real platform key.
- Per-key scopes (which tool groups it may call) and a per-key requests/minute limit.
- A simple in-memory sliding-window rate limiter (fine for a single-process deployment;
  swap for Redis if you run more than one worker).
"""
import hashlib
import hmac
import json
import os
import secrets
import threading
import time

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
OWNER_FILE = os.path.join(DATA_DIR, 'owner.json')
KEYS_FILE = os.path.join(DATA_DIR, 'keys.json')
SECRET_FILE = os.path.join(DATA_DIR, 'session.secret')

ALL_SCOPES = ['codec', 'hash', 'jwt', 'aes', 'qr']

# Login lockout: after MAX_FAILED_ATTEMPTS wrong passwords from the same
# username within LOCKOUT_WINDOW seconds, further attempts are rejected
# for LOCKOUT_SECONDS, regardless of whether the password is right - this
# defeats both online brute-force and credential-stuffing against the
# single owner account.
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW = 300     # seconds over which failures are counted
LOCKOUT_SECONDS = 300    # how long a lockout lasts once triggered

_lock = threading.Lock()
_rate_state = {}      # key_id -> list[timestamps]            (API rate limiting)
_login_state = {}     # username(lower) -> list[failure timestamps]
_lockout_until = {}   # username(lower) -> unix timestamp


def _ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def get_session_secret() -> str:
    _ensure_data_dir()
    if not os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, 'w') as f:
            f.write(secrets.token_hex(32))
    with open(SECRET_FILE) as f:
        return f.read().strip()


def _pbkdf2(password: str, salt: bytes, iters: int = 200_000) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters, dklen=32)


def _load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path) as f:
        return json.load(f)


def _save_json(path, data):
    _ensure_data_dir()
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


# ---------- owner account ----------

def owner_exists() -> bool:
    return os.path.exists(OWNER_FILE)


def set_owner_password(username: str, password: str):
    salt = secrets.token_hex(16)
    pwhash = _pbkdf2(password, bytes.fromhex(salt)).hex()
    _save_json(OWNER_FILE, {'username': username, 'salt': salt, 'hash': pwhash})


def is_locked_out(username: str):
    """Return seconds remaining in a lockout for this username, or 0 if none."""
    key = (username or '').lower()
    with _lock:
        until = _lockout_until.get(key, 0)
        remaining = until - time.time()
        return max(0, remaining)


def _record_login_failure(username: str):
    key = (username or '').lower()
    now = time.time()
    with _lock:
        hist = _login_state.setdefault(key, [])
        hist[:] = [t for t in hist if now - t < LOCKOUT_WINDOW]
        hist.append(now)
        if len(hist) >= MAX_FAILED_ATTEMPTS:
            _lockout_until[key] = now + LOCKOUT_SECONDS
            hist.clear()


def _clear_login_failures(username: str):
    key = (username or '').lower()
    with _lock:
        _login_state.pop(key, None)
        _lockout_until.pop(key, None)


def verify_owner(username: str, password: str) -> bool:
    """Constant-shape check: always runs a PBKDF2 derivation (even for an
    unknown username, against a fixed dummy salt) so a wrong-username
    response can't be distinguished from a wrong-password one by timing,
    and tracks failed attempts for lockout."""
    if is_locked_out(username):
        return False
    data = _load_json(OWNER_FILE, None)
    if data and data['username'] == username:
        salt = bytes.fromhex(data['salt'])
        expected = data['hash']
    else:
        # Dummy salt/hash so the PBKDF2 cost is paid either way.
        salt = hashlib.sha256(b'byteende-dummy-salt').digest()[:16]
        expected = hashlib.sha256(b'byteende-dummy-hash').hexdigest()
    candidate = _pbkdf2(password, salt).hex()
    ok = bool(data) and data['username'] == username and hmac.compare_digest(candidate, expected)
    if ok:
        _clear_login_failures(username)
    else:
        _record_login_failure(username)
    return ok


def change_owner_password(current: str, new: str) -> bool:
    data = _load_json(OWNER_FILE, None)
    if not data or not verify_owner(data['username'], current):
        return False
    set_owner_password(data['username'], new)
    return True


def get_owner_username() -> str:
    data = _load_json(OWNER_FILE, None)
    return data['username'] if data else ''


def change_owner_username(new_username: str, current_password: str):
    """Rename the owner account. Requires the current password so a hijacked
    session alone can't silently rotate the login name. Returns the new
    username on success, or None if the password was wrong / username is
    invalid / already taken by itself trivially (single-account system)."""
    new_username = (new_username or '').strip()
    if not (3 <= len(new_username) <= 24):
        return None
    data = _load_json(OWNER_FILE, None)
    if not data or not verify_owner(data['username'], current_password):
        return None
    data['username'] = new_username
    _save_json(OWNER_FILE, data)
    _clear_login_failures(new_username)
    return new_username


# ---------- API keys ----------

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def list_keys() -> list:
    return _load_json(KEYS_FILE, [])


def create_key(name: str, scopes: list, rate_per_min: int = 30) -> dict:
    scopes = [s for s in scopes if s in ALL_SCOPES] or list(ALL_SCOPES)
    rate_per_min = max(1, min(1000, int(rate_per_min)))
    token = 'bende_' + secrets.token_urlsafe(32)
    keys = list_keys()
    entry = {
        'id': secrets.token_hex(6),
        'name': name[:40] or 'Unnamed key',
        'prefix': token[:12],
        'hash': _hash_token(token),
        'scopes': scopes,
        'rate': rate_per_min,
        'enabled': True,
        'created': time.time(),
        'last_used': None,
    }
    keys.append(entry)
    _save_json(KEYS_FILE, keys)
    return {'entry': entry, 'token': token}


def delete_key(key_id: str) -> bool:
    keys = list_keys()
    n = len(keys)
    keys = [k for k in keys if k['id'] != key_id]
    _save_json(KEYS_FILE, keys)
    return len(keys) != n


def set_key_enabled(key_id: str, enabled: bool) -> bool:
    keys = list_keys()
    for k in keys:
        if k['id'] == key_id:
            k['enabled'] = enabled
            _save_json(KEYS_FILE, keys)
            return True
    return False


def authenticate(token: str):
    """Return the key entry for a valid, enabled token, or None."""
    if not token:
        return None
    th = _hash_token(token)
    keys = list_keys()
    for k in keys:
        if hmac.compare_digest(k['hash'], th) and k['enabled']:
            k['last_used'] = time.time()
            _save_json(KEYS_FILE, keys)
            return k
    return None


def check_scope(key_entry: dict, scope: str) -> bool:
    return scope in key_entry.get('scopes', [])


def check_rate_limit(key_entry: dict) -> bool:
    """Sliding 60s window. Returns True if the request is allowed."""
    kid = key_entry['id']
    limit = key_entry.get('rate', 30)
    now = time.time()
    with _lock:
        hist = _rate_state.setdefault(kid, [])
        hist[:] = [t for t in hist if now - t < 60]
        if len(hist) >= limit:
            return False
        hist.append(now)
        return True


# ---------- CSRF protection for session-based (cookie-authenticated) forms ----------
# The REST API under /api/v1/* is Bearer-token authenticated and stateless, so it is
# not vulnerable to CSRF and does not use these. Every session-authenticated POST
# form in the web panel does.

def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_valid(session_token: str, submitted_token: str) -> bool:
    if not session_token or not submitted_token:
        return False
    return hmac.compare_digest(session_token, submitted_token)
