from flask import Blueprint, request, session, redirect, jsonify, g, send_file, abort
import hashlib
import json
import logging
import os
import time
import base64
import urllib.parse
import secrets
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)
_audit = logging.getLogger('audit')

# Erreurs ADFS autorisées dans les redirections (whitelist anti-XSS)
_ADFS_SAFE_ERRORS = frozenset({
    'access_denied', 'invalid_request', 'unauthorized_client',
    'unsupported_response_type', 'invalid_scope', 'server_error',
    'temporarily_unavailable', 'too_many_requests',
})


def _hash_for_log(username: str) -> str:
    """Retourne un identifiant court non-réversible pour les logs d'audit."""
    return hashlib.sha256(username.encode()).hexdigest()[:8]

import bcrypt
import requests as http_requests
from cryptography.hazmat.primitives.asymmetric import padding as _asym_padding
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend

auth_bp = Blueprint('auth', __name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

from auth_store import load_auth as _load, save_auth as _save, load_secrets as _load_secrets, merge_config_secrets as _merge_secrets

# === Rate limiting (in-memory, reset au redémarrage) ===
_login_attempts = {}   # {username: {'count', 'locked_until', 'window_start'}}
_MAX_ATTEMPTS  = 5
_LOCKOUT_SEC   = 900   # 15 minutes
_WINDOW_SEC    = 300   # fenêtre de 5 minutes

# === Cache JWKS ===
_jwks_cache = {}       # {uri: (jwks_dict, fetched_at)}
_JWKS_TTL   = 600     # 10 minutes — assez court pour voir une rotation de clé ADFS

def get_auth_config() -> dict:
    """Charge la config en fusionnant config.json (non-sensible) et secrets.json.
    secrets.json prend la priorité en cas de clé commune (deep merge).
    Backward compat : si secrets.json n'existe pas, tout reste dans config.json.
    """
    config = _load('config.json') or {}
    secrets = _load_secrets()
    return _merge_secrets(config, secrets) if secrets else config

def get_users() -> list[dict]:
    return _load('users.json') or []

def save_users(users: list[dict]) -> None:
    _save('users.json', users)

def get_teams() -> list[dict]:
    return _load('teams.json') or []

def get_user_by_id(user_id: str) -> Optional[dict]:
    return next((u for u in get_users() if u['id'] == user_id), None)

def get_user_teams(user_id):
    teams = get_teams()
    return [t for t in teams if any(m['user_id'] == user_id for m in t.get('members', []))]

def get_user_resources(user_id: str) -> Optional[list[dict]]:
    user = get_user_by_id(user_id)
    if not user:
        return []
    if user.get('role') == 'superadmin':
        return None  # None = acces a tout
    resources = []
    for team in get_user_teams(user_id):
        for res in team.get('resources', []):
            if res not in resources:
                resources.append(res)
    return resources

def check_access(user_id: str, module: str, resource_id: str) -> bool:
    resources = get_user_resources(user_id)
    if resources is None:
        return True  # superadmin
    return any(r.get('module') == module and r.get('resource_id') == resource_id for r in resources)

def is_admin(user_id: str) -> bool:
    user = get_user_by_id(user_id)
    if not user:
        return False
    if user.get('role') == 'superadmin':
        return True
    teams = get_user_teams(user_id)
    return any(
        m.get('role') == 'admin'
        for t in teams
        for m in t.get('members', [])
        if m['user_id'] == user_id
    )


# === SSL verify ===

def get_ssl_verify() -> bool | str:
    """Retourne la valeur ssl_verify depuis datas/auth/config.json (True par défaut).
    Accepte True, False, ou un chemin absolu vers un CA bundle existant."""
    val = get_auth_config().get('ssl_verify', True)
    if isinstance(val, str) and not os.path.isfile(val):
        logger.warning('CA bundle introuvable : %s — SSL verify forcé à True', val)
        return True
    return val


# === JWT / JWKS ===

def _b64url_decode(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def _fetch_jwks(uri):
    now = time.time()
    cached = _jwks_cache.get(uri)
    if cached and now - cached[1] < _JWKS_TTL:
        return cached[0]
    resp = http_requests.get(uri, timeout=10, verify=get_ssl_verify())
    resp.raise_for_status()
    jwks = resp.json()
    _jwks_cache[uri] = (jwks, now)
    return jwks


def verify_id_token(id_token, adfs_config):
    """Vérifie la signature RS256 du JWT ADFS via JWKS et retourne les claims."""
    parts = id_token.split('.')
    if len(parts) != 3:
        raise ValueError('Format JWT invalide')

    header  = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    sig     = _b64url_decode(parts[2])

    if header.get('alg') != 'RS256':
        raise ValueError(f'Algorithme non supporté : {header.get("alg")}')

    # Détermine l'URI JWKS (override explicite ou découverte OIDC)
    jwks_uri = adfs_config.get('jwks_uri')
    if not jwks_uri:
        authority = adfs_config['authority'].rstrip('/')
        try:
            disc = http_requests.get(
                f'{authority}/.well-known/openid-configuration',
                timeout=10, verify=get_ssl_verify()
            ).json()
            jwks_uri = disc['jwks_uri']
        except Exception as e:
            logger.warning('Découverte JWKS via openid-configuration a échoué (%s), fallback sur /adfs/discovery/keys : %s', authority, e)
            jwks_uri = f'{authority}/adfs/discovery/keys'

    jwks = _fetch_jwks(jwks_uri)
    kid  = header.get('kid')
    keys = jwks.get('keys', [])
    key_data = next((k for k in keys if k.get('kid') == kid), None)
    if key_data is None and len(keys) == 1:
        key_data = keys[0]
    if key_data is None:
        raise ValueError(f'Clé JWKS introuvable (kid={kid})')

    n = int.from_bytes(_b64url_decode(key_data['n']), 'big')
    e = int.from_bytes(_b64url_decode(key_data['e']), 'big')
    pub_key = RSAPublicNumbers(e, n).public_key(default_backend())
    pub_key.verify(
        sig,
        f'{parts[0]}.{parts[1]}'.encode(),
        _asym_padding.PKCS1v15(),
        _hashes.SHA256()
    )

    now = time.time()
    if payload.get('exp', now + 1) < now:
        raise ValueError('Token expiré')

    client_id = adfs_config.get('client_id', '')
    if not client_id:
        raise ValueError('client_id ADFS non configuré')
    aud = payload.get('aud', '')
    if isinstance(aud, list):
        if client_id not in aud:
            raise ValueError('Audience invalide')
    elif aud != client_id:
        raise ValueError('Audience invalide')

    return payload


# === Rate limiting ===

def _rl_check(username):
    """Retourne (allowed: bool, retry_after_seconds: int)."""
    now = time.time()
    e = _login_attempts.get(username, {})
    if now < e.get('locked_until', 0):
        return False, int(e['locked_until'] - now)
    if now - e.get('window_start', now) > _WINDOW_SEC:
        _login_attempts.pop(username, None)
    return True, 0


def _rl_fail(username):
    now = time.time()
    e = _login_attempts.get(username, {})
    if not e or now - e.get('window_start', now) > _WINDOW_SEC:
        e = {'count': 0, 'locked_until': 0, 'window_start': now}
    e['count'] += 1
    if e['count'] >= _MAX_ATTEMPTS:
        e['locked_until'] = now + _LOCKOUT_SEC
    _login_attempts[username] = e


def _rl_success(username):
    _login_attempts.pop(username, None)


# === Public routes ===

PUBLIC_PREFIXES = ('/login', '/auth/', '/img/', '/api/auth/config')

_CSRF_METHODS = {'POST', 'PUT', 'DELETE'}

@auth_bp.before_app_request
def require_auth():
    path = request.path

    # Static & public routes
    if any(path.startswith(p) for p in PUBLIC_PREFIXES):
        return None

    user_id = session.get('user_id')
    if not user_id:
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Non authentifié'}), 401
        session['next_url'] = request.url
        return redirect('/login')

    user = get_user_by_id(user_id)
    if not user:
        session.clear()
        return redirect('/login')

    g.current_user = user

    # Génère un token CSRF par session si absent
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)

    # Validation CSRF pour les méthodes mutantes
    if request.method in _CSRF_METHODS:
        token_header = request.headers.get('X-CSRF-Token', '')
        if not token_header or token_header != session.get('csrf_token', ''):
            if path.startswith('/api/'):
                return jsonify({'error': 'CSRF token invalide'}), 403
            return redirect('/login')

    # Protection de la documentation API (Swagger) — module api_docs requis
    if path.startswith('/api/docs') or path.startswith('/flasgger_static'):
        if not check_access(user_id, 'api_docs', 'docs'):
            if path.startswith('/api/'):
                return jsonify({'error': 'Accès refusé', 'status': 403}), 403
            abort(403)
        return None

    # Resource-level access for module routes
    import re as _re
    _checks = [
        (_re.match(r'^(?:/api)?/cluster/([A-Za-z0-9_-]+)', path), 'sre'),
        (_re.match(r'^(?:/api)?/cad/workspace/([A-Za-z0-9_-]+)', path), 'cad'),
        (_re.match(r'^(?:/api)?/pssit/app/([A-Za-z0-9_-]+)', path), 'pssit'),
    ]
    for _m, _module in _checks:
        if _m:
            if not check_access(user_id, _module, _m.group(1)):
                abort(403)
            break
    else:
        if path in ('/auth-admin',):
            if user.get('role') != 'superadmin' and not is_admin(user_id):
                abort(403)

    return None


# === Login page ===

@auth_bp.route('/login')
def login_page():
    return send_file(os.path.join(BASE_DIR, 'pages', 'login.html'))


# === Local admin login ===

@auth_bp.route('/auth/local/login', methods=['POST'])
def local_login():
    body = request.json or {}
    username = body.get('username', '').strip()
    password = body.get('password', '')

    allowed, retry_after = _rl_check(username)
    if not allowed:
        minutes = max(1, retry_after // 60)
        _audit.warning('login_blocked user=%s ip=%s retry_after=%d', _hash_for_log(username), request.remote_addr, retry_after)
        return jsonify({'error': f'Compte verrouillé. Réessayez dans {minutes} minute(s).'}), 429

    config = get_auth_config()
    local = config.get('local_admin', {})

    if username != local.get('username', ''):
        _rl_fail(username)
        _audit.warning('login_failed user=%s ip=%s reason=unknown_user', _hash_for_log(username), request.remote_addr)
        return jsonify({'error': 'Identifiants invalides'}), 401

    stored_hash = local.get('password_hash', '')
    try:
        pwd_ok = bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
    except (ValueError, TypeError):
        pwd_ok = False
    if not pwd_ok:
        _rl_fail(username)
        _audit.warning('login_failed user=%s ip=%s reason=wrong_password', _hash_for_log(username), request.remote_addr)
        return jsonify({'error': 'Identifiants invalides'}), 401

    _rl_success(username)
    _audit.info('login_success user=%s ip=%s', _hash_for_log(username), request.remote_addr)

    # Ensure admin user exists
    users = get_users()
    admin_user = next((u for u in users if u['id'] == 'admin' and u['type'] == 'local'), None)
    if not admin_user:
        admin_user = {
            'id': 'admin',
            'type': 'local',
            'display_name': local.get('display_name', 'Super Admin'),
            'role': 'superadmin',
            'created': datetime.utcnow().strftime('%Y-%m-%d')
        }
        users.append(admin_user)
        save_users(users)

    session['user_id'] = 'admin'
    next_url = session.pop('next_url', '/')
    return jsonify({'success': True, 'redirect': next_url})


# === ADFS OIDC ===

@auth_bp.route('/auth/adfs/login')
def adfs_login():
    config = get_auth_config()
    adfs = config.get('adfs', {})
    if not adfs.get('enabled'):
        return redirect('/login')

    state = secrets.token_hex(16)
    session['oauth_state'] = state

    authority = adfs['authority'].rstrip('/')
    params = {
        'client_id': adfs['client_id'],
        'response_type': 'code',
        'redirect_uri': adfs['redirect_uri'],
        'scope': ' '.join(adfs.get('scopes', ['openid', 'profile', 'email'])),
        'state': state,
        'response_mode': 'query'
    }
    auth_url = f"{authority}/oauth2/authorize?{urllib.parse.urlencode(params)}"
    return redirect(auth_url)

@auth_bp.route('/auth/adfs/callback')
def adfs_callback():
    # Rate limiting par IP pour ralentir les abus du callback OAuth
    remote_ip = request.remote_addr or 'unknown'
    allowed, _ = _rl_check(remote_ip)
    if not allowed:
        _audit.warning('adfs_callback_blocked ip=%s', remote_ip)
        return redirect('/login?error=too_many_requests')

    config = get_auth_config()
    adfs = config.get('adfs', {})
    if not adfs.get('enabled'):
        return redirect('/login')

    error = request.args.get('error')
    if error:
        # Whitelist anti-XSS : on n'injecte jamais error_description dans l'URL
        safe_error = error if error in _ADFS_SAFE_ERRORS else 'adfs_error'
        _rl_fail(remote_ip)
        return redirect(f'/login?error={urllib.parse.quote(safe_error)}')

    code = request.args.get('code', '')
    state = request.args.get('state', '')

    if state != session.pop('oauth_state', ''):
        _rl_fail(remote_ip)
        return redirect('/login?error=state_mismatch')

    # Exchange code for token
    authority = adfs['authority'].rstrip('/')
    token_url = f"{authority}/oauth2/token"

    try:
        from flask import current_app
        from crypto import decrypt_token
        raw_secret = adfs.get('client_secret', '')
        client_secret = decrypt_token(raw_secret, current_app.secret_key)
        resp = http_requests.post(token_url, data={
            'grant_type': 'authorization_code',
            'client_id': adfs['client_id'],
            'client_secret': client_secret,
            'code': code,
            'redirect_uri': adfs['redirect_uri']
        }, timeout=15, verify=get_ssl_verify())

        if resp.status_code != 200:
            return redirect('/login?error=token_exchange_failed')

        tokens = resp.json()
        id_token = tokens.get('id_token', '')

        # Vérifie la signature RS256 via JWKS et valide les claims
        try:
            claims = verify_id_token(id_token, adfs)
        except Exception as jwt_err:
            logger.warning('JWT validation échouée : %s', jwt_err)
            _audit.warning('adfs_jwt_failed ip=%s reason=%s', remote_ip, type(jwt_err).__name__)
            _rl_fail(remote_ip)
            return redirect('/login?error=adfs_error')

    except Exception:
        _audit.warning('adfs_callback_error ip=%s', remote_ip)
        _rl_fail(remote_ip)
        return redirect('/login?error=adfs_error')

    # Extract user info
    sub = claims.get('sub', '')
    username = claims.get('preferred_username', claims.get('upn', claims.get('unique_name', sub)))
    email = claims.get('email', '')
    display_name = claims.get('name', username)
    groups = claims.get('groups', claims.get('group', []))
    if isinstance(groups, str):
        groups = [groups]

    user_id = 'adfs_' + username.split('@')[0].lower()

    # Upsert user
    users = get_users()
    user = next((u for u in users if u['id'] == user_id), None)
    if user:
        user['adfs_sub'] = sub
        user['username'] = username
        user['email'] = email
        user['display_name'] = display_name
        user['adfs_groups'] = groups
        user['last_login'] = datetime.utcnow().isoformat() + 'Z'
    else:
        user = {
            'id': user_id,
            'type': 'adfs',
            'adfs_sub': sub,
            'username': username,
            'email': email,
            'display_name': display_name,
            'adfs_groups': groups,
            'role': 'user',
            'created': datetime.utcnow().strftime('%Y-%m-%d'),
            'last_login': datetime.utcnow().isoformat() + 'Z'
        }
        users.append(user)
    save_users(users)

    _rl_success(remote_ip)
    session['user_id'] = user_id
    next_url = session.pop('next_url', '/')
    if not next_url.startswith('/'):
        next_url = '/'
    return redirect(next_url)


# === Logout ===

@auth_bp.route('/auth/logout')
def logout():
    session.clear()
    return redirect('/login')


# === Current user API ===

@auth_bp.route('/api/auth/me')
def api_me():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Non authentifié'}), 401

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'error': 'Utilisateur introuvable'}), 401

    teams = get_user_teams(user_id)
    resources = get_user_resources(user_id)

    return jsonify({
        'id': user['id'],
        'display_name': user.get('display_name', user['id']),
        'role': user.get('role', 'user'),
        'type': user.get('type', 'local'),
        'is_admin': is_admin(user_id),
        'teams': [{'id': t['id'], 'name': t['name'], 'role': next((m['role'] for m in t.get('members', []) if m['user_id'] == user_id), 'member')} for t in teams],
        'resources': resources,
        'modules': list(set(r['module'] for r in resources)) if resources is not None else None,
        'csrf_token': session.get('csrf_token', '')
    })


# === Auth config API (for login page) ===

@auth_bp.route('/api/auth/config')
def api_auth_config():
    config = get_auth_config()
    return jsonify({
        'adfs_enabled': config.get('adfs', {}).get('enabled', False)
    })
