from flask import Blueprint, request, session, redirect, jsonify, g, send_file, abort
import json
import os
import urllib.parse
import secrets
from datetime import datetime

import bcrypt
import requests as http_requests

auth_bp = Blueprint('auth', __name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_DIR = os.path.join(BASE_DIR, 'datas', 'auth')

def _load(name):
    path = os.path.join(AUTH_DIR, name)
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None

def _save(name, data):
    os.makedirs(AUTH_DIR, exist_ok=True)
    with open(os.path.join(AUTH_DIR, name), 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def get_auth_config():
    return _load('config.json') or {}

def get_users():
    return _load('users.json') or []

def save_users(users):
    _save('users.json', users)

def get_teams():
    return _load('teams.json') or []

def get_user_by_id(user_id):
    return next((u for u in get_users() if u['id'] == user_id), None)

def get_user_teams(user_id):
    teams = get_teams()
    return [t for t in teams if any(m['user_id'] == user_id for m in t.get('members', []))]

def get_user_resources(user_id):
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

def check_access(user_id, module, resource_id):
    resources = get_user_resources(user_id)
    if resources is None:
        return True  # superadmin
    return any(r.get('module') == module and r.get('resource_id') == resource_id for r in resources)

def is_admin(user_id):
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


# === Public routes ===

PUBLIC_PREFIXES = ('/login', '/auth/', '/img/', '/api/auth/config')

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

    # Resource-level access for module routes
    if path.startswith('/cluster/') or path.startswith('/api/cluster/'):
        parts = path.split('/')
        cluster_id = parts[2] if len(parts) > 2 else None
        if cluster_id and not check_access(user_id, 'sre', cluster_id):
            abort(403)

    elif path.startswith('/cad/workspace/') or path.startswith('/api/cad/workspace/'):
        parts = path.split('/')
        ws_id = parts[3] if len(parts) > 3 else None
        if ws_id and not check_access(user_id, 'cad', ws_id):
            abort(403)

    elif path.startswith('/pssit/app/') or path.startswith('/api/pssit/app/'):
        parts = path.split('/')
        app_id = parts[3] if len(parts) > 3 else None
        if app_id and not check_access(user_id, 'pssit', app_id):
            abort(403)

    elif path in ('/auth-admin',):
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

    config = get_auth_config()
    local = config.get('local_admin', {})

    if username != local.get('username', ''):
        return jsonify({'error': 'Identifiants invalides'}), 401

    stored_hash = local.get('password_hash', '')
    if not bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
        return jsonify({'error': 'Identifiants invalides'}), 401

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
    config = get_auth_config()
    adfs = config.get('adfs', {})
    if not adfs.get('enabled'):
        return redirect('/login')

    error = request.args.get('error')
    if error:
        return redirect('/login?error=' + urllib.parse.quote(request.args.get('error_description', error)))

    code = request.args.get('code', '')
    state = request.args.get('state', '')

    if state != session.pop('oauth_state', ''):
        return redirect('/login?error=state_mismatch')

    # Exchange code for token
    authority = adfs['authority'].rstrip('/')
    token_url = f"{authority}/oauth2/token"

    try:
        resp = http_requests.post(token_url, data={
            'grant_type': 'authorization_code',
            'client_id': adfs['client_id'],
            'client_secret': adfs.get('client_secret', ''),
            'code': code,
            'redirect_uri': adfs['redirect_uri']
        }, timeout=15, verify=False)

        if resp.status_code != 200:
            return redirect('/login?error=token_exchange_failed')

        tokens = resp.json()
        id_token = tokens.get('id_token', '')

        # Decode ID token (no signature verification for now — ADFS is trusted)
        import base64
        parts = id_token.split('.')
        if len(parts) >= 2:
            payload = parts[1]
            payload += '=' * (4 - len(payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
        else:
            return redirect('/login?error=invalid_token')

    except Exception:
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

    session['user_id'] = user_id
    next_url = session.pop('next_url', '/')
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
        'modules': list(set(r['module'] for r in resources)) if resources is not None else None
    })


# === Auth config API (for login page) ===

@auth_bp.route('/api/auth/config')
def api_auth_config():
    config = get_auth_config()
    return jsonify({
        'adfs_enabled': config.get('adfs', {}).get('enabled', False)
    })
