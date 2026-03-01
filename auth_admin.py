from flask import Blueprint, request, jsonify, session, g
import json
import os
import re
from datetime import datetime

import bcrypt
from crypto import encrypt_token, decrypt_token

auth_admin_bp = Blueprint('auth_admin', __name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

from auth_store import load_auth as _load, save_auth as _save

def _require_admin():
    from auth import get_user_by_id, is_admin
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Non authentifié'}), 401
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'error': 'Utilisateur introuvable'}), 401
    if user.get('role') != 'superadmin' and not is_admin(user_id):
        return jsonify({'error': 'Accès refusé'}), 403
    return None


# === Organizations ===

@auth_admin_bp.route('/api/auth/organizations', methods=['GET'])
def api_get_orgs():
    err = _require_admin()
    if err:
        return err
    orgs = _load('organizations.json') or []
    return jsonify(orgs)

@auth_admin_bp.route('/api/auth/organizations', methods=['POST'])
def api_create_org():
    err = _require_admin()
    if err:
        return err
    body = request.json or {}
    oid = body.get('id', '').strip().upper()
    name = body.get('name', '').strip()
    desc = body.get('description', '').strip()

    if not oid or not re.match(r'^[A-Z0-9_-]+$', oid):
        return jsonify({'error': 'ID invalide'}), 400

    orgs = _load('organizations.json') or []
    if any(o['id'] == oid for o in orgs):
        return jsonify({'error': 'Cette organisation existe déjà'}), 400

    orgs.append({'id': oid, 'name': name or oid, 'description': desc, 'created': datetime.utcnow().strftime('%Y-%m-%d')})
    _save('organizations.json', orgs)
    return jsonify({'success': True})

@auth_admin_bp.route('/api/auth/organizations/<org_id>', methods=['PUT'])
def api_update_org(org_id):
    err = _require_admin()
    if err:
        return err
    orgs = _load('organizations.json') or []
    org = next((o for o in orgs if o['id'] == org_id), None)
    if not org:
        return jsonify({'error': 'Organisation non trouvée'}), 404

    body = request.json or {}
    if 'name' in body:
        org['name'] = body['name']
    if 'description' in body:
        org['description'] = body['description']
    _save('organizations.json', orgs)
    return jsonify({'success': True})

@auth_admin_bp.route('/api/auth/organizations/<org_id>', methods=['DELETE'])
def api_delete_org(org_id):
    err = _require_admin()
    if err:
        return err
    orgs = _load('organizations.json') or []
    if not any(o['id'] == org_id for o in orgs):
        return jsonify({'error': 'Organisation non trouvée'}), 404

    orgs = [o for o in orgs if o['id'] != org_id]
    _save('organizations.json', orgs)

    # Remove org_id from teams
    teams = _load('teams.json') or []
    teams = [t for t in teams if t.get('org_id') != org_id]
    _save('teams.json', teams)

    return jsonify({'success': True})


# === Teams ===

@auth_admin_bp.route('/api/auth/teams', methods=['GET'])
def api_get_teams():
    err = _require_admin()
    if err:
        return err
    teams = _load('teams.json') or []
    return jsonify(teams)

@auth_admin_bp.route('/api/auth/teams', methods=['POST'])
def api_create_team():
    err = _require_admin()
    if err:
        return err
    body = request.json or {}
    tid = body.get('id', '').strip().lower()
    name = body.get('name', '').strip()
    org_id = body.get('org_id', '').strip()
    desc = body.get('description', '').strip()

    if not tid or not re.match(r'^[a-z0-9_-]+$', tid):
        return jsonify({'error': 'ID invalide (minuscules, chiffres, tirets)'}), 400

    teams = _load('teams.json') or []
    if any(t['id'] == tid for t in teams):
        return jsonify({'error': 'Cette équipe existe déjà'}), 400

    teams.append({
        'id': tid,
        'name': name or tid,
        'org_id': org_id,
        'description': desc,
        'members': [],
        'resources': [],
        'created': datetime.utcnow().strftime('%Y-%m-%d')
    })
    _save('teams.json', teams)
    return jsonify({'success': True})

@auth_admin_bp.route('/api/auth/teams/<team_id>', methods=['PUT'])
def api_update_team(team_id):
    err = _require_admin()
    if err:
        return err
    teams = _load('teams.json') or []
    team = next((t for t in teams if t['id'] == team_id), None)
    if not team:
        return jsonify({'error': 'Équipe non trouvée'}), 404

    body = request.json or {}
    if 'name' in body:
        team['name'] = body['name']
    if 'org_id' in body:
        team['org_id'] = body['org_id']
    if 'description' in body:
        team['description'] = body['description']
    _save('teams.json', teams)
    return jsonify({'success': True})

@auth_admin_bp.route('/api/auth/teams/<team_id>', methods=['DELETE'])
def api_delete_team(team_id):
    err = _require_admin()
    if err:
        return err
    teams = _load('teams.json') or []
    if not any(t['id'] == team_id for t in teams):
        return jsonify({'error': 'Équipe non trouvée'}), 404

    teams = [t for t in teams if t['id'] != team_id]
    _save('teams.json', teams)
    return jsonify({'success': True})


# === Team Members ===

@auth_admin_bp.route('/api/auth/teams/<team_id>/members', methods=['POST'])
def api_add_member(team_id):
    err = _require_admin()
    if err:
        return err
    teams = _load('teams.json') or []
    team = next((t for t in teams if t['id'] == team_id), None)
    if not team:
        return jsonify({'error': 'Équipe non trouvée'}), 404

    body = request.json or {}
    user_id = body.get('user_id', '').strip()
    role = body.get('role', 'member')
    if role not in ('admin', 'member'):
        role = 'member'

    if not user_id:
        return jsonify({'error': 'user_id requis'}), 400

    members = team.setdefault('members', [])
    if any(m['user_id'] == user_id for m in members):
        return jsonify({'error': 'Membre déjà présent'}), 400

    members.append({'user_id': user_id, 'role': role})
    _save('teams.json', teams)
    return jsonify({'success': True})

@auth_admin_bp.route('/api/auth/teams/<team_id>/members/<user_id>', methods=['PUT'])
def api_update_member(team_id, user_id):
    err = _require_admin()
    if err:
        return err
    teams = _load('teams.json') or []
    team = next((t for t in teams if t['id'] == team_id), None)
    if not team:
        return jsonify({'error': 'Équipe non trouvée'}), 404

    member = next((m for m in team.get('members', []) if m['user_id'] == user_id), None)
    if not member:
        return jsonify({'error': 'Membre non trouvé'}), 404

    body = request.json or {}
    new_role = body.get('role', 'member')
    if new_role in ('admin', 'member'):
        member['role'] = new_role
    _save('teams.json', teams)
    return jsonify({'success': True})

@auth_admin_bp.route('/api/auth/teams/<team_id>/members/<user_id>', methods=['DELETE'])
def api_remove_member(team_id, user_id):
    err = _require_admin()
    if err:
        return err
    teams = _load('teams.json') or []
    team = next((t for t in teams if t['id'] == team_id), None)
    if not team:
        return jsonify({'error': 'Équipe non trouvée'}), 404

    team['members'] = [m for m in team.get('members', []) if m['user_id'] != user_id]
    _save('teams.json', teams)
    return jsonify({'success': True})


# === Team Resources ===

@auth_admin_bp.route('/api/auth/teams/<team_id>/resources', methods=['POST'])
def api_add_resource(team_id):
    err = _require_admin()
    if err:
        return err
    teams = _load('teams.json') or []
    team = next((t for t in teams if t['id'] == team_id), None)
    if not team:
        return jsonify({'error': 'Équipe non trouvée'}), 404

    body = request.json or {}
    module = body.get('module', '').strip()
    resource_id = body.get('resource_id', '').strip()

    if not module or not resource_id:
        return jsonify({'error': 'module et resource_id requis'}), 400

    resources = team.setdefault('resources', [])
    if any(r['module'] == module and r['resource_id'] == resource_id for r in resources):
        return jsonify({'error': 'Ressource déjà assignée'}), 400

    resources.append({'module': module, 'resource_id': resource_id})
    _save('teams.json', teams)
    return jsonify({'success': True})

@auth_admin_bp.route('/api/auth/teams/<team_id>/resources', methods=['DELETE'])
def api_remove_resource(team_id):
    err = _require_admin()
    if err:
        return err
    teams = _load('teams.json') or []
    team = next((t for t in teams if t['id'] == team_id), None)
    if not team:
        return jsonify({'error': 'Équipe non trouvée'}), 404

    body = request.json or {}
    module = body.get('module', '')
    resource_id = body.get('resource_id', '')

    team['resources'] = [r for r in team.get('resources', []) if not (r['module'] == module and r['resource_id'] == resource_id)]
    _save('teams.json', teams)
    return jsonify({'success': True})


# === Users ===

@auth_admin_bp.route('/api/auth/users', methods=['GET'])
def api_get_users():
    err = _require_admin()
    if err:
        return err
    users = _load('users.json') or []
    # Don't return password hashes
    safe = []
    for u in users:
        su = {k: v for k, v in u.items() if k != 'password_hash'}
        safe.append(su)
    return jsonify(safe)

@auth_admin_bp.route('/api/auth/users/<user_id>', methods=['DELETE'])
def api_delete_user(user_id):
    err = _require_admin()
    if err:
        return err

    if user_id == 'admin':
        return jsonify({'error': 'Impossible de supprimer le super admin'}), 400

    users = _load('users.json') or []
    if not any(u['id'] == user_id for u in users):
        return jsonify({'error': 'Utilisateur non trouvé'}), 404

    users = [u for u in users if u['id'] != user_id]
    _save('users.json', users)

    # Remove from all teams
    teams = _load('teams.json') or []
    for team in teams:
        team['members'] = [m for m in team.get('members', []) if m['user_id'] != user_id]
    _save('teams.json', teams)

    return jsonify({'success': True})


# === Auth Config (superadmin only) ===

def _migrate_ldap_servers(config: dict) -> list:
    """Retourne la liste des serveurs LDAP. Migre l'ancien format 'ldap' si besoin."""
    servers = config.get('ldap_servers', [])
    if not servers and config.get('ldap'):
        old = config['ldap']
        servers = [{
            'id': 'default',
            'name': 'AD Principal',
            'host': old.get('host', ''),
            'base_dn': old.get('base_dn', ''),
            'bind_dn_template': old.get('bind_dn_template', ''),
            'tls_verify': old.get('tls_verify', False),
        }]
    return [{'id': s['id'], 'name': s.get('name', s['id']),
             'host': s.get('host', ''), 'base_dn': s.get('base_dn', ''),
             'bind_dn_template': s.get('bind_dn_template', ''),
             'tls_verify': s.get('tls_verify', False)} for s in servers]

@auth_admin_bp.route('/api/auth/admin-config', methods=['GET'])
def api_get_auth_admin_config():
    from auth import get_user_by_id
    user_id = session.get('user_id')
    user = get_user_by_id(user_id) if user_id else None
    if not user or user.get('role') != 'superadmin':
        return jsonify({'error': 'Accès refusé'}), 403

    config = _load('config.json') or {}
    # Hide sensitive fields
    ssl_val = config.get('ssl_verify', True)
    smtp = config.get('smtp', {})
    safe = {
        'adfs': {
            'enabled': config.get('adfs', {}).get('enabled', False),
            'client_id': config.get('adfs', {}).get('client_id', ''),
            'authority': config.get('adfs', {}).get('authority', ''),
            'redirect_uri': config.get('adfs', {}).get('redirect_uri', ''),
            'scopes': config.get('adfs', {}).get('scopes', []),
            'has_secret': bool(config.get('adfs', {}).get('client_secret', '')),
            'jwks_uri': config.get('adfs', {}).get('jwks_uri', '')
        },
        'local_admin': {
            'username': config.get('local_admin', {}).get('username', 'admin'),
            'display_name': config.get('local_admin', {}).get('display_name', 'Super Admin')
        },
        'ssl_verify': ssl_val,
        'ldap_servers': _migrate_ldap_servers(config),
        'smtp': {
            'enabled': smtp.get('enabled', False),
            'host': smtp.get('host', ''),
            'port': smtp.get('port', 587),
            'use_tls': smtp.get('use_tls', True),
            'username': smtp.get('username', ''),
            'has_password': bool(smtp.get('password', '')),
            'from_address': smtp.get('from_address', ''),
            'from_name': smtp.get('from_name', 'Portal DevOps')
        }
    }
    return jsonify(safe)

@auth_admin_bp.route('/api/auth/admin-config', methods=['POST'])
def api_save_auth_admin_config():
    from auth import get_user_by_id
    user_id = session.get('user_id')
    user = get_user_by_id(user_id) if user_id else None
    if not user or user.get('role') != 'superadmin':
        return jsonify({'error': 'Accès refusé'}), 403

    body = request.json or {}
    config = _load('config.json') or {}

    # Update ADFS
    if 'adfs' in body:
        adfs = body['adfs']
        cfg_adfs = config.setdefault('adfs', {})
        if 'enabled' in adfs:
            cfg_adfs['enabled'] = bool(adfs['enabled'])
        if 'client_id' in adfs:
            cfg_adfs['client_id'] = adfs['client_id']
        if 'client_secret' in adfs and adfs['client_secret'] != '__UNCHANGED__':
            from flask import current_app
            cfg_adfs['client_secret'] = encrypt_token(adfs['client_secret'], current_app.secret_key)
        if 'authority' in adfs:
            cfg_adfs['authority'] = adfs['authority']
        if 'redirect_uri' in adfs:
            cfg_adfs['redirect_uri'] = adfs['redirect_uri']
        if 'scopes' in adfs:
            cfg_adfs['scopes'] = adfs['scopes']
        if 'jwks_uri' in adfs:
            jwks = adfs['jwks_uri'].strip()
            if jwks:
                cfg_adfs['jwks_uri'] = jwks
            else:
                cfg_adfs.pop('jwks_uri', None)

    # Update SSL verify
    if 'ssl_verify' in body:
        val = body['ssl_verify']
        # Accepte True, False, ou un chemin string vers un CA bundle
        if isinstance(val, bool):
            config['ssl_verify'] = val
        elif isinstance(val, str):
            stripped = val.strip()
            if stripped.lower() == 'true':
                config['ssl_verify'] = True
            elif stripped.lower() == 'false':
                config['ssl_verify'] = False
            elif stripped:
                config['ssl_verify'] = stripped  # chemin CA bundle
            else:
                config['ssl_verify'] = True

    # Update local admin
    if 'local_admin' in body:
        la = body['local_admin']
        cfg_la = config.setdefault('local_admin', {})
        if 'username' in la:
            cfg_la['username'] = la['username']
        if 'display_name' in la:
            cfg_la['display_name'] = la['display_name']
        if 'password' in la and la['password']:
            cfg_la['password_hash'] = bcrypt.hashpw(la['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Update LDAP servers (liste complète, remplace l'ancienne)
    if 'ldap_servers' in body:
        validated = []
        for s in body['ldap_servers']:
            sid = re.sub(r'[^a-z0-9_-]', '', str(s.get('id', '')).strip().lower())
            host = str(s.get('host', '')).strip()
            if not sid or not host:
                continue
            validated.append({
                'id': sid,
                'name': str(s.get('name', sid)).strip(),
                'host': host,
                'base_dn': str(s.get('base_dn', '')).strip(),
                'bind_dn_template': str(s.get('bind_dn_template', '')).strip(),
                'tls_verify': bool(s.get('tls_verify', False)),
            })
        config['ldap_servers'] = validated
        config.pop('ldap', None)  # Supprime l'ancienne clé unique si elle existe

    # Update SMTP
    if 'smtp' in body:
        smtp = body['smtp']
        cfg_smtp = config.setdefault('smtp', {})
        if 'enabled' in smtp:
            cfg_smtp['enabled'] = bool(smtp['enabled'])
        for key in ('host', 'username', 'from_address', 'from_name'):
            if key in smtp:
                cfg_smtp[key] = smtp[key].strip() if isinstance(smtp[key], str) else smtp[key]
        if 'port' in smtp:
            try:
                cfg_smtp['port'] = int(smtp['port'])
            except (ValueError, TypeError):
                pass
        if 'use_tls' in smtp:
            cfg_smtp['use_tls'] = bool(smtp['use_tls'])
        if 'password' in smtp and smtp['password'] != '__UNCHANGED__':
            cfg_smtp['password'] = smtp['password']  # stocké en clair (interne)

    _save('config.json', config)
    return jsonify({'success': True})


# === Available resources (for team resource assignment) ===

@auth_admin_bp.route('/api/auth/available-resources', methods=['GET'])
def api_available_resources():
    err = _require_admin()
    if err:
        return err

    datas_dir = os.path.join(BASE_DIR, 'datas')
    resources = []

    # SRE clusters
    clusters_path = os.path.join(datas_dir, 'clusters.json')
    if os.path.exists(clusters_path):
        with open(clusters_path, 'r', encoding='utf-8') as f:
            clusters = json.load(f)
        for c in clusters:
            resources.append({'module': 'sre', 'resource_id': c['id'], 'label': c.get('name', c['id'])})

    # CAD workspaces
    cad_path = os.path.join(datas_dir, 'cad_workspaces.json')
    if os.path.exists(cad_path):
        with open(cad_path, 'r', encoding='utf-8') as f:
            workspaces = json.load(f)
        for w in workspaces:
            resources.append({'module': 'cad', 'resource_id': w['id'], 'label': w.get('name', w['id'])})

    # PSSIT apps
    pssit_path = os.path.join(datas_dir, 'pssit_apps.json')
    if os.path.exists(pssit_path):
        with open(pssit_path, 'r', encoding='utf-8') as f:
            apps = json.load(f)
        for a in apps:
            resources.append({'module': 'pssit', 'resource_id': a['id'], 'label': a.get('name', a['id'])})

    # API Docs (Swagger) — ressource singleton, contrôle qui peut accéder à /api/docs/
    resources.append({'module': 'api_docs', 'resource_id': 'docs', 'label': 'API Documentation (Swagger)'})

    return jsonify(resources)
