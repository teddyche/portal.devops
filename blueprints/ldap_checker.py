"""
Blueprint LDAP Checker — recherches Active Directory via ldapsearch.

Les credentials LDAP de l'utilisateur portail sont stockés en session Flask
(cookie signé) le temps de la navigation ; ils sont effacés via /api/ldap/logout
ou à la déconnexion du portail.

Config LDAP (dans datas/auth/config.json, section "ldap") :
  host              : ldaps://ZOE.GCA
  base_dn           : DC=zoe,DC=gca
  bind_dn_template  : (optionnel) si absent, bind UPN auto = username@zoe.gca
                      si présent, exemples valides :
                        "{username}@zoe.gca"          ← UPN (recommandé AD)
                        "ZOE\\{username}"              ← NetBIOS
                        "CN={username},OU=Users,DC=zoe,DC=gca" ← DN complet
  tls_verify        : false
"""
import base64
import logging
import os
import subprocess
from typing import Any

from flask import Blueprint, jsonify, request, session

from auth import get_auth_config
from blueprints import api_error

ldap_bp = Blueprint('ldap', __name__)
logger = logging.getLogger(__name__)
_audit = logging.getLogger('audit')

# ── Config multi-serveurs ─────────────────────────────────────────────────────

def _get_servers() -> list[dict]:
    """Retourne la liste des serveurs LDAP configurés (avec migration ancien format)."""
    config = get_auth_config()
    servers = config.get('ldap_servers', [])
    if not servers and config.get('ldap'):
        old = config['ldap']
        servers = [{'id': 'default', 'name': 'AD Principal', **old}]
    return servers

def _cfg_for(server_id: str) -> dict:
    """Retourne la config d'un serveur précis (ou le premier disponible)."""
    servers = _get_servers()
    s = next((s for s in servers if s['id'] == server_id), None)
    return s if s is not None else (servers[0] if servers else {})

def _host(c: dict) -> str:
    return c.get('host', 'ldaps://domain.com')

def _base_dn(c: dict) -> str:
    return c.get('base_dn', 'DC=domain,DC=com')

def _derive_upn_suffix(base_dn: str) -> str:
    """Extrait le domaine UPN depuis base_dn. 'DC=zoe,DC=gca' → 'zoe.gca'."""
    parts = [p.strip()[3:] for p in base_dn.split(',') if p.strip().upper().startswith('DC=')]
    return '.'.join(parts)

def _bind_dn(c: dict, username: str) -> str:
    tpl = c.get('bind_dn_template', '')
    if tpl:
        return tpl.replace('{username}', username)
    # Fallback automatique : UPN à partir du base_dn (format le plus compatible AD)
    domain = _derive_upn_suffix(_base_dn(c))
    return f'{username}@{domain}'

def _env(c: dict) -> dict:
    env = os.environ.copy()
    if not c.get('tls_verify', False):
        env['LDAPTLS_REQCERT'] = 'never'
    return env

def _base_cmd(c: dict, username: str, password: str) -> list[str]:
    return [
        'ldapsearch', '-LLL', '-o', 'ldif-wrap=no',
        '-H', _host(c),
        '-D', _bind_dn(c, username),
        '-w', password,
    ]

def _uid() -> str:
    return session.get('user_id', 'anonymous')

# ── LDIF parser ───────────────────────────────────────────────────────────────

def _decode_b64(s: str) -> str:
    try:
        return base64.b64decode(s).decode('utf-8', errors='replace')
    except Exception:
        return s

def parse_ldif(text: str) -> list[dict]:
    """Parse un output LDIF en liste de dicts (multi-valeurs → liste)."""
    entries: list[dict] = []
    cur: dict = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            if cur:
                entries.append(cur)
                cur = {}
            continue
        # dn base64
        if line.startswith('dn:: '):
            cur['dn'] = _decode_b64(line[5:])
        elif line.startswith('dn: '):
            cur['dn'] = line[4:]
        # attribut base64
        elif ':: ' in line:
            k, _, v = line.partition(':: ')
            val = _decode_b64(v)
            cur.setdefault(k, []) if isinstance(cur.get(k), list) else None
            if k in cur:
                cur[k] = ([cur[k]] if not isinstance(cur[k], list) else cur[k]) + [val]
            else:
                cur[k] = val
        # attribut simple
        elif ': ' in line:
            k, _, val = line.partition(': ')
            if k in cur:
                cur[k] = ([cur[k]] if not isinstance(cur[k], list) else cur[k]) + [val]
            else:
                cur[k] = val
    if cur:
        entries.append(cur)
    return entries

# ── Exécution ldapsearch ──────────────────────────────────────────────────────

def _run(cmd: list[str], env: dict, timeout: int = 30) -> tuple[bool, str]:
    """Lance ldapsearch. Retourne (succès, stdout|erreur)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout)
        # code 4 = size limit exceeded → résultat partiel, on accepte
        if r.returncode not in (0, 4):
            return False, (r.stderr or f'Code retour {r.returncode}').strip()
        return True, r.stdout
    except subprocess.TimeoutExpired:
        return False, 'Délai dépassé (timeout)'
    except FileNotFoundError:
        return False, 'ldapsearch introuvable sur ce serveur (paquet openldap-clients requis)'
    except Exception as exc:
        logger.exception('Erreur ldapsearch inattendue')
        return False, str(exc)

# ── Auth LDAP ─────────────────────────────────────────────────────────────────

def _require_ldap() -> Any:
    if 'ldap_user' not in session or 'ldap_pass' not in session:
        return api_error('Authentification LDAP requise', 401)
    return None

@ldap_bp.route('/api/ldap/servers', methods=['GET'])
def get_ldap_servers():
    """Liste des serveurs LDAP disponibles (pour le sélecteur de connexion)."""
    servers = _get_servers()
    return jsonify([{'id': s['id'], 'name': s.get('name', s['id'])} for s in servers])

@ldap_bp.route('/api/ldap/auth', methods=['POST'])
def ldap_auth():
    """Teste les credentials AD et les stocke en session Flask."""
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get('username') or '').strip()
    password = body.get('password') or ''
    server_id = (body.get('server_id') or '').strip()
    if not username or not password:
        return api_error('username et password requis')

    # Résolution du serveur (fallback sur le premier si id inconnu)
    if not server_id:
        servers = _get_servers()
        server_id = servers[0]['id'] if servers else 'default'
    c = _cfg_for(server_id)

    cmd = _base_cmd(c, username, password) + [
        '-b', _base_dn(c), '-s', 'base', '(objectClass=*)', 'dn'
    ]
    ok, err_msg = _run(cmd, _env(c), timeout=10)
    if not ok:
        _audit.warning('ldap_auth_failed portal_user=%s ldap_user=%s server=%s err=%s', _uid(), username, server_id, err_msg)
        logger.warning('LDAP auth failed for %s on %s — bind_dn=%s — err: %s', username, server_id, _bind_dn(c, username), err_msg)
        return api_error(f'Authentification AD échouée : {err_msg}', 401)

    session['ldap_user'] = username
    session['ldap_pass'] = password
    session['ldap_server_id'] = server_id
    _audit.info('ldap_auth_ok portal_user=%s ldap_user=%s server=%s', _uid(), username, server_id)
    return jsonify({'success': True, 'username': username, 'server_id': server_id, 'server_name': c.get('name', server_id)})

@ldap_bp.route('/api/ldap/check-auth', methods=['GET'])
def ldap_check_auth():
    if 'ldap_user' in session:
        server_id = session.get('ldap_server_id', '')
        c = _cfg_for(server_id)
        return jsonify({'authenticated': True, 'username': session['ldap_user'],
                        'server_id': server_id, 'server_name': c.get('name', server_id)})
    return jsonify({'authenticated': False})

@ldap_bp.route('/api/ldap/logout', methods=['POST'])
def ldap_logout():
    session.pop('ldap_user', None)
    session.pop('ldap_pass', None)
    session.pop('ldap_server_id', None)
    return jsonify({'success': True})

# ── Helpers communs ───────────────────────────────────────────────────────────

def _user_entry(e: dict) -> dict:
    uac = 0
    try:
        uac = int(e.get('userAccountControl', 0) or 0)
    except (ValueError, TypeError):
        pass
    return {
        'dn':         e.get('dn', ''),
        'cn':         e.get('cn', ''),
        'username':   e.get('sAMAccountName', ''),
        'email':      e.get('mail', ''),
        'department': e.get('department', ''),
        'title':      e.get('title', ''),
        'phone':      e.get('telephoneNumber', ''),
        'mobile':     e.get('mobile', ''),
        'created':    e.get('whenCreated', ''),
        'disabled':   bool(uac & 2),
    }

# ── Recherches ────────────────────────────────────────────────────────────────

@ldap_bp.route('/api/ldap/search/groups', methods=['POST'])
def search_groups():
    """Groupes AD par pattern CN (wildcards * supportés)."""
    if (err := _require_ldap()) is not None:
        return err
    body = request.get_json(force=True, silent=True) or {}
    pattern = (body.get('pattern') or '').strip()
    if not pattern:
        return api_error('pattern requis')

    c = _cfg_for(session.get('ldap_server_id', ''))
    cmd = _base_cmd(c, session['ldap_user'], session['ldap_pass']) + [
        '-b', _base_dn(c),
        f'(&(objectClass=group)(CN={pattern}))',
        'cn', 'description', 'managedBy', 'member',
    ]
    ok, out = _run(cmd, _env(c))
    if not ok:
        return api_error(out, 500)

    results = []
    for e in parse_ldif(out):
        m = e.get('member', [])
        cnt = len(m) if isinstance(m, list) else (1 if m else 0)
        mgr_raw = e.get('managedBy', '')
        mgr = mgr_raw.split(',')[0].replace('CN=', '') if mgr_raw else ''
        results.append({
            'dn':          e.get('dn', ''),
            'cn':          e.get('cn', ''),
            'description': e.get('description', ''),
            'member_count': cnt,
            'managed_by':  mgr,
        })
    results.sort(key=lambda x: x['cn'].lower())
    return jsonify({'count': len(results), 'results': results})


@ldap_bp.route('/api/ldap/search/users', methods=['POST'])
def search_users():
    """Utilisateurs AD — recherche multi-critères avec wildcards."""
    if (err := _require_ldap()) is not None:
        return err
    body = request.get_json(force=True, silent=True) or {}
    pattern = (body.get('pattern') or '').strip()
    by = body.get('by', 'all')
    if not pattern:
        return api_error('pattern requis')

    filters = {
        'all':       f'(&(objectClass=person)(|(cn={pattern})(sAMAccountName={pattern})(mail={pattern})(sn={pattern})(givenName={pattern})))',
        'cn':        f'(&(objectClass=person)(cn={pattern}))',
        'username':  f'(&(objectClass=person)(sAMAccountName={pattern}))',
        'email':     f'(&(objectClass=person)(mail={pattern}))',
        'lastname':  f'(&(objectClass=person)(sn={pattern}))',
        'firstname': f'(&(objectClass=person)(givenName={pattern}))',
    }
    ldap_filter = filters.get(by, filters['all'])

    c = _cfg_for(session.get('ldap_server_id', ''))
    cmd = _base_cmd(c, session['ldap_user'], session['ldap_pass']) + [
        '-b', _base_dn(c), ldap_filter,
        'cn', 'sAMAccountName', 'mail', 'department', 'title',
        'telephoneNumber', 'mobile', 'whenCreated', 'userAccountControl',
    ]
    ok, out = _run(cmd, _env(c))
    if not ok:
        return api_error(out, 500)

    results = [_user_entry(e) for e in parse_ldif(out)]
    results.sort(key=lambda x: x['cn'].lower())
    return jsonify({'count': len(results), 'results': results})


@ldap_bp.route('/api/ldap/search/user-groups', methods=['POST'])
def search_user_groups():
    """Groupes AD auxquels appartient un utilisateur (memberOf)."""
    if (err := _require_ldap()) is not None:
        return err
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get('username') or '').strip()
    if not username:
        return api_error('username requis')

    c = _cfg_for(session.get('ldap_server_id', ''))
    cmd = _base_cmd(c, session['ldap_user'], session['ldap_pass']) + [
        '-b', _base_dn(c),
        f'(&(objectClass=person)(|(sAMAccountName={username})(cn={username})))',
        'cn', 'sAMAccountName', 'mail', 'memberOf',
    ]
    ok, out = _run(cmd, _env(c))
    if not ok:
        return api_error(out, 500)

    entries = parse_ldif(out)
    if not entries:
        return jsonify({'count': 0, 'user': None, 'groups': []})

    e = entries[0]
    raw = e.get('memberOf', [])
    if isinstance(raw, str):
        raw = [raw]
    groups = sorted(
        [{'dn': g, 'cn': g.split(',')[0].replace('CN=', '').replace('cn=', '')} for g in raw if g],
        key=lambda x: x['cn'].lower()
    )
    return jsonify({
        'user':   {'cn': e.get('cn', ''), 'username': e.get('sAMAccountName', ''), 'email': e.get('mail', '')},
        'count':  len(groups),
        'groups': groups,
    })


@ldap_bp.route('/api/ldap/search/group-members', methods=['POST'])
def search_group_members():
    """Membres directs d'un groupe AD (pas récursif)."""
    if (err := _require_ldap()) is not None:
        return err
    body = request.get_json(force=True, silent=True) or {}
    group_cn = (body.get('group') or '').strip()
    if not group_cn:
        return api_error('group requis')

    c = _cfg_for(session.get('ldap_server_id', ''))
    # 1. Résoudre le DN du groupe
    cmd_g = _base_cmd(c, session['ldap_user'], session['ldap_pass']) + [
        '-b', _base_dn(c), f'(&(objectClass=group)(CN={group_cn}))', 'dn', 'cn', 'description',
    ]
    ok, out_g = _run(cmd_g, _env(c))
    if not ok:
        return api_error(out_g, 500)
    grp_entries = parse_ldif(out_g)
    if not grp_entries:
        return api_error(f'Groupe "{group_cn}" introuvable', 404)

    group_dn   = grp_entries[0].get('dn', '')
    group_desc = grp_entries[0].get('description', '')

    # 2. Membres via memberOf
    cmd_m = _base_cmd(c, session['ldap_user'], session['ldap_pass']) + [
        '-b', _base_dn(c), f'(memberOf={group_dn})',
        'cn', 'sAMAccountName', 'mail', 'department', 'title', 'userAccountControl',
    ]
    ok, out_m = _run(cmd_m, _env(c))
    if not ok:
        return api_error(out_m, 500)

    members = sorted(
        [_user_entry(e) for e in parse_ldif(out_m)],
        key=lambda x: x['cn'].lower()
    )
    return jsonify({
        'group':   {'dn': group_dn, 'cn': group_cn, 'description': group_desc},
        'count':   len(members),
        'members': members,
    })


@ldap_bp.route('/api/ldap/search/computers', methods=['POST'])
def search_computers():
    """Ordinateurs AD par pattern CN (wildcards supportés)."""
    if (err := _require_ldap()) is not None:
        return err
    body = request.get_json(force=True, silent=True) or {}
    pattern = (body.get('pattern') or '').strip()
    if not pattern:
        return api_error('pattern requis')

    c = _cfg_for(session.get('ldap_server_id', ''))
    cmd = _base_cmd(c, session['ldap_user'], session['ldap_pass']) + [
        '-b', _base_dn(c),
        f'(&(objectClass=computer)(CN={pattern}))',
        'cn', 'operatingSystem', 'operatingSystemVersion',
        'description', 'whenCreated', 'lastLogonTimestamp',
    ]
    ok, out = _run(cmd, _env(c))
    if not ok:
        return api_error(out, 500)

    results = sorted(
        [{'cn': e.get('cn', ''), 'os': e.get('operatingSystem', ''),
          'os_version': e.get('operatingSystemVersion', ''),
          'description': e.get('description', ''),
          'created': e.get('whenCreated', ''), 'dn': e.get('dn', '')}
         for e in parse_ldif(out)],
        key=lambda x: x['cn'].lower()
    )
    return jsonify({'count': len(results), 'results': results})


@ldap_bp.route('/api/ldap/compare-users', methods=['POST'])
def compare_users():
    """Diff des groupes AD entre deux utilisateurs (memberOf direct)."""
    if (err := _require_ldap()) is not None:
        return err
    body = request.get_json(force=True, silent=True) or {}
    uname1 = (body.get('user1') or '').strip()
    uname2 = (body.get('user2') or '').strip()
    if not uname1 or not uname2:
        return api_error('user1 et user2 requis')

    c = _cfg_for(session.get('ldap_server_id', ''))

    def _fetch(uname: str):
        """Retourne (info_dict, {cn_lower: {cn, dn}}) ou (None, None/erreur)."""
        cmd = _base_cmd(c, session['ldap_user'], session['ldap_pass']) + [
            '-b', _base_dn(c),
            f'(&(objectClass=person)(|(sAMAccountName={uname})(cn={uname})))',
            'cn', 'sAMAccountName', 'mail', 'memberOf',
        ]
        ok, out = _run(cmd, _env(c))
        if not ok:
            return None, out
        entries = parse_ldif(out)
        if not entries:
            return None, None
        e = entries[0]
        raw = e.get('memberOf', [])
        if isinstance(raw, str):
            raw = [raw]
        groups = {}
        for g in raw:
            if not g:
                continue
            cn = g.split(',')[0].replace('CN=', '').replace('cn=', '')
            groups[cn.lower()] = {'cn': cn, 'dn': g}
        return {'cn': e.get('cn', ''), 'username': e.get('sAMAccountName', ''), 'email': e.get('mail', '')}, groups

    info1, grps1 = _fetch(uname1)
    if info1 is None:
        return api_error(f'Utilisateur "{uname1}" introuvable', 404) if grps1 is None else api_error(grps1, 500)

    info2, grps2 = _fetch(uname2)
    if info2 is None:
        return api_error(f'Utilisateur "{uname2}" introuvable', 404) if grps2 is None else api_error(grps2, 500)

    comparison = []
    for k in sorted(set(grps1) | set(grps2)):
        g1, g2 = grps1.get(k), grps2.get(k)
        in1, in2 = bool(g1), bool(g2)
        entry = g1 or g2
        status = 'common' if in1 and in2 else ('user1_only' if in1 else 'user2_only')
        comparison.append({'cn': entry['cn'], 'dn': entry['dn'], 'in_user1': in1, 'in_user2': in2, 'status': status})

    return jsonify({
        'user1': info1, 'user2': info2,
        'comparison': comparison,
        'stats': {
            'total':      len(comparison),
            'common':     sum(1 for x in comparison if x['status'] == 'common'),
            'user1_only': sum(1 for x in comparison if x['status'] == 'user1_only'),
            'user2_only': sum(1 for x in comparison if x['status'] == 'user2_only'),
        }
    })


@ldap_bp.route('/api/ldap/last-sync', methods=['GET'])
def last_sync():
    """Date de dernière synchronisation AD (nTDSDSA.whenChanged)."""
    if (err := _require_ldap()) is not None:
        return err
    c = _cfg_for(session.get('ldap_server_id', ''))
    cmd = _base_cmd(c, session['ldap_user'], session['ldap_pass']) + [
        '-b', f'CN=Configuration,{_base_dn(c)}',
        '(objectClass=nTDSDSA)',
        'whenChanged', 'modifyTimeStamp',
    ]
    ok, out = _run(cmd, _env(c))
    if not ok:
        return api_error(out, 500)

    entries = parse_ldif(out)
    results = [{'dn': e.get('dn', ''), 'whenChanged': e.get('whenChanged', e.get('modifyTimeStamp', ''))}
               for e in entries]
    return jsonify({'count': len(results), 'results': results})
