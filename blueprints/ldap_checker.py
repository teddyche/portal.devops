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

# ── Config ────────────────────────────────────────────────────────────────────

def _cfg() -> dict:
    return get_auth_config().get('ldap', {})

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

@ldap_bp.route('/api/ldap/auth', methods=['POST'])
def ldap_auth():
    """Teste les credentials AD et les stocke en session Flask."""
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get('username') or '').strip()
    password = body.get('password') or ''
    if not username or not password:
        return api_error('username et password requis')

    c = _cfg()
    cmd = _base_cmd(c, username, password) + [
        '-b', _base_dn(c), '-s', 'base', '(objectClass=*)', 'dn'
    ]
    ok, err_msg = _run(cmd, _env(c), timeout=10)
    if not ok:
        _audit.warning('ldap_auth_failed portal_user=%s ldap_user=%s err=%s', _uid(), username, err_msg)
        logger.warning('LDAP auth failed for %s — bind_dn=%s — err: %s', username, _bind_dn(c, username), err_msg)
        return api_error(f'Authentification AD échouée : {err_msg}', 401)

    session['ldap_user'] = username
    session['ldap_pass'] = password
    _audit.info('ldap_auth_ok portal_user=%s ldap_user=%s', _uid(), username)
    return jsonify({'success': True, 'username': username})

@ldap_bp.route('/api/ldap/check-auth', methods=['GET'])
def ldap_check_auth():
    if 'ldap_user' in session:
        return jsonify({'authenticated': True, 'username': session['ldap_user']})
    return jsonify({'authenticated': False})

@ldap_bp.route('/api/ldap/logout', methods=['POST'])
def ldap_logout():
    session.pop('ldap_user', None)
    session.pop('ldap_pass', None)
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

    c = _cfg()
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

    c = _cfg()
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

    c = _cfg()
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

    c = _cfg()
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

    c = _cfg()
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


@ldap_bp.route('/api/ldap/last-sync', methods=['GET'])
def last_sync():
    """Date de dernière synchronisation AD (nTDSDSA.whenChanged)."""
    if (err := _require_ldap()) is not None:
        return err
    c = _cfg()
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
