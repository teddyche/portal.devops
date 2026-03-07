"""
Service JFrog Tokens Checker — instances, fetch tokens (access + API keys), snapshots.
"""
import glob
import json
import os
import shutil
import ssl
import uuid
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from services.store import ServiceError, load_json, save_json


def _root(dd):             return os.path.join(dd, 'jfrog')
def _ipath(dd):            return os.path.join(_root(dd), 'instances.json')
def _sdir(dd, iid):        return os.path.join(_root(dd), 'snapshots', iid)
def _spath(dd, iid, sid):  return os.path.join(_sdir(dd, iid), sid + '.json')

def _li(dd): return load_json(_ipath(dd)) or {'instances': []}
def _si(dd, d): save_json(_ipath(dd), d)


# ── Instances ──────────────────────────────────────────────────────────────────

def list_instances(dd):
    return _li(dd)['instances']


def get_instance(dd, iid):
    return next((i for i in list_instances(dd) if i['id'] == iid), None)


def create_instance(dd, name, url, token, color='#2196f3', description='', validate_certs=True):
    if not name or not url or not token:
        raise ServiceError('Nom, URL et token requis')
    d = _li(dd)
    inst = {
        'id':             uuid.uuid4().hex[:12],
        'name':           name,
        'description':    description,
        'color':          color,
        'url':            url.rstrip('/'),
        'token':          token,
        'validate_certs': validate_certs,
        'created_at':     datetime.utcnow().isoformat(),
    }
    d['instances'].append(inst)
    _si(dd, d)
    return inst


def update_instance(dd, iid, **kw):
    d = _li(dd)
    inst = next((i for i in d['instances'] if i['id'] == iid), None)
    if not inst:
        raise ServiceError('Instance introuvable', 404)
    for k in ('name', 'description', 'color', 'validate_certs'):
        if k in kw and kw[k] is not None:
            inst[k] = kw[k]
    if 'url' in kw and kw['url']:
        inst['url'] = kw['url'].rstrip('/')
    if 'token' in kw and kw['token'] and not set(kw['token']) <= {'•'}:
        inst['token'] = kw['token']
    _si(dd, d)
    return inst


def delete_instance(dd, iid):
    d = _li(dd)
    d['instances'] = [i for i in d['instances'] if i['id'] != iid]
    _si(dd, d)
    p = _sdir(dd, iid)
    if os.path.isdir(p):
        shutil.rmtree(p)


# ── HTTP ───────────────────────────────────────────────────────────────────────

def _ctx(validate_certs):
    return ssl.create_default_context() if validate_certs else ssl._create_unverified_context()


def _get(url, token, ctx, timeout=30):
    req = Request(url, headers={'Authorization': f'Bearer {token}'})
    with urlopen(req, context=ctx, timeout=timeout) as r:
        return json.loads(r.read().decode())


# ── Test connexion ─────────────────────────────────────────────────────────────

def test_connection(url, token, validate_certs=True):
    try:
        base = url.rstrip('/')
        ctx  = _ctx(validate_certs)
        _get(f'{base}/artifactory/api/system/ping', token, ctx)
        version = None
        try:
            info    = _get(f'{base}/artifactory/api/system/version', token, ctx)
            version = info.get('version')
        except Exception:
            pass
        return {'ok': True, 'version': version or 'OK'}
    except HTTPError as e:
        if e.code in (401, 403):
            raise ServiceError('Authentification échouée — vérifier le token', 401)
        raise ServiceError(f'Erreur HTTP {e.code}', 502)
    except Exception as e:
        raise ServiceError(f'Connexion impossible : {e}', 502)


# ── Normalisation tokens ───────────────────────────────────────────────────────

def _normalize_access_token(raw):
    now    = datetime.now(timezone.utc)
    expiry = raw.get('expiry', 0)
    issued = raw.get('issued_at', 0)

    if isinstance(expiry, (int, float)) and expiry > 0:
        exp_dt     = datetime.fromtimestamp(expiry, tz=timezone.utc)
        expires_at = exp_dt.strftime('%Y-%m-%d')
        days_left  = (exp_dt - now).days
        expired    = days_left < 0
    else:
        expires_at = '—'
        days_left  = None
        expired    = False

    issued_at = datetime.fromtimestamp(issued, tz=timezone.utc).strftime('%Y-%m-%d') \
        if isinstance(issued, (int, float)) and issued > 0 else '—'

    subject = raw.get('subject', '')
    if '/users/' in subject:
        user = subject.split('/users/')[-1]
    elif '/groups/' in subject:
        user = subject.split('/groups/')[-1]
    else:
        user = subject

    return {
        'id':          raw.get('token_id', ''),
        'name':        raw.get('description') or subject or raw.get('token_id', ''),
        'type':        'access_token',
        'token_type':  raw.get('token_type', 'user').lower(),
        'subject':     user,
        'scope':       raw.get('scope', ''),
        'issued_at':   issued_at,
        'expires_at':  expires_at,
        'days_left':   days_left,
        'expired':     expired,
        'project_key': raw.get('project_key', ''),
    }


def _normalize_api_key(username):
    return {
        'id':          f'apikey_{username}',
        'name':        f'API Key — {username}',
        'type':        'api_key',
        'token_type':  'user',
        'subject':     username,
        'scope':       'api-key',
        'issued_at':   '—',
        'expires_at':  '—',
        'days_left':   None,
        'expired':     False,
        'project_key': '',
    }


def _sort_key(t):
    d = t['days_left']
    if d is None: return (2, 99999)
    if d < 0:     return (0, d)
    return (1, d)


# ── Fetch ──────────────────────────────────────────────────────────────────────

def fetch_tokens(url, token, validate_certs=True):
    base   = url.rstrip('/')
    ctx    = _ctx(validate_certs)
    tokens = []

    # 1. Access tokens (pagination offset/limit)
    try:
        offset = 0
        limit  = 100
        while True:
            data = _get(f'{base}/access/api/v1/tokens?offset={offset}&limit={limit}', token, ctx)
            page = data.get('tokens', [])
            tokens.extend(_normalize_access_token(r) for r in page)
            total = data.get('total_count', len(tokens))
            if len(tokens) >= total or not page:
                break
            offset += limit
    except HTTPError as e:
        if e.code in (401, 403):
            raise ServiceError('Authentification échouée — token admin requis', 401)
        raise ServiceError(f'Erreur access tokens : HTTP {e.code}', 502)
    except Exception as e:
        raise ServiceError(f'Impossible de récupérer les tokens : {e}', 502)

    # 2. Legacy API keys (best-effort, skip si non disponible)
    seen_subjects = {t['subject'] for t in tokens if t['type'] == 'access_token'}
    try:
        users = _get(f'{base}/artifactory/api/security/users', token, ctx)
        for u in users[:300]:
            uname = u.get('name', '')
            if not uname or uname in seen_subjects:
                continue
            try:
                udata = _get(f'{base}/artifactory/api/security/user/{uname}', token, ctx, timeout=10)
                if udata.get('apiKey'):
                    tokens.append(_normalize_api_key(uname))
            except Exception:
                pass
    except Exception:
        pass  # API non disponible ou accès insuffisant

    tokens.sort(key=_sort_key)

    expired  = sum(1 for t in tokens if t['expired'])
    critical = sum(1 for t in tokens if not t['expired'] and t['days_left'] is not None and t['days_left'] <= 7)
    warning  = sum(1 for t in tokens if not t['expired'] and t['days_left'] is not None and 7 < t['days_left'] <= 30)
    stats = {
        'total':         len(tokens),
        'access_tokens': sum(1 for t in tokens if t['type'] == 'access_token'),
        'api_keys':      sum(1 for t in tokens if t['type'] == 'api_key'),
        'expired':       expired,
        'critical':      critical,
        'warning':       warning,
    }
    return {'tokens': tokens, 'stats': stats}


# ── Snapshots ──────────────────────────────────────────────────────────────────

def save_snapshot(dd, iid, tokens, stats):
    now = datetime.now(timezone.utc)
    sid = now.strftime('%Y%m%d_%H%M%S')
    snap = {'id': sid, 'timestamp': now.isoformat(), 'tokens': tokens, 'stats': stats}
    os.makedirs(_sdir(dd, iid), exist_ok=True)
    save_json(_spath(dd, iid, sid), snap)
    return sid


def list_snapshots(dd, iid):
    d = _sdir(dd, iid)
    if not os.path.isdir(d):
        return []
    out = []
    for f in glob.glob(os.path.join(d, '*.json')):
        s = load_json(f)
        if not s:
            continue
        out.append({'id': s.get('id', ''), 'timestamp': s.get('timestamp', ''), 'stats': s.get('stats', {})})
    return sorted(out, key=lambda x: x['timestamp'], reverse=True)


def get_snapshot(dd, iid, sid):
    snap = load_json(_spath(dd, iid, sid))
    if not snap:
        raise ServiceError('Snapshot introuvable', 404)
    return snap


def delete_snapshot(dd, iid, sid):
    p = _spath(dd, iid, sid)
    if os.path.exists(p):
        os.remove(p)


def purge_old_snapshots(dd, iid, retention_days=90):
    d = _sdir(dd, iid)
    if not os.path.isdir(d):
        return 0
    cutoff  = datetime.now(timezone.utc) - timedelta(days=max(1, retention_days))
    deleted = 0
    for f in glob.glob(os.path.join(d, '*.json')):
        mtime = datetime.fromtimestamp(os.path.getmtime(f), tz=timezone.utc)
        if mtime < cutoff:
            os.remove(f)
            deleted += 1
    return deleted
