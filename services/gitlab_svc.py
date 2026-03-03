"""
Module GitLab — gestion des tokens et pipelines.

Utilise l'API REST GitLab v4 avec un Personal Access Token (PAT) stocké
dans la configuration du portail.

Endpoints utilisés :
  GET /api/v4/personal_access_tokens         → tous les PAT (admin = tous users)
  GET /api/v4/projects?min_access_level=40   → projets accessibles (Maintainer+)
  GET /api/v4/projects/:id/access_tokens     → tokens d'un projet
  GET /api/v4/groups?min_access_level=40     → groupes accessibles
  GET /api/v4/groups/:id/access_tokens       → tokens d'un groupe
"""
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import requests
import urllib3

from services import store
from services.store import ServiceError

logger = logging.getLogger(__name__)

_GITLAB_CONFIG_FILE = 'gitlab_config.json'


# === Config ===

def _config_file(datas_dir: str) -> str:
    return os.path.join(datas_dir, _GITLAB_CONFIG_FILE)


def get_gitlab_config(datas_dir: str) -> dict:
    """Retourne la config GitLab. Initialise avec les defaults si absente."""
    cfg = store.load_json(_config_file(datas_dir)) or {}
    cfg.setdefault('url', '')
    cfg.setdefault('token', '')
    cfg.setdefault('insecure', False)
    return cfg


def save_gitlab_config(datas_dir: str, config: dict) -> None:
    """Sauvegarde la config GitLab."""
    url = config.get('url', '').strip().rstrip('/')
    if not url:
        raise ServiceError('URL GitLab requise', 400)
    token = config.get('token', '').strip()
    if not token:
        raise ServiceError('Token API GitLab requis', 400)
    store.save_json(_config_file(datas_dir), {
        'url':      url,
        'token':    token,
        'insecure': bool(config.get('insecure', False)),
    })


# === Helpers ===

def _days_left(expires_at: Optional[str]) -> Optional[int]:
    """Retourne le nombre de jours avant expiration (négatif si expiré, None si pas de date)."""
    if not expires_at:
        return None
    try:
        exp = datetime.strptime(expires_at[:10], '%Y-%m-%d').replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        return (exp - now).days
    except ValueError:
        return None


def _paginate(
    base_url: str,
    token: str,
    path: str,
    params: Optional[dict] = None,
    insecure: bool = False,
) -> list:
    """Itère toutes les pages d'un endpoint GitLab paginé (header X-Next-Page)."""
    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    headers = {'PRIVATE-TOKEN': token}
    p = dict(params or {})
    p['per_page'] = 100
    p['page'] = 1

    results = []
    while True:
        try:
            resp = requests.get(
                f'{base_url}{path}',
                headers=headers,
                params=p,
                verify=not insecure,
                timeout=20,
            )
        except requests.exceptions.ConnectionError as e:
            raise ServiceError(f'Impossible de joindre GitLab ({base_url}) : {e}', 502)
        except requests.exceptions.Timeout:
            raise ServiceError('Timeout GitLab (20s)', 504)
        except requests.exceptions.RequestException as e:
            raise ServiceError(f'Erreur réseau GitLab : {e}', 502)

        if resp.status_code == 401:
            raise ServiceError('Token GitLab invalide ou expiré (HTTP 401)', 401)
        if resp.status_code == 403:
            raise ServiceError('Accès refusé (HTTP 403) — vérifiez les scopes du token', 403)
        if not resp.ok:
            raise ServiceError(f'GitLab HTTP {resp.status_code} : {resp.text[:200]}', 502)

        page_data = resp.json()
        if not page_data:
            break
        results.extend(page_data)

        next_page = resp.headers.get('X-Next-Page', '')
        if not next_page:
            break
        p['page'] = int(next_page)

    return results


def _normalize_token(t: dict, tok_type: str, scope_name: str) -> dict:
    """Normalise un token GitLab brut en dict uniforme."""
    days = _days_left(t.get('expires_at'))
    return {
        'id':         t.get('id'),
        'name':       t.get('name', ''),
        'type':       tok_type,
        'scope':      scope_name,
        'scopes':     ', '.join(t.get('scopes') or []),
        'created_at': (t.get('created_at') or '')[:10],
        'expires_at': t.get('expires_at') or '—',
        'days_left':  days,
        'expired':    isinstance(days, int) and days < 0,
        'revoked':    t.get('revoked', False),
        'active':     t.get('active', True),
    }


def _sort_key(t: dict):
    """Tri : expirés (jours < 0) en tête, puis par jours croissants, pas de date à la fin."""
    d = t['days_left']
    if d is None:
        return (2, 99999)
    if d < 0:
        return (0, d)
    return (1, d)


# === API ===

def test_connection(base_url: str, token: str, insecure: bool = False) -> dict:
    """Vérifie la connexion GitLab et retourne les infos du token."""
    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    base_url = base_url.rstrip('/')
    try:
        resp = requests.get(
            f'{base_url}/api/v4/personal_access_tokens/self',
            headers={'PRIVATE-TOKEN': token},
            verify=not insecure,
            timeout=10,
        )
    except requests.exceptions.ConnectionError as e:
        raise ServiceError(f'Impossible de joindre GitLab ({base_url}) : {e}', 502)
    except requests.exceptions.Timeout:
        raise ServiceError('Timeout GitLab (10s)', 504)
    except requests.exceptions.RequestException as e:
        raise ServiceError(f'Erreur réseau : {e}', 502)

    if resp.status_code == 401:
        raise ServiceError('Token invalide ou expiré (HTTP 401)', 401)
    if not resp.ok:
        raise ServiceError(f'GitLab HTTP {resp.status_code}', 502)

    data = resp.json()
    days = _days_left(data.get('expires_at'))
    return {
        'name':       data.get('name', ''),
        'username':   data.get('user', {}).get('username', '—') if isinstance(data.get('user'), dict) else '—',
        'scopes':     ', '.join(data.get('scopes') or []),
        'expires_at': data.get('expires_at') or '—',
        'days_left':  days,
        'expired':    isinstance(days, int) and days < 0,
    }


def get_all_tokens(base_url: str, token: str, insecure: bool = False) -> dict:
    """
    Récupère tous les tokens accessibles :
      - Personal Access Tokens (admin → tous les users ; sinon → le sien)
      - Project Access Tokens  (projets où l'on est Maintainer+)
      - Group Access Tokens    (groupes où l'on est Maintainer+)

    Retourne {tokens, stats: {personal, project, group, total, expired, warning}}
    """
    base_url = base_url.rstrip('/')
    results = []

    # ── 1. Personal Access Tokens ──────────────────────────────────────────
    try:
        pats = _paginate(base_url, token, '/api/v4/personal_access_tokens',
                         {'state': 'all'}, insecure)
        for t in pats:
            results.append(_normalize_token(t, 'Personal', t.get('user_id', '—')))
        logger.debug('GitLab PATs: %d', len(pats))
    except ServiceError as e:
        if e.status == 401:
            raise
        logger.warning('PAT fetch skipped: %s', e.message)

    # ── 2. Project Access Tokens ───────────────────────────────────────────
    proj_count = 0
    try:
        projects = _paginate(base_url, token, '/api/v4/projects',
                             {'min_access_level': 40, 'simple': 'true'}, insecure)
        for proj in projects:
            pid = proj.get('id')
            pname = proj.get('path_with_namespace', str(pid))
            try:
                ptoks = _paginate(base_url, token,
                                  f'/api/v4/projects/{pid}/access_tokens', {}, insecure)
                for t in ptoks:
                    results.append(_normalize_token(t, 'Project', pname))
                    proj_count += 1
            except ServiceError:
                pass  # 403 sur un projet → on ignore silencieusement
    except ServiceError as e:
        if e.status == 401:
            raise
        logger.warning('Project tokens fetch skipped: %s', e.message)

    # ── 3. Group Access Tokens ─────────────────────────────────────────────
    grp_count = 0
    try:
        groups = _paginate(base_url, token, '/api/v4/groups',
                           {'min_access_level': 40, 'all_available': 'false'}, insecure)
        for grp in groups:
            gid = grp.get('id')
            gname = grp.get('full_path', grp.get('name', str(gid)))
            try:
                gtoks = _paginate(base_url, token,
                                  f'/api/v4/groups/{gid}/access_tokens', {}, insecure)
                for t in gtoks:
                    results.append(_normalize_token(t, 'Group', gname))
                    grp_count += 1
            except ServiceError:
                pass
    except ServiceError as e:
        if e.status == 401:
            raise
        logger.warning('Group tokens fetch skipped: %s', e.message)

    results.sort(key=_sort_key)

    # ── Stats ──────────────────────────────────────────────────────────────
    expired = sum(1 for t in results if t['expired'] or t['revoked'])
    warning = sum(1 for t in results
                  if not t['expired'] and not t['revoked']
                  and isinstance(t['days_left'], int) and t['days_left'] <= 30)

    stats = {
        'personal': sum(1 for t in results if t['type'] == 'Personal'),
        'project':  proj_count,
        'group':    grp_count,
        'total':    len(results),
        'expired':  expired,
        'warning':  warning,
    }

    return {'tokens': results, 'stats': stats}
