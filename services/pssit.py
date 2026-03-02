"""
Logique métier du module PSSIT : apps, configuration (tokens chiffrés),
historique, planifications, proxy AWX/JFrog.
"""
import json
import logging
import os
import re
import uuid
from datetime import date, datetime, timezone
from typing import Any, Optional

import requests as http_requests

from crypto import decrypt_token, encrypt_token, mask_token
from services import store
from services.store import ServiceError
from services.base import entity_exists, filter_by_resources, remove_from_list

logger = logging.getLogger(__name__)

_HISTORY_MAX = 100
_PARAMS_MAX_KEYS = 20
_PARAMS_MAX_VALUE_LEN = 512
_ALLOWED_PARAM_KEY = re.compile(r'^[A-Za-z0-9_-]{1,64}$')

AWX_STATUS_MAP = {
    'new': 'pending', 'pending': 'pending', 'waiting': 'pending',
    'running': 'running', 'successful': 'successful',
    'failed': 'failed', 'error': 'error', 'canceled': 'canceled',
}


# === Validation params AWX ===

def _validate_params(params: Any) -> dict:
    """Valide la structure, les types et la taille du dict params AWX."""
    if params is None:
        return {}
    if not isinstance(params, dict):
        raise ServiceError('params doit être un objet JSON', 400)
    if len(params) > _PARAMS_MAX_KEYS:
        raise ServiceError(f'params limité à {_PARAMS_MAX_KEYS} clés', 400)
    validated: dict = {}
    for k, v in params.items():
        if not isinstance(k, str) or not _ALLOWED_PARAM_KEY.match(k):
            raise ServiceError(f'Clé params invalide : {k!r}', 400)
        if not isinstance(v, (str, int, float, bool)):
            raise ServiceError(f'Valeur params invalide pour {k!r} : type non supporté', 400)
        if isinstance(v, str) and len(v) > _PARAMS_MAX_VALUE_LEN:
            raise ServiceError(f'Valeur params trop longue pour {k!r}', 400)
        validated[k] = v
    return validated


# === Helpers chemins ===

def _apps_file(datas_dir: str) -> str:
    return os.path.join(datas_dir, 'pssit_apps.json')


def _app_dir(datas_dir: str, app_id: str) -> str:
    return os.path.join(datas_dir, 'pssit', app_id)


def _trash_dir(datas_dir: str) -> str:
    return os.path.join(datas_dir, '_trash')


# === Apps CRUD ===

def pssit_app_exists(datas_dir: str, app_id: str) -> bool:
    return entity_exists(_apps_file(datas_dir), app_id)


def get_pssit_apps(datas_dir: str, user_resources: Optional[list[dict]] = None) -> list[dict]:
    apps: list[dict] = store.load_json(_apps_file(datas_dir)) or []
    return filter_by_resources(apps, user_resources, 'pssit')


def create_pssit_app(datas_dir: str, body: dict) -> None:
    aid = body.get('id', '').strip().upper()
    name = body.get('name', '').strip()
    team = body.get('team', '').strip()
    desc = body.get('description', '').strip()

    if not aid or not store.safe_id(aid):
        raise ServiceError('ID invalide')

    af = _apps_file(datas_dir)
    apps: list[dict] = store.load_json(af) or []
    if any(a['id'] == aid for a in apps):
        raise ServiceError('Cette application existe déjà')

    app_dir = _app_dir(datas_dir, aid)
    os.makedirs(app_dir, exist_ok=True)
    store.save_json(os.path.join(app_dir, 'config.json'), {'environments': []})
    store.save_json(os.path.join(app_dir, 'history.json'), [])
    store.save_json(os.path.join(app_dir, 'schedules.json'), [])

    apps.append({'id': aid, 'name': name or aid, 'team': team, 'description': desc, 'created': date.today().isoformat()})
    store.save_json(af, apps)


def update_pssit_app(datas_dir: str, app_id: str, body: dict) -> None:
    af = _apps_file(datas_dir)
    apps: list[dict] = store.load_json(af) or []
    entry = next((a for a in apps if a['id'] == app_id), None)
    if not entry:
        raise ServiceError('Application non trouvée', 404)
    for field in ('name', 'team', 'description'):
        if field in body:
            entry[field] = body[field]
    store.save_json(af, apps)


def delete_pssit_app(datas_dir: str, app_id: str) -> None:
    remove_from_list(_apps_file(datas_dir), app_id, 'Application non trouvée')
    store.soft_delete_dir(_app_dir(datas_dir, app_id), 'pssit_app', _trash_dir(datas_dir))


# === Config ===

def get_pssit_config(datas_dir: str, app_id: str, secret_key: str = '') -> dict:
    """Retourne la config avec les tokens masqués pour le frontend.
    Avec secret_key, détecte et efface les tokens corrompus (chiffrement de __UNCHANGED__).
    """
    config: dict = store.load_json(os.path.join(_app_dir(datas_dir, app_id), 'config.json')) or {'environments': []}
    for env in config.get('environments', []):
        for section_key in ('awx', 'jfrog'):
            section = env.get(section_key, {})
            if not section.get('token'):
                continue
            if secret_key:
                decrypted = decrypt_token(section['token'], secret_key)
                if not decrypted or decrypted == '__UNCHANGED__':
                    section['token'] = ''  # token corrompu → force re-saisie
                    continue
            section['token'] = mask_token(section['token'])
    return config


def save_pssit_config(datas_dir: str, app_id: str, new_config: dict, secret_key: str) -> None:
    """Sauvegarde la config en chiffrant les nouveaux tokens et préservant les tokens inchangés."""
    old_config: dict = store.load_json(os.path.join(_app_dir(datas_dir, app_id), 'config.json')) or {'environments': []}
    old_envs = {e['id']: e for e in old_config.get('environments', [])}
    for env in new_config.get('environments', []):
        old_env = old_envs.get(env['id'], {})
        awx = env.get('awx', {})
        awx_tok = awx.get('token')
        if awx_tok is None or awx_tok == '__UNCHANGED__':
            old_tok = old_env.get('awx', {}).get('token', '')
            d = decrypt_token(old_tok, secret_key) if old_tok else ''
            awx['token'] = old_tok if (d and d != '__UNCHANGED__') else ''
        elif awx_tok:
            awx['token'] = encrypt_token(awx_tok, secret_key)
        jfrog = env.get('jfrog', {})
        jfrog_tok = jfrog.get('token')
        if jfrog_tok is None or jfrog_tok == '__UNCHANGED__':
            old_tok = old_env.get('jfrog', {}).get('token', '')
            d = decrypt_token(old_tok, secret_key) if old_tok else ''
            jfrog['token'] = old_tok if (d and d != '__UNCHANGED__') else ''
        elif jfrog_tok:
            jfrog['token'] = encrypt_token(jfrog_tok, secret_key)
    store.save_json(os.path.join(_app_dir(datas_dir, app_id), 'config.json'), new_config)


def get_pssit_env_config(datas_dir: str, app_id: str, env_id: str, secret_key: str) -> Optional[dict]:
    """Retourne la config d'un environnement avec les tokens déchiffrés pour usage interne."""
    config: dict = store.load_json(os.path.join(_app_dir(datas_dir, app_id), 'config.json')) or {}
    env = next((e for e in config.get('environments', []) if e['id'] == env_id), None)
    if env is None:
        return None
    awx = env.get('awx', {})
    if awx.get('token'):
        decrypted = decrypt_token(awx['token'], secret_key)
        awx['token'] = decrypted if decrypted != '__UNCHANGED__' else ''
    jfrog = env.get('jfrog', {})
    if jfrog.get('token'):
        decrypted = decrypt_token(jfrog['token'], secret_key)
        jfrog['token'] = decrypted if decrypted != '__UNCHANGED__' else ''
    return env


# === Historique ===

def get_pssit_history(datas_dir: str, app_id: str, limit: int = 50, offset: int = 0) -> list[dict]:
    path = os.path.join(_app_dir(datas_dir, app_id), 'history.json')
    history: list[dict] = store.load_json(path) or []
    return history[offset:offset + limit]


def add_pssit_history(datas_dir: str, app_id: str, entry: dict) -> dict:
    path = os.path.join(_app_dir(datas_dir, app_id), 'history.json')
    history: list[dict] = store.load_json(path) or []
    history.insert(0, entry)
    if len(history) > _HISTORY_MAX:
        history = history[:_HISTORY_MAX]
    store.save_json(path, history)
    return entry


# === Planifications ===

def get_pssit_schedules(datas_dir: str, app_id: str) -> list[dict]:
    path = os.path.join(_app_dir(datas_dir, app_id), 'schedules.json')
    return store.load_json(path) or []


def cancel_pssit_schedule(
    datas_dir: str,
    app_id: str,
    schedule_id: str,
    secret_key: str,
    ssl_verify: Any,
) -> None:
    path = os.path.join(_app_dir(datas_dir, app_id), 'schedules.json')
    schedules: list[dict] = store.load_json(path) or []
    schedule = next((s for s in schedules if s['id'] == schedule_id), None)
    if not schedule:
        raise ServiceError('Schedule non trouvé', 404)

    env_config = get_pssit_env_config(datas_dir, app_id, schedule['envId'], secret_key)
    if env_config:
        awx = env_config.get('awx', {})
        awx_url = awx.get('url', '').rstrip('/')
        awx_token = awx.get('token', '')
        awx_sid = schedule.get('awxScheduleId')
        if awx_url and awx_token and awx_sid:
            try:
                http_requests.delete(
                    f'{awx_url}/api/v2/schedules/{awx_sid}/',
                    headers={'Authorization': f'Bearer {awx_token}'},
                    timeout=15,
                    verify=env_config.get('ssl_verify', ssl_verify),
                )
            except Exception as e:
                logger.warning('Impossible de supprimer le schedule AWX %s : %s', awx_sid, e)

    schedule['status'] = 'cancelled'
    store.save_json(path, schedules)


# === Proxy AWX ===

def launch_pssit_workflow(
    datas_dir: str,
    app_id: str,
    env_id: str,
    body: dict,
    secret_key: str,
    ssl_verify: Any,
) -> dict:
    env_config = get_pssit_env_config(datas_dir, app_id, env_id, secret_key)
    if not env_config:
        raise ServiceError('Environnement non trouvé', 404)

    action = body.get('action')
    if action not in ('stop', 'start', 'status', 'deploy', 'patch'):
        raise ServiceError('Action invalide')
    params = _validate_params(body.get('params', {}))

    awx = env_config.get('awx', {})
    template_id = awx.get('workflows', {}).get(action)
    if not template_id:
        raise ServiceError(f'Workflow non configuré pour {action}')

    awx_url = awx.get('url', '').rstrip('/')
    awx_token = awx.get('token', '')
    extra_vars = {**env_config.get('extraParams', {}), **params}

    entry: dict = {
        'id': uuid.uuid4().hex[:8],
        'action': action,
        'envId': env_id,
        'timestamp': datetime.now(timezone.utc).isoformat() + 'Z',
        'awxJobId': None,
        'awxJobUrl': None,
        'status': 'pending',
        'params': extra_vars,
        'artifact': params.get('artifact'),
    }

    try:
        resp = http_requests.post(
            f'{awx_url}/api/v2/workflow_job_templates/{template_id}/launch/',
            headers={'Authorization': f'Bearer {awx_token}', 'Content-Type': 'application/json'},
            json={'extra_vars': json.dumps(extra_vars)} if extra_vars else {},
            timeout=30,
            verify=env_config.get('ssl_verify', ssl_verify),
        )
        if resp.status_code in (200, 201):
            job_data = resp.json()
            awx_job_id = job_data.get('id') or job_data.get('workflow_job')
            entry['awxJobId'] = awx_job_id
            entry['awxJobUrl'] = f'{awx_url}/#/jobs/workflow/{awx_job_id}'
            entry['status'] = 'running'
        else:
            entry['status'] = 'error'
            entry['params']['_error'] = resp.text[:500]
    except Exception as e:
        entry['status'] = 'error'
        entry['params']['_error'] = str(e)[:500]

    add_pssit_history(datas_dir, app_id, entry)
    return entry


def get_pssit_job_status(
    datas_dir: str,
    app_id: str,
    env_id: str,
    awx_job_id: int,
    secret_key: str,
    ssl_verify: Any,
) -> dict:
    env_config = get_pssit_env_config(datas_dir, app_id, env_id, secret_key)
    if not env_config:
        raise ServiceError('Environnement non trouvé', 404)

    awx = env_config.get('awx', {})
    awx_url = awx.get('url', '').rstrip('/')
    awx_token = awx.get('token', '')

    try:
        resp = http_requests.get(
            f'{awx_url}/api/v2/workflow_jobs/{awx_job_id}/',
            headers={'Authorization': f'Bearer {awx_token}'},
            timeout=15,
            verify=env_config.get('ssl_verify', ssl_verify),
        )
    except http_requests.RequestException as exc:
        logger.warning('AWX job status request failed: %s', exc)
        raise ServiceError('AWX indisponible', 502) from exc
    if resp.status_code != 200:
        raise ServiceError(f'AWX returned {resp.status_code}', 502)

    job = resp.json()
    mapped = AWX_STATUS_MAP.get(job.get('status', ''), job.get('status', 'unknown'))

    hist_path = os.path.join(_app_dir(datas_dir, app_id), 'history.json')
    history: list[dict] = store.load_json(hist_path) or []
    for h in history:
        if h.get('awxJobId') == awx_job_id:
            h['status'] = mapped
            break
    store.save_json(hist_path, history)

    return {'awxJobId': awx_job_id, 'status': mapped, 'finished': job.get('finished'), 'started': job.get('started')}


def schedule_pssit_action(
    datas_dir: str,
    app_id: str,
    env_id: str,
    body: dict,
    secret_key: str,
    ssl_verify: Any,
) -> dict:
    env_config = get_pssit_env_config(datas_dir, app_id, env_id, secret_key)
    if not env_config:
        raise ServiceError('Environnement non trouvé', 404)

    action = body.get('action')
    scheduled_dt: str = body.get('datetime', '')

    if action not in ('stop', 'start'):
        raise ServiceError('Seuls stop et start sont planifiables')

    awx = env_config.get('awx', {})
    template_id = awx.get('workflows', {}).get(action)
    if not template_id:
        raise ServiceError(f'Workflow non configuré pour {action}')

    try:
        dt = datetime.fromisoformat(scheduled_dt.replace('Z', '+00:00') if 'Z' in scheduled_dt else scheduled_dt)
    except (ValueError, AttributeError):
        raise ServiceError('Format de date invalide, attendu ISO 8601')

    awx_url = awx.get('url', '').rstrip('/')
    awx_token = awx.get('token', '')
    schedule_name = f'pssit-{app_id}-{env_id}-{action}-{uuid.uuid4().hex[:6]}'
    dtstart = dt.strftime('%Y%m%dT%H%M%SZ')

    resp = http_requests.post(
        f'{awx_url}/api/v2/workflow_job_templates/{template_id}/schedules/',
        headers={'Authorization': f'Bearer {awx_token}', 'Content-Type': 'application/json'},
        json={
            'name': schedule_name,
            'rrule': f'DTSTART:{dtstart} RRULE:FREQ=MINUTELY;INTERVAL=1;COUNT=1',
            'extra_data': env_config.get('extraParams', {}),
        },
        timeout=30,
        verify=env_config.get('ssl_verify', ssl_verify),
    )
    if resp.status_code not in (200, 201):
        raise ServiceError('AWX schedule failed: ' + resp.text[:500], 502)

    awx_data = resp.json()
    entry: dict = {
        'id': uuid.uuid4().hex[:8],
        'awxScheduleId': awx_data.get('id'),
        'action': action,
        'envId': env_id,
        'scheduledAt': scheduled_dt,
        'createdAt': datetime.now(timezone.utc).isoformat() + 'Z',
        'status': 'active',
    }
    path = os.path.join(_app_dir(datas_dir, app_id), 'schedules.json')
    schedules: list[dict] = store.load_json(path) or []
    schedules.insert(0, entry)
    store.save_json(path, schedules)
    return entry


# === Proxy JFrog ===

def get_pssit_artifacts(
    datas_dir: str,
    app_id: str,
    env_id: str,
    secret_key: str,
    ssl_verify: Any,
) -> list[dict]:
    env_config = get_pssit_env_config(datas_dir, app_id, env_id, secret_key)
    if not env_config:
        raise ServiceError('Environnement non trouvé', 404)

    jfrog = env_config.get('jfrog', {})
    jfrog_url = jfrog.get('url', '').rstrip('/')
    jfrog_token = jfrog.get('token', '')
    repo = jfrog.get('repo', '')
    path = jfrog.get('path', '')

    if not jfrog_url or not repo:
        return []

    if '/artifactory' not in jfrog_url:
        jfrog_url = jfrog_url + '/artifactory'

    resp = http_requests.get(
        f'{jfrog_url}/api/storage/{repo}/{path}',
        headers={'Authorization': f'Bearer {jfrog_token}', 'X-JFrog-Art-Api': jfrog_token},
        params={'list': '', 'deep': '0', 'listFolders': '0'},
        timeout=15,
        verify=env_config.get('ssl_verify', ssl_verify),
    )
    if resp.status_code != 200:
        raise ServiceError(f'JFrog returned {resp.status_code}', 502)

    data = resp.json()
    files = data.get('files', data.get('children', []))
    artifacts: list[dict] = []
    for f in files:
        if f.get('folder', False):
            continue
        name = f.get('uri', f.get('name', '')).lstrip('/')
        artifacts.append({
            'name': name,
            'size': f.get('size', 0),
            'lastModified': f.get('lastModified', f.get('modified', '')),
        })
    artifacts.sort(key=lambda x: x.get('lastModified', ''), reverse=True)
    return artifacts


def browse_jfrog_path(
    datas_dir: str,
    app_id: str,
    env_id: str,
    secret_key: str,
    ssl_verify: Any,
    repo: str = '',
    path: str = '',
) -> dict:
    """Navigation dans l'arborescence JFrog : liste des repos ou contenu d'un dossier.

    Utilise le token enregistré (chiffré) — l'environnement doit être sauvegardé
    avant de pouvoir utiliser le navigateur.
    """
    env_config = get_pssit_env_config(datas_dir, app_id, env_id, secret_key)
    if not env_config:
        raise ServiceError('Environnement non trouvé', 404)

    jfrog = env_config.get('jfrog', {})
    jfrog_url = jfrog.get('url', '').rstrip('/')
    jfrog_token = jfrog.get('token', '')

    if not jfrog_url:
        raise ServiceError('URL JFrog non configurée pour cet environnement', 400)
    if not jfrog_token:
        # Debug : afficher le token brut sur disque pour diagnostiquer
        _raw = store.load_json(os.path.join(_app_dir(datas_dir, app_id), 'config.json')) or {}
        _renv = next((e for e in _raw.get('environments', []) if e['id'] == env_id), None)
        _rtok = (_renv or {}).get('jfrog', {}).get('token', '(absent)')
        raise ServiceError(
            f'Token JFrog non configuré — disque: "{_rtok[:20]}" ({len(_rtok)} cars). '
            f'Enregistrez la config avant de parcourir.', 400
        )

    # Normalise l'URL : l'API Artifactory est sous /artifactory
    if '/artifactory' not in jfrog_url:
        jfrog_url = jfrog_url + '/artifactory'

    # Supporte API key (X-JFrog-Art-Api) et Access Token (Bearer)
    headers = {
        'Authorization': f'Bearer {jfrog_token}',
        'X-JFrog-Art-Api': jfrog_token,
    }
    actual_ssl = env_config.get('ssl_verify', ssl_verify)
    repos_url = f'{jfrog_url}/api/repositories'

    try:
        if not repo:
            # Liste des dépôts disponibles
            resp = http_requests.get(
                repos_url,
                headers=headers,
                timeout=15,
                verify=actual_ssl,
            )
            if resp.status_code in (401, 403):
                tok_debug = jfrog_token[:6] + '…' + jfrog_token[-4:] if len(jfrog_token) > 10 else f'({len(jfrog_token)} cars)'
                raise ServiceError(
                    f'Authentification JFrog échouée ({resp.status_code}) sur {repos_url} — '
                    f'token utilisé : {tok_debug} — '
                    f'Réponse JFrog : {resp.text[:300]}',
                    502,
                )
            if resp.status_code != 200:
                raise ServiceError(
                    f'JFrog a retourné {resp.status_code} sur {repos_url} : {resp.text[:200]}', 502
                )
            repos_data = resp.json()
            if not isinstance(repos_data, list):
                repos_data = []
            return {
                'type': 'repos',
                'items': [
                    {
                        'key': r.get('key', ''),
                        'rtype': r.get('type', ''),
                        'description': r.get('description', ''),
                    }
                    for r in repos_data
                    if r.get('key')
                ],
            }

        # Navigation à l'intérieur d'un dépôt
        path_clean = path.strip('/')
        browse_url = f'{jfrog_url}/api/storage/{repo}'
        if path_clean:
            browse_url += f'/{path_clean}'

        resp = http_requests.get(browse_url, headers=headers, timeout=15, verify=actual_ssl)
        if resp.status_code in (401, 403):
            raise ServiceError(
                f'Authentification JFrog échouée ({resp.status_code}) sur {browse_url} — '
                f'Réponse : {resp.text[:300]}',
                502,
            )
        if resp.status_code == 404:
            raise ServiceError(f'Dépôt ou chemin introuvable : {repo}/{path_clean}', 404)
        if resp.status_code != 200:
            raise ServiceError(f'JFrog a retourné {resp.status_code} : {resp.text[:200]}', 502)
    except http_requests.exceptions.SSLError as e:
        raise ServiceError(
            f'Erreur SSL : {e} — désactivez "Vérification SSL" dans la config env ou '
            f'importez le certificat CA.', 502
        ) from e
    except http_requests.exceptions.ConnectionError as e:
        raise ServiceError(f'Impossible de joindre JFrog ({jfrog_url}) : {e}', 502) from e
    except http_requests.exceptions.Timeout:
        raise ServiceError(f'Timeout en contactant JFrog ({jfrog_url})', 502)
    except ServiceError:
        raise
    except http_requests.exceptions.RequestException as e:
        raise ServiceError(f'Erreur réseau JFrog : {e}', 502) from e

    data = resp.json()
    children = data.get('children', [])
    items = [
        {'uri': c['uri'].lstrip('/'), 'folder': c.get('folder', True)}
        for c in children
        if c.get('uri')
    ]
    # Dossiers en premier, puis fichiers, tri alphabétique
    items.sort(key=lambda x: (not x['folder'], x['uri'].lower()))
    return {'type': 'dir', 'repo': repo, 'path': path_clean, 'items': items}


def browse_awx_templates(
    datas_dir: str,
    app_id: str,
    env_id: str,
    secret_key: str,
    ssl_verify: Any,
) -> dict:
    """Récupère les Workflow Job Templates et Job Templates depuis AWX.

    Utilise le token enregistré (chiffré) — l'environnement doit être sauvegardé.
    Retourne les deux types triés par nom, workflow_job_templates en premier.
    """
    env_config = get_pssit_env_config(datas_dir, app_id, env_id, secret_key)
    if not env_config:
        raise ServiceError('Environnement non trouvé', 404)

    awx = env_config.get('awx', {})
    awx_url = awx.get('url', '').rstrip('/')
    awx_token = awx.get('token', '')

    if not awx_url:
        raise ServiceError('URL AWX non configurée pour cet environnement', 400)
    if not awx_token:
        raise ServiceError(
            'Token AWX non configuré — enregistrez la configuration avant de parcourir', 400
        )

    headers = {'Authorization': f'Bearer {awx_token}'}
    actual_ssl = env_config.get('ssl_verify', ssl_verify)
    templates: list[dict] = []
    warnings: list[str] = []

    for ttype, endpoint in (
        ('workflow', 'workflow_job_templates'),
        ('job', 'job_templates'),
    ):
        try:
            resp = http_requests.get(
                f'{awx_url}/api/v2/{endpoint}/',
                headers=headers,
                params={'page_size': 200, 'order_by': 'name'},
                timeout=15,
                verify=actual_ssl,
            )
            if resp.status_code == 200:
                for t in resp.json().get('results', []):
                    if t.get('id') and t.get('name'):
                        templates.append({
                            'id': t['id'],
                            'name': t['name'],
                            'type': ttype,
                            'description': t.get('description', ''),
                        })
            elif resp.status_code in (401, 403):
                warnings.append(f'Accès refusé à {endpoint} (HTTP {resp.status_code})')
            else:
                warnings.append(f'{endpoint} returned HTTP {resp.status_code}')
        except Exception as e:
            logger.warning('AWX browse %s failed: %s', endpoint, e)
            warnings.append(f'Erreur {endpoint} : {e}')

    if not templates and warnings:
        raise ServiceError(
            'Impossible de charger les templates AWX — ' + '; '.join(warnings), 502
        )

    return {'templates': templates, 'warnings': warnings}
