"""
Logique métier du module Kubi IHM.

Kubi est un serveur d'authentification Kubernetes (via AD/LDAP).
Il expose 3 endpoints :
  GET /ca      → Certificat CA du cluster (skip SSL)
  GET /token   → JWT token (Basic Auth user:pass, ?scopes=)
  GET /config  → Kubeconfig YAML complet (Basic Auth user:pass)

Le mot de passe n'est jamais stocké — utilisé uniquement pour l'appel API.
"""
import base64
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

import requests
import urllib3

from services import store
from services.store import ServiceError

logger = logging.getLogger(__name__)

_KUBI_CONFIG_FILE = 'kubi_config.json'

# Clusters par défaut (peuvent être surchargés via la page config)
_DEFAULT_CLUSTERS = [
    {
        'id': 'prod',
        'name': 'Prod',
        'url': 'https://kubi.prd.managed.ca-ps.group.gca',
        'insecure': True,
        'use_proxy': True,
    },
    {
        'id': 'hprd',
        'name': 'Hors Prod 1',
        'url': 'https://kubi.hprd.managed.ca-ps.group.gca',
        'insecure': True,
        'use_proxy': True,
    },
    {
        'id': 'hpr02',
        'name': 'Hors Prod 2',
        'url': 'https://kubi.hpr02.managed.ca-ps.group.gca',
        'insecure': True,
        'use_proxy': True,
    },
]


# === Config ===

def _kubi_config_file(datas_dir: str) -> str:
    return os.path.join(datas_dir, _KUBI_CONFIG_FILE)


def get_kubi_config(datas_dir: str) -> dict:
    """Retourne la config kubi (clusters + proxy_url). Initialise avec les defaults si absent."""
    cfg = store.load_json(_kubi_config_file(datas_dir)) or {}
    cfg.setdefault('clusters', _DEFAULT_CLUSTERS)
    cfg.setdefault('proxy_url', '')
    return cfg


def save_kubi_config(datas_dir: str, config: dict) -> None:
    """Sauvegarde la config kubi."""
    clusters = config.get('clusters', [])
    for c in clusters:
        cid = c.get('id', '').strip()
        if not cid or not store.safe_id(cid):
            raise ServiceError(f'ID cluster invalide : {cid!r}', 400)
        if not c.get('url', '').strip():
            raise ServiceError(f'URL manquante pour le cluster {cid!r}', 400)
    store.save_json(_kubi_config_file(datas_dir), config)


# === Token ===

def decode_token(token: str) -> dict:
    """Décode un JWT (sans vérifier la signature) et retourne ses informations.

    Retourne : { exp, expires_at, valid, remaining_seconds, body }
    """
    token = token.strip()
    parts = token.split('.')
    if len(parts) != 3:
        raise ServiceError('Token JWT invalide — doit contenir 3 parties séparées par des points', 400)

    try:
        # Padding base64url
        padded = parts[1] + '=' * (-len(parts[1]) % 4)
        payload_bytes = base64.urlsafe_b64decode(padded)
        payload = json.loads(payload_bytes)
    except Exception as e:
        raise ServiceError(f'Impossible de décoder le token JWT : {e}', 400)

    exp = payload.get('exp', 0)
    exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
    now = datetime.now(timezone.utc)
    valid = now < exp_dt
    remaining = int((exp_dt - now).total_seconds()) if valid else 0

    return {
        'exp': exp,
        'expires_at': exp_dt.isoformat(),
        'valid': valid,
        'remaining_seconds': remaining,
        'body': payload,
    }


def generate_kubi_token(
    cluster_url: str,
    username: str,
    password: str,
    insecure: bool = True,
    proxy_url: str = '',
    use_proxy: bool = False,
    scopes: str = '',
) -> dict:
    """
    Génère un token Kubi et récupère le kubeconfig complet.

    Appelle :
      GET {cluster_url}/token  → JWT string (Basic Auth)
      GET {cluster_url}/config → kubeconfig YAML (Basic Auth)

    Le mot de passe n'est jamais stocké ni loggé.

    Retourne :
      { token, kubeconfig, exp, expires_at, valid, remaining_seconds, body }
    """
    if not username or not password:
        raise ServiceError('Username et mot de passe requis', 400)

    if not cluster_url.startswith('https://'):
        cluster_url = 'https://' + cluster_url
    cluster_url = cluster_url.rstrip('/')

    # Supprime les warnings SSL si mode insecure
    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Construit le proxy avec les credentials utilisateur (format AD)
    # ex: http://U76YB33%40zoe.gca:password@prxcagip.zoe.gca:8080
    proxies: Optional[dict] = None
    if use_proxy and proxy_url.strip():
        encoded_user = quote(username, safe='')
        encoded_pass = quote(password, safe='')
        proxy_base = proxy_url.strip().rstrip('/')
        if '://' in proxy_base:
            scheme, host = proxy_base.split('://', 1)
        else:
            scheme, host = 'http', proxy_base
        auth_proxy = f'{scheme}://{encoded_user}:{encoded_pass}@{host}'
        proxies = {'http': auth_proxy, 'https': auth_proxy}

    sess = requests.Session()
    sess.verify = False  # Kubi utilise toujours un CA interne non reconnu
    if proxies:
        sess.proxies.update(proxies)

    # ── Étape 1 : Token JWT ──────────────────────────────────────────────────
    try:
        params = {'scopes': scopes} if scopes else {}
        token_resp = sess.get(
            f'{cluster_url}/token',
            auth=(username, password),
            params=params,
            timeout=30,
        )
    except requests.exceptions.ConnectionError as e:
        raise ServiceError(f'Impossible de joindre le serveur Kubi ({cluster_url}) : {e}', 502)
    except requests.exceptions.Timeout:
        raise ServiceError(f'Timeout en contactant {cluster_url} (30s)', 504)
    except requests.exceptions.RequestException as e:
        raise ServiceError(f'Erreur réseau : {e}', 502)

    if token_resp.status_code == 401:
        raise ServiceError('Identifiants incorrects (HTTP 401) — vérifiez username et mot de passe', 401)
    if token_resp.status_code == 403:
        raise ServiceError('Accès refusé (HTTP 403) — compte non autorisé sur ce cluster', 403)
    if token_resp.status_code not in (200, 201):
        raise ServiceError(
            f'Kubi a retourné HTTP {token_resp.status_code} sur /token : {token_resp.text[:300]}',
            502,
        )

    token = token_resp.text.strip()
    if not token:
        raise ServiceError('Kubi a retourné un token vide', 502)

    # ── Étape 2 : Kubeconfig YAML ────────────────────────────────────────────
    kubeconfig = ''
    try:
        config_resp = sess.get(
            f'{cluster_url}/config',
            auth=(username, password),
            timeout=30,
        )
        if config_resp.status_code in (200, 201):
            kubeconfig = config_resp.text
        else:
            logger.warning('Kubi /config returned %d — kubeconfig not available', config_resp.status_code)
    except requests.exceptions.RequestException as e:
        logger.warning('Kubi /config failed (non-blocking): %s', e)

    # ── Étape 3 : Decode JWT ─────────────────────────────────────────────────
    token_info = decode_token(token)

    # ── Étape 4 : URL K8s depuis kubeconfig ──────────────────────────────────
    k8s_url = _parse_k8s_url(kubeconfig) if kubeconfig else ''

    return {
        'token': token,
        'kubeconfig': kubeconfig,
        'k8s_url': k8s_url,
        **token_info,
    }


# === K8s API — Namespaces + Quotas ===

def _parse_k8s_url(kubeconfig_yaml: str) -> str:
    """Extrait l'URL du serveur K8s depuis un kubeconfig YAML (ligne 'server: ...')."""
    match = re.search(r'^\s+server:\s*(\S+)', kubeconfig_yaml, re.MULTILINE)
    return match.group(1).rstrip('/') if match else ''


def _parse_resource_value(val: str) -> float:
    """Convertit une valeur de ressource K8s en float normalisé (CPU→cores, mémoire→Gi)."""
    if not val:
        return 0.0
    val = str(val).strip()
    # CPU millicores
    if val.endswith('m'):
        return round(float(val[:-1]) / 1000, 3)
    # Mémoire / stockage
    if val.endswith('Ki'):
        return round(float(val[:-2]) / (1024 ** 2), 4)
    if val.endswith('Mi'):
        return round(float(val[:-2]) / 1024, 3)
    if val.endswith('Gi'):
        return round(float(val[:-2]), 3)
    if val.endswith('Ti'):
        return round(float(val[:-2]) * 1024, 3)
    try:
        return round(float(val), 3)
    except ValueError:
        return 0.0


def get_kubi_quotas(
    k8s_url: str,
    token: str,
    namespace: str,
    insecure: bool = True,
    proxy_url: str = '',
    use_proxy: bool = False,
) -> list:
    """
    Retourne les ResourceQuotas d'un namespace K8s en appelant l'API directement.

    Utilise le token Bearer (JWT kubi) — aucun mot de passe requis.
    Le proxy (sans credentials) est utilisé si use_proxy=True et proxy_url fourni.
    Retourne une liste de dicts normalisés { name, resources: [{name, hard_raw, used_raw,
    hard, used, percent}] }.
    """
    if not k8s_url or not token or not namespace:
        raise ServiceError('k8s_url, token et namespace requis', 400)

    k8s_url = k8s_url.rstrip('/')

    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Proxy sans credentials (les calls K8s utilisent le Bearer token, pas Basic Auth)
    proxies: Optional[dict] = None
    if use_proxy and proxy_url.strip():
        proxy_base = proxy_url.strip().rstrip('/')
        proxies = {'http': proxy_base, 'https': proxy_base}

    try:
        resp = requests.get(
            f'{k8s_url}/api/v1/namespaces/{namespace}/resourcequotas',
            headers={'Authorization': f'Bearer {token}'},
            verify=not insecure,
            proxies=proxies,
            timeout=15,
        )
    except requests.exceptions.ConnectionError as e:
        raise ServiceError(f'Impossible de joindre l\'API K8s ({k8s_url}) : {e}', 502)
    except requests.exceptions.Timeout:
        raise ServiceError(f'Timeout en contactant l\'API K8s (15s)', 504)
    except requests.exceptions.RequestException as e:
        raise ServiceError(f'Erreur réseau K8s : {e}', 502)

    if resp.status_code == 401:
        raise ServiceError('Token expiré ou invalide pour l\'API K8s (HTTP 401)', 401)
    if resp.status_code == 403:
        raise ServiceError(
            f'Accès refusé au namespace "{namespace}" (HTTP 403) — droits insuffisants', 403
        )
    if resp.status_code == 404:
        raise ServiceError(f'Namespace "{namespace}" introuvable (HTTP 404)', 404)
    if not resp.ok:
        raise ServiceError(
            f'API K8s a retourné HTTP {resp.status_code} : {resp.text[:200]}', 502
        )

    data = resp.json()
    result = []

    for item in data.get('items', []):
        status = item.get('status', {})
        hard = status.get('hard', {})
        used = status.get('used', {})

        resources = []
        for key in sorted(hard.keys()):
            hard_raw = hard.get(key, '0')
            used_raw = used.get(key, '0')
            hard_f = _parse_resource_value(hard_raw)
            used_f = _parse_resource_value(used_raw)
            pct = round(used_f / hard_f * 100, 1) if hard_f > 0 else 0.0

            resources.append({
                'name': key,
                'hard_raw': hard_raw,
                'used_raw': used_raw,
                'hard': hard_f,
                'used': used_f,
                'percent': pct,
            })

        result.append({
            'name': item['metadata']['name'],
            'resources': resources,
        })

    return result


def _list_namespaces(
    k8s_url: str,
    token: str,
    insecure: bool = True,
    proxy_url: str = '',
    use_proxy: bool = False,
) -> list:
    """Liste tous les namespaces K8s accessibles avec ce token (GET /api/v1/namespaces)."""
    k8s_url = k8s_url.rstrip('/')

    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    proxies: Optional[dict] = None
    if use_proxy and proxy_url.strip():
        proxy_base = proxy_url.strip().rstrip('/')
        proxies = {'http': proxy_base, 'https': proxy_base}

    try:
        resp = requests.get(
            f'{k8s_url}/api/v1/namespaces',
            headers={'Authorization': f'Bearer {token}'},
            verify=not insecure,
            proxies=proxies,
            timeout=15,
        )
    except requests.exceptions.ConnectionError as e:
        raise ServiceError(f'Impossible de joindre l\'API K8s ({k8s_url}) : {e}', 502)
    except requests.exceptions.Timeout:
        raise ServiceError('Timeout en contactant l\'API K8s (15s)', 504)
    except requests.exceptions.RequestException as e:
        raise ServiceError(f'Erreur réseau K8s : {e}', 502)

    if resp.status_code == 401:
        raise ServiceError('Token expiré ou invalide (HTTP 401)', 401)
    if resp.status_code == 403:
        raise ServiceError('Token sans permission de lister les namespaces (HTTP 403)', 403)
    if not resp.ok:
        raise ServiceError(f'API K8s a retourné HTTP {resp.status_code}', 502)

    data = resp.json()
    return sorted(item['metadata']['name'] for item in data.get('items', []))


def get_all_kubi_quotas(
    k8s_url: str,
    token: str,
    insecure: bool = True,
    proxy_url: str = '',
    use_proxy: bool = False,
) -> list:
    """
    Liste tous les namespaces accessibles puis récupère leurs quotas.

    Ignore silencieusement les namespaces en 403/404 (droits insuffisants).
    Retourne une liste de dicts { namespace, quotas } uniquement pour les
    namespaces qui ont des ResourceQuotas et sont accessibles.
    """
    namespaces = _list_namespaces(k8s_url, token, insecure, proxy_url, use_proxy)

    results = []
    for ns in namespaces:
        try:
            quotas = get_kubi_quotas(k8s_url, token, ns, insecure, proxy_url, use_proxy)
            # N'inclut que les namespaces qui ont effectivement des quotas configurés
            if quotas:
                results.append({'namespace': ns, 'quotas': quotas})
        except ServiceError as e:
            if e.status not in (403, 404):
                # Erreur inattendue : on l'inclut pour que l'UI puisse l'afficher
                results.append({'namespace': ns, 'quotas': [], 'error': e.message})
            # 403/404 → on ignore silencieusement

    return results


# === Helpers ===

def _fmt_age(ts_str: str, now: datetime) -> str:
    """Convertit un timestamp ISO K8s en durée lisible (ex: 3h, 2j)."""
    if not ts_str:
        return '—'
    try:
        created = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        secs = int((now - created).total_seconds())
        if secs < 0:      return '—'
        if secs < 60:     return f'{secs}s'
        if secs < 3600:   return f'{secs // 60}m'
        if secs < 86400:  return f'{secs // 3600}h'
        return f'{secs // 86400}j'
    except ValueError:
        return ts_str[:10] if len(ts_str) >= 10 else ts_str


# === K8s API — Pods ===

def _pod_display_status(pod: dict) -> str:
    """Calcule le statut affiché d'un pod (équivalent kubectl get pods STATUS)."""
    # Terminating
    if pod.get('metadata', {}).get('deletionTimestamp'):
        return 'Terminating'

    phase = pod.get('status', {}).get('phase', 'Unknown')

    # Raisons spécifiques dans les containerStatuses (CrashLoopBackOff, ImagePullBackOff…)
    for cs in (pod.get('status', {}).get('initContainerStatuses', []) +
               pod.get('status', {}).get('containerStatuses', [])):
        state = cs.get('state', {})
        waiting = state.get('waiting', {})
        if waiting.get('reason'):
            return waiting['reason']
        terminated = state.get('terminated', {})
        if terminated and terminated.get('exitCode', 0) != 0:
            return 'Error'

    if phase == 'Running':
        container_statuses = pod.get('status', {}).get('containerStatuses', [])
        if container_statuses and not all(cs.get('ready', False) for cs in container_statuses):
            return 'NotReady'
        return 'Running'

    return phase  # Pending, Succeeded, Failed, Unknown


def get_kubi_pods(
    k8s_url: str,
    token: str,
    namespace: str,
    insecure: bool = True,
    proxy_url: str = '',
    use_proxy: bool = False,
) -> list:
    """Liste les pods d'un namespace avec statut normalisé, ready, restarts et age."""
    if not k8s_url or not token or not namespace:
        raise ServiceError('k8s_url, token et namespace requis', 400)

    k8s_url = k8s_url.rstrip('/')

    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    proxies: Optional[dict] = None
    if use_proxy and proxy_url.strip():
        proxy_base = proxy_url.strip().rstrip('/')
        proxies = {'http': proxy_base, 'https': proxy_base}

    try:
        resp = requests.get(
            f'{k8s_url}/api/v1/namespaces/{namespace}/pods',
            headers={'Authorization': f'Bearer {token}'},
            verify=not insecure,
            proxies=proxies,
            timeout=15,
        )
    except requests.exceptions.ConnectionError as e:
        raise ServiceError(f'Impossible de joindre l\'API K8s ({k8s_url}) : {e}', 502)
    except requests.exceptions.Timeout:
        raise ServiceError('Timeout K8s (15s)', 504)
    except requests.exceptions.RequestException as e:
        raise ServiceError(f'Erreur réseau K8s : {e}', 502)

    if resp.status_code == 401:
        raise ServiceError('Token expiré ou invalide (HTTP 401)', 401)
    if resp.status_code == 403:
        raise ServiceError(f'Accès refusé aux pods du namespace "{namespace}" (HTTP 403)', 403)
    if resp.status_code == 404:
        raise ServiceError(f'Namespace "{namespace}" introuvable (HTTP 404)', 404)
    if not resp.ok:
        raise ServiceError(f'API K8s HTTP {resp.status_code} : {resp.text[:200]}', 502)

    data = resp.json()
    now = datetime.now(timezone.utc)

    # Ordre de tri : problématiques en premier
    _status_order = {
        'CrashLoopBackOff': 0, 'Error': 1, 'OOMKilled': 2,
        'ImagePullBackOff': 3, 'ErrImagePull': 4, 'Failed': 5,
        'Pending': 6, 'NotReady': 7, 'Terminating': 8,
        'Running': 20, 'Succeeded': 21, 'Completed': 22, 'Unknown': 30,
    }

    result = []
    for item in data.get('items', []):
        meta = item.get('metadata', {})
        status = item.get('status', {})
        container_statuses = status.get('containerStatuses', [])
        spec_containers = item.get('spec', {}).get('containers', [])

        ready_count = sum(1 for cs in container_statuses if cs.get('ready', False))
        total_count = len(container_statuses) or len(spec_containers)
        restarts = sum(cs.get('restartCount', 0) for cs in container_statuses)

        # Age
        age_str = ''
        created_str = meta.get('creationTimestamp', '')
        if created_str:
            try:
                created = datetime.strptime(created_str, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
                secs = int((now - created).total_seconds())
                if secs < 60:        age_str = f'{secs}s'
                elif secs < 3600:    age_str = f'{secs // 60}m'
                elif secs < 86400:   age_str = f'{secs // 3600}h'
                else:                age_str = f'{secs // 86400}j'
            except ValueError:
                age_str = created_str

        pod_status = _pod_display_status(item)

        result.append({
            'name': meta.get('name', ''),
            'status': pod_status,
            'ready': f'{ready_count}/{total_count}',
            'restarts': restarts,
            'age': age_str,
        })

    result.sort(key=lambda p: (_status_order.get(p['status'], 15), p['name']))
    return result


def delete_kubi_pod(
    k8s_url: str,
    token: str,
    namespace: str,
    pod_name: str,
    insecure: bool = True,
    proxy_url: str = '',
    use_proxy: bool = False,
) -> dict:
    """Supprime un pod (force restart via le Deployment/StatefulSet qui le gère)."""
    if not all([k8s_url, token, namespace, pod_name]):
        raise ServiceError('k8s_url, token, namespace et pod_name requis', 400)

    k8s_url = k8s_url.rstrip('/')

    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    proxies: Optional[dict] = None
    if use_proxy and proxy_url.strip():
        proxy_base = proxy_url.strip().rstrip('/')
        proxies = {'http': proxy_base, 'https': proxy_base}

    try:
        resp = requests.delete(
            f'{k8s_url}/api/v1/namespaces/{namespace}/pods/{pod_name}',
            headers={'Authorization': f'Bearer {token}'},
            verify=not insecure,
            proxies=proxies,
            timeout=15,
        )
    except requests.exceptions.ConnectionError as e:
        raise ServiceError(f'Impossible de joindre l\'API K8s : {e}', 502)
    except requests.exceptions.Timeout:
        raise ServiceError('Timeout K8s (15s)', 504)
    except requests.exceptions.RequestException as e:
        raise ServiceError(f'Erreur réseau K8s : {e}', 502)

    if resp.status_code == 401:
        raise ServiceError('Token expiré ou invalide (HTTP 401)', 401)
    if resp.status_code == 403:
        raise ServiceError(f'Droits insuffisants pour supprimer "{pod_name}" (HTTP 403)', 403)
    if resp.status_code == 404:
        raise ServiceError(f'Pod "{pod_name}" introuvable (déjà supprimé ?)', 404)
    if not resp.ok:
        raise ServiceError(f'API K8s HTTP {resp.status_code} : {resp.text[:200]}', 502)

    return {'deleted': pod_name}


# === K8s API — Namespace Describe ===

def get_kubi_namespace_describe(
    k8s_url: str,
    token: str,
    namespace: str,
    insecure: bool = True,
    proxy_url: str = '',
    use_proxy: bool = False,
) -> dict:
    """
    Décrit un namespace : métadonnées (labels, annotations, statut) + LimitRanges.
    Équivalent de `kubectl describe namespace <ns>`.
    """
    if not all([k8s_url, token, namespace]):
        raise ServiceError('k8s_url, token et namespace requis', 400)

    k8s_url = k8s_url.rstrip('/')

    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    proxies: Optional[dict] = None
    if use_proxy and proxy_url.strip():
        proxy_base = proxy_url.strip().rstrip('/')
        proxies = {'http': proxy_base, 'https': proxy_base}

    headers = {'Authorization': f'Bearer {token}'}
    req_kwargs = dict(headers=headers, verify=not insecure, proxies=proxies, timeout=15)

    def _get(path: str):
        try:
            resp = requests.get(f'{k8s_url}{path}', **req_kwargs)
        except requests.exceptions.ConnectionError as e:
            raise ServiceError(f'Impossible de joindre l\'API K8s : {e}', 502)
        except requests.exceptions.Timeout:
            raise ServiceError('Timeout K8s (15s)', 504)
        except requests.exceptions.RequestException as e:
            raise ServiceError(f'Erreur réseau K8s : {e}', 502)
        if resp.status_code == 401:
            raise ServiceError('Token expiré ou invalide (HTTP 401)', 401)
        if resp.status_code == 403:
            raise ServiceError(f'Accès refusé (HTTP 403)', 403)
        if resp.status_code == 404:
            return None
        if not resp.ok:
            raise ServiceError(f'API K8s HTTP {resp.status_code}', 502)
        return resp.json()

    ns_data = _get(f'/api/v1/namespaces/{namespace}')
    if ns_data is None:
        raise ServiceError(f'Namespace "{namespace}" introuvable (HTTP 404)', 404)

    # Appels parallèles (séquentiels ici mais 403 tolérés)
    lr_data      = _get(f'/api/v1/namespaces/{namespace}/limitranges')      or {'items': []}
    events_data  = _get(f'/api/v1/namespaces/{namespace}/events')           or {'items': []}
    pvc_data     = _get(f'/api/v1/namespaces/{namespace}/persistentvolumeclaims') or {'items': []}
    ing_data     = _get(f'/apis/networking.k8s.io/v1/namespaces/{namespace}/ingresses') or {'items': []}
    dep_data     = _get(f'/apis/apps/v1/namespaces/{namespace}/deployments')            or {'items': []}

    now = datetime.now(timezone.utc)

    # Nettoyage des labels/annotations K8s internes
    _skip_prefixes = ('kubernetes.io/', 'k8s.io/', 'kubectl.kubernetes.io/')

    def _clean(d: dict) -> dict:
        return {k: v for k, v in (d or {}).items()
                if not any(k.startswith(p) for p in _skip_prefixes)}

    meta = ns_data.get('metadata', {})

    # LimitRanges
    limit_ranges = []
    for lr in lr_data.get('items', []):
        lr_name = lr.get('metadata', {}).get('name', '')
        for limit in lr.get('spec', {}).get('limits', []):
            lr_type = limit.get('type', 'Container')
            all_resources = set(limit.get('max', {}) | limit.get('min', {}) |
                                limit.get('default', {}) | limit.get('defaultRequest', {}))
            for resource in sorted(all_resources):
                limit_ranges.append({
                    'lr_name':       lr_name,
                    'type':          lr_type,
                    'resource':      resource,
                    'min':           limit.get('min', {}).get(resource, '—'),
                    'max':           limit.get('max', {}).get(resource, '—'),
                    'default_limit': limit.get('default', {}).get(resource, '—'),
                    'default_req':   limit.get('defaultRequest', {}).get(resource, '—'),
                })

    # Events — triés par lastTimestamp desc, Warning en premier si même âge
    events = []
    for ev in events_data.get('items', []):
        last_ts = ev.get('lastTimestamp') or ev.get('eventTime', '')
        events.append({
            'type':    ev.get('type', 'Normal'),
            'reason':  ev.get('reason', ''),
            'object':  ev.get('involvedObject', {}).get('kind', '') + '/' +
                       ev.get('involvedObject', {}).get('name', ''),
            'message': (ev.get('message') or '')[:200],
            'count':   ev.get('count', 1),
            'age':     _fmt_age(last_ts, now),
            '_ts':     last_ts,
        })
    events.sort(key=lambda e: (0 if e['type'] == 'Warning' else 1, e['_ts']), reverse=False)
    events.sort(key=lambda e: e['_ts'], reverse=True)
    for e in events:
        del e['_ts']
    events = events[:50]

    # PVC
    pvcs = []
    for pvc in pvc_data.get('items', []):
        m = pvc.get('metadata', {})
        spec = pvc.get('spec', {})
        st = pvc.get('status', {})
        capacity = (st.get('capacity') or {}).get('storage') or \
                   (spec.get('resources') or {}).get('requests', {}).get('storage', '—')
        pvcs.append({
            'name':          m.get('name', ''),
            'phase':         st.get('phase', 'Unknown'),
            'capacity':      capacity,
            'access_modes':  ', '.join(spec.get('accessModes', [])),
            'storage_class': spec.get('storageClassName', '—'),
            'age':           _fmt_age(m.get('creationTimestamp', ''), now),
        })

    # Ingresses
    ingresses = []
    for ing in ing_data.get('items', []):
        m = ing.get('metadata', {})
        spec = ing.get('spec', {})
        ing_class = spec.get('ingressClassName') or \
                    (m.get('annotations') or {}).get('kubernetes.io/ingress.class', '—')
        rules = []
        for rule in spec.get('rules', []):
            host = rule.get('host', '*')
            for path_item in (rule.get('http') or {}).get('paths', []):
                svc = (path_item.get('backend') or {}).get('service') or {}
                port_obj = svc.get('port') or {}
                rules.append({
                    'host':    host,
                    'path':    path_item.get('path', '/'),
                    'service': svc.get('name', '—'),
                    'port':    str(port_obj.get('number') or port_obj.get('name', '—')),
                })
        ingresses.append({
            'name':  m.get('name', ''),
            'class': ing_class,
            'rules': rules,
            'tls':   [t.get('secretName', '?') for t in spec.get('tls', [])],
            'age':   _fmt_age(m.get('creationTimestamp', ''), now),
        })

    # Deployments
    deployments = []
    for dep in dep_data.get('items', []):
        m = dep.get('metadata', {})
        spec = dep.get('spec', {})
        status = dep.get('status', {})
        desired = spec.get('replicas') or 0
        deployments.append({
            'name':       m.get('name', ''),
            'desired':    desired,
            'ready':      status.get('readyReplicas') or 0,
            'available':  status.get('availableReplicas') or 0,
            'up_to_date': status.get('updatedReplicas') or 0,
            'age':        _fmt_age(m.get('creationTimestamp', ''), now),
        })

    return {
        'name':         meta.get('name', namespace),
        'status':       ns_data.get('status', {}).get('phase', 'Unknown'),
        'created':      meta.get('creationTimestamp', ''),
        'labels':       _clean(meta.get('labels')),
        'annotations':  _clean(meta.get('annotations')),
        'limit_ranges': limit_ranges,
        'deployments':  deployments,
        'events':       events,
        'pvcs':         pvcs,
        'ingresses':    ingresses,
    }
