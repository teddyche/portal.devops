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


# === K8s API — Quotas ===

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
