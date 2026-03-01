"""
Logique métier du module SRE : clusters, configuration, données, autoscore.
Toutes les fonctions reçoivent datas_dir en paramètre pour la testabilité.
"""
import os
from datetime import date
from typing import Any, Optional

from services import store
from services.store import ServiceError


# === Helpers chemins ===

def _clusters_file(datas_dir: str) -> str:
    return os.path.join(datas_dir, 'clusters.json')


def _cluster_dir(datas_dir: str, cluster_id: str) -> str:
    return os.path.join(datas_dir, cluster_id)


def _trash_dir(datas_dir: str) -> str:
    return os.path.join(datas_dir, '_trash')


def _default_config() -> dict:
    from migrate import DEFAULT_CONFIG
    return DEFAULT_CONFIG


def _default_autoscore_config() -> dict:
    from migrate import DEFAULT_AUTOSCORE_CONFIG
    return DEFAULT_AUTOSCORE_CONFIG


# === Clusters CRUD ===

def cluster_exists(datas_dir: str, cluster_id: str) -> bool:
    clusters: list[dict] = store.load_json(_clusters_file(datas_dir)) or []
    return any(c['id'] == cluster_id for c in clusters)


def get_clusters(datas_dir: str, user_resources: Optional[list[dict]] = None) -> list[dict]:
    clusters: list[dict] = store.load_json(_clusters_file(datas_dir)) or []
    if user_resources is not None:
        allowed = {r['resource_id'] for r in user_resources if r['module'] == 'sre'}
        clusters = [c for c in clusters if c['id'] in allowed]
    return clusters


def create_cluster(datas_dir: str, body: dict) -> None:
    cid = body.get('id', '').strip()
    name = body.get('name', '').strip()
    desc = body.get('description', '').strip()

    if not cid or not store.safe_id(cid):
        raise ServiceError('ID invalide (alphanum, tirets, underscores)')

    cf = _clusters_file(datas_dir)
    clusters: list[dict] = store.load_json(cf) or []
    if any(c['id'] == cid for c in clusters):
        raise ServiceError('Ce cluster existe déjà')

    cluster_dir = _cluster_dir(datas_dir, cid)
    os.makedirs(os.path.join(cluster_dir, 'autoscore'), exist_ok=True)
    store.save_json(os.path.join(cluster_dir, 'config.json'), _default_config())
    store.save_json(os.path.join(cluster_dir, 'autoscore_config.json'), _default_autoscore_config())
    store.save_json(os.path.join(cluster_dir, 'data.json'), [])

    clusters.append({'id': cid, 'name': name or cid, 'description': desc, 'created': date.today().isoformat()})
    store.save_json(cf, clusters)


def update_cluster(datas_dir: str, cluster_id: str, body: dict) -> None:
    cf = _clusters_file(datas_dir)
    clusters: list[dict] = store.load_json(cf) or []
    cluster = next((c for c in clusters if c['id'] == cluster_id), None)
    if not cluster:
        raise ServiceError('Cluster non trouvé', 404)
    if 'name' in body:
        cluster['name'] = body['name']
    if 'description' in body:
        cluster['description'] = body['description']
    store.save_json(cf, clusters)


def delete_cluster(datas_dir: str, cluster_id: str) -> None:
    cf = _clusters_file(datas_dir)
    clusters: list[dict] = store.load_json(cf) or []
    if not any(c['id'] == cluster_id for c in clusters):
        raise ServiceError('Cluster non trouvé', 404)
    clusters = [c for c in clusters if c['id'] != cluster_id]
    store.save_json(cf, clusters)
    store.soft_delete_dir(_cluster_dir(datas_dir, cluster_id), 'cluster', _trash_dir(datas_dir))


# === Config ===

def get_cluster_config(datas_dir: str, cluster_id: str) -> dict:
    path = os.path.join(_cluster_dir(datas_dir, cluster_id), 'config.json')
    return store.load_json(path) or {}


def save_cluster_config(datas_dir: str, cluster_id: str, config: Any) -> None:
    path = os.path.join(_cluster_dir(datas_dir, cluster_id), 'config.json')
    store.save_json(path, config)


# === Data ===

def get_cluster_data(datas_dir: str, cluster_id: str) -> list:
    path = os.path.join(_cluster_dir(datas_dir, cluster_id), 'data.json')
    return store.load_json(path) or []


def save_cluster_data(datas_dir: str, cluster_id: str, data: Any) -> None:
    path = os.path.join(_cluster_dir(datas_dir, cluster_id), 'data.json')
    store.save_json(path, data)


# === Autoscore ===

def get_autoscore(datas_dir: str, cluster_id: str, app_code: str) -> dict:
    path = os.path.join(_cluster_dir(datas_dir, cluster_id), 'autoscore', f'{app_code}.json')
    return store.load_json(path) or {}


def save_autoscore(datas_dir: str, cluster_id: str, app_code: str, autoscore_data: dict) -> None:
    cluster_dir = _cluster_dir(datas_dir, cluster_id)
    as_path = os.path.join(cluster_dir, 'autoscore', f'{app_code}.json')
    store.save_json(as_path, autoscore_data)

    # Synchronise score et note dans data.json
    data_path = os.path.join(cluster_dir, 'data.json')
    apps: list[dict] = store.load_json(data_path) or []
    score = autoscore_data.get('score', 0)
    note = autoscore_data.get('note', '')
    for app_entry in apps:
        if app_entry.get('code') == app_code:
            app_entry['score'] = score
            app_entry['note'] = note
            break
    store.save_json(data_path, apps)


# === Autoscore Config ===

def get_autoscore_config(datas_dir: str, cluster_id: str) -> dict:
    path = os.path.join(_cluster_dir(datas_dir, cluster_id), 'autoscore_config.json')
    config = store.load_json(path)
    if config is None:
        config = _default_autoscore_config()
        store.save_json(path, config)
    return config


def save_autoscore_config(datas_dir: str, cluster_id: str, data: Any) -> None:
    if not data or not isinstance(data, dict):
        data = _default_autoscore_config()
    path = os.path.join(_cluster_dir(datas_dir, cluster_id), 'autoscore_config.json')
    store.save_json(path, data)
