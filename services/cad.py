"""
Logique métier du module CAD : workspaces, configuration, données.
"""
import os
from datetime import date
from typing import Any, Optional

from services import store
from services.base import entity_exists, filter_by_resources, remove_from_list
from services.store import ServiceError


# === Helpers chemins ===

def _workspaces_file(datas_dir: str) -> str:
    return os.path.join(datas_dir, 'cad_workspaces.json')


def _ws_dir(datas_dir: str, ws_id: str) -> str:
    return os.path.join(datas_dir, 'cad', ws_id)


def _trash_dir(datas_dir: str) -> str:
    return os.path.join(datas_dir, '_trash')


def _default_cad_config() -> dict:
    from migrate import DEFAULT_CAD_CONFIG
    return DEFAULT_CAD_CONFIG


# === Workspaces CRUD ===

def cad_ws_exists(datas_dir: str, ws_id: str) -> bool:
    return entity_exists(_workspaces_file(datas_dir), ws_id)


def get_cad_workspaces(datas_dir: str, user_resources: Optional[list[dict]] = None) -> list[dict]:
    workspaces: list[dict] = store.load_json(_workspaces_file(datas_dir)) or []
    return filter_by_resources(workspaces, user_resources, 'cad')


def create_cad_workspace(datas_dir: str, body: dict) -> None:
    wid = body.get('id', '').strip().upper()
    name = body.get('name', '').strip()
    desc = body.get('description', '').strip()

    if not wid or not store.safe_id(wid):
        raise ServiceError('ID invalide')

    wf = _workspaces_file(datas_dir)
    workspaces: list[dict] = store.load_json(wf) or []
    if any(w['id'] == wid for w in workspaces):
        raise ServiceError('Ce workspace existe déjà')

    ws_dir = _ws_dir(datas_dir, wid)
    os.makedirs(ws_dir, exist_ok=True)
    store.save_json(os.path.join(ws_dir, 'config.json'), _default_cad_config())
    store.save_json(os.path.join(ws_dir, 'data.json'), [])

    workspaces.append({'id': wid, 'name': name or wid, 'description': desc, 'created': date.today().isoformat()})
    store.save_json(wf, workspaces)


def update_cad_workspace(datas_dir: str, ws_id: str, body: dict) -> None:
    wf = _workspaces_file(datas_dir)
    workspaces: list[dict] = store.load_json(wf) or []
    ws = next((w for w in workspaces if w['id'] == ws_id), None)
    if not ws:
        raise ServiceError('Workspace non trouvé', 404)
    if 'name' in body:
        ws['name'] = body['name']
    if 'description' in body:
        ws['description'] = body['description']
    store.save_json(wf, workspaces)


def delete_cad_workspace(datas_dir: str, ws_id: str) -> None:
    remove_from_list(_workspaces_file(datas_dir), ws_id, 'Workspace non trouvé')
    store.soft_delete_dir(_ws_dir(datas_dir, ws_id), 'cad_workspace', _trash_dir(datas_dir))


# === Config ===

def get_cad_config(datas_dir: str, ws_id: str) -> dict:
    path = os.path.join(_ws_dir(datas_dir, ws_id), 'config.json')
    return store.load_json(path) or {}


def save_cad_config(datas_dir: str, ws_id: str, config: Any) -> None:
    path = os.path.join(_ws_dir(datas_dir, ws_id), 'config.json')
    store.save_json(path, config)


# === Data ===

def get_cad_data(datas_dir: str, ws_id: str) -> list:
    path = os.path.join(_ws_dir(datas_dir, ws_id), 'data.json')
    return store.load_json(path) or []


def save_cad_data(datas_dir: str, ws_id: str, data: Any) -> None:
    path = os.path.join(_ws_dir(datas_dir, ws_id), 'data.json')
    store.save_json(path, data)
