"""
Blueprint CLPASS — gestionnaire de secrets chiffrés AES-256-GCM.

Routes :
  GET    /api/clpass/vaults                               → liste (filtrée par équipes)
  POST   /api/clpass/vaults                               → créer coffre
  PUT    /api/clpass/vaults/<vid>                         → modifier nom/desc/couleur
  DELETE /api/clpass/vaults/<vid>                         → supprimer (+ master password)
  POST   /api/clpass/vaults/<vid>/verify                  → vérifier master password
  POST   /api/clpass/vaults/<vid>/change-password         → changer master password
  GET    /api/clpass/vaults/<vid>/entries                 → liste entrées (metadata uniquement)
  POST   /api/clpass/vaults/<vid>/entries                 → créer entrée
  PUT    /api/clpass/vaults/<vid>/entries/<eid>           → modifier entrée
  DELETE /api/clpass/vaults/<vid>/entries/<eid>           → supprimer entrée
  POST   /api/clpass/vaults/<vid>/entries/<eid>/decrypt   → déchiffrer (secret + notes)
"""
import logging

from flask import Blueprint, current_app, g, jsonify, request

import services.clpass as svc
from auth import get_user_teams
from blueprints import _require_json, api_error
from services.store import ServiceError

clpass_bp = Blueprint('clpass', __name__)
logger    = logging.getLogger(__name__)


def _dd() -> str:
    return current_app.config['DATAS_DIR']


def _user():
    return g.current_user


def _team_ids() -> list:
    return [t['id'] for t in get_user_teams(_user()['id'])]


def _is_super() -> bool:
    return _user().get('role') == 'superadmin'


def _check_access(vid: str):
    """Retourne une réponse 403 si le user n'a pas accès au coffre, None sinon."""
    if _is_super():
        return None
    vault = svc.get_vault_raw(_dd(), vid)
    if not vault:
        return api_error('Coffre introuvable', 404)
    if vault.get('team_id') not in _team_ids():
        return api_error('Accès refusé à ce coffre', 403)
    return None


# ── Vaults ─────────────────────────────────────────────────────────────────────

@clpass_bp.route('/api/clpass/vaults', methods=['GET'])
def api_list_vaults():
    return jsonify({'vaults': svc.list_vaults(_dd(), _team_ids(), _is_super())})


@clpass_bp.route('/api/clpass/vaults', methods=['POST'])
def api_create_vault():
    try:
        b = _require_json()
        vault = svc.create_vault(
            _dd(),
            name=b.get('name', ''),
            description=b.get('description', ''),
            color=b.get('color', '#6a1b9a'),
            team_id=b.get('team_id', ''),
            master_pw=b.get('master_password', ''),
            created_by=_user().get('id', 'unknown'),
        )
        return jsonify({'vault': vault}), 201
    except ServiceError as e:
        return api_error(e.message, e.status)


@clpass_bp.route('/api/clpass/vaults/<vid>', methods=['PUT'])
def api_update_vault(vid):
    err = _check_access(vid)
    if err: return err
    try:
        b = _require_json()
        vault = svc.update_vault(_dd(), vid,
            name=b.get('name'), description=b.get('description'),
            color=b.get('color'), team_id=b.get('team_id'))
        return jsonify({'vault': vault})
    except ServiceError as e:
        return api_error(e.message, e.status)


@clpass_bp.route('/api/clpass/vaults/<vid>', methods=['DELETE'])
def api_delete_vault(vid):
    err = _check_access(vid)
    if err: return err
    try:
        b = _require_json()
        svc.delete_vault(_dd(), vid, master_pw=b.get('master_password', ''))
        return jsonify({'ok': True})
    except ServiceError as e:
        return api_error(e.message, e.status)


@clpass_bp.route('/api/clpass/vaults/<vid>/verify', methods=['POST'])
def api_verify_vault(vid):
    err = _check_access(vid)
    if err: return err
    try:
        b  = _require_json()
        ok = svc.verify_vault(_dd(), vid, master_pw=b.get('master_password', ''))
        return jsonify({'ok': ok})
    except ServiceError as e:
        return api_error(e.message, e.status)


@clpass_bp.route('/api/clpass/vaults/<vid>/change-password', methods=['POST'])
def api_change_vault_pw(vid):
    err = _check_access(vid)
    if err: return err
    try:
        b = _require_json()
        svc.change_vault_pw(_dd(), vid,
            old_pw=b.get('old_password', ''),
            new_pw=b.get('new_password', ''))
        return jsonify({'ok': True})
    except ServiceError as e:
        return api_error(e.message, e.status)


# ── Entries ────────────────────────────────────────────────────────────────────

@clpass_bp.route('/api/clpass/vaults/<vid>/entries', methods=['GET'])
def api_list_entries(vid):
    err = _check_access(vid)
    if err: return err
    return jsonify({'entries': svc.list_entries(_dd(), vid)})


@clpass_bp.route('/api/clpass/vaults/<vid>/entries', methods=['POST'])
def api_create_entry(vid):
    err = _check_access(vid)
    if err: return err
    try:
        b = _require_json()
        entry = svc.create_entry(
            _dd(), vid,
            master_pw=b.get('master_password', ''),
            entry_type=b.get('type', 'login'),
            title=b.get('title', ''),
            username=b.get('username', ''),
            url=b.get('url', ''),
            tags=b.get('tags', []),
            secret=b.get('secret', ''),
            notes=b.get('notes', ''),
        )
        return jsonify({'entry': entry}), 201
    except ServiceError as e:
        return api_error(e.message, e.status)


@clpass_bp.route('/api/clpass/vaults/<vid>/entries/<eid>', methods=['PUT'])
def api_update_entry(vid, eid):
    err = _check_access(vid)
    if err: return err
    try:
        b = _require_json()
        entry = svc.update_entry(
            _dd(), vid, eid,
            master_pw=b.get('master_password', ''),
            title=b.get('title'),
            username=b.get('username'),
            url=b.get('url'),
            tags=b.get('tags'),
            secret=b.get('secret'),
            notes=b.get('notes'),
        )
        return jsonify({'entry': entry})
    except ServiceError as e:
        return api_error(e.message, e.status)


@clpass_bp.route('/api/clpass/vaults/<vid>/entries/<eid>', methods=['DELETE'])
def api_delete_entry(vid, eid):
    err = _check_access(vid)
    if err: return err
    try:
        svc.delete_entry(_dd(), vid, eid)
        return jsonify({'ok': True})
    except ServiceError as e:
        return api_error(e.message, e.status)


@clpass_bp.route('/api/clpass/vaults/<vid>/entries/<eid>/decrypt', methods=['POST'])
def api_decrypt_entry(vid, eid):
    err = _check_access(vid)
    if err: return err
    try:
        b = _require_json()
        result = svc.decrypt_entry(_dd(), vid, eid, master_pw=b.get('master_password', ''))
        return jsonify(result)
    except ServiceError as e:
        return api_error(e.message, e.status)
