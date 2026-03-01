"""
Blueprint CAD : routes API pour les workspaces, configurations et données.
"""
import logging

from flask import Blueprint, abort, current_app, jsonify, request, session

import services.cad as cad_service
from blueprints import _require_json, api_error
from services.store import ServiceError

cad_bp = Blueprint('cad', __name__)
_audit = logging.getLogger('audit')


def _dd() -> str:
    return current_app.config['DATAS_DIR']


def _uid() -> str:
    return session.get('user_id', 'anonymous')


# === Workspaces CRUD ===

@cad_bp.route('/api/cad/workspaces', methods=['GET'])
def api_get_cad_workspaces():
    """
    Liste les workspaces CAD accessibles à l'utilisateur courant.
    ---
    tags: [CAD]
    responses:
      200:
        description: Liste des workspaces
    """
    from auth import get_user_resources
    user_resources = get_user_resources(_uid())
    return jsonify(cad_service.get_cad_workspaces(_dd(), user_resources))


@cad_bp.route('/api/cad/workspaces', methods=['POST'])
def api_create_cad_workspace():
    try:
        body = _require_json()
        cad_service.create_cad_workspace(_dd(), body)
        _audit.info('cad_workspace_created user=%s id=%s', _uid(), body.get('id', '?'))
        return jsonify({'success': True})
    except ServiceError as e:
        return api_error(e.message, e.status)


@cad_bp.route('/api/cad/workspaces/<ws_id>', methods=['PUT'])
def api_update_cad_workspace(ws_id: str):
    try:
        cad_service.update_cad_workspace(_dd(), ws_id, _require_json())
        _audit.info('cad_workspace_updated user=%s id=%s', _uid(), ws_id)
        return jsonify({'success': True})
    except ServiceError as e:
        return api_error(e.message, e.status)


@cad_bp.route('/api/cad/workspaces/<ws_id>', methods=['DELETE'])
def api_delete_cad_workspace(ws_id: str):
    try:
        cad_service.delete_cad_workspace(_dd(), ws_id)
        _audit.info('cad_workspace_deleted user=%s id=%s', _uid(), ws_id)
        return jsonify({'success': True})
    except ServiceError as e:
        return api_error(e.message, e.status)


# === Config & Data ===

@cad_bp.route('/api/cad/workspace/<ws_id>/config', methods=['GET'])
def api_get_cad_config(ws_id: str):
    if not cad_service.cad_ws_exists(_dd(), ws_id):
        abort(404)
    return jsonify(cad_service.get_cad_config(_dd(), ws_id))


@cad_bp.route('/api/cad/workspace/<ws_id>/config', methods=['POST'])
def api_save_cad_config(ws_id: str):
    if not cad_service.cad_ws_exists(_dd(), ws_id):
        abort(404)
    cad_service.save_cad_config(_dd(), ws_id, _require_json())
    _audit.info('cad_config_saved user=%s id=%s', _uid(), ws_id)
    return jsonify({'success': True})


@cad_bp.route('/api/cad/workspace/<ws_id>/data', methods=['GET'])
def api_get_cad_data(ws_id: str):
    if not cad_service.cad_ws_exists(_dd(), ws_id):
        abort(404)
    return jsonify(cad_service.get_cad_data(_dd(), ws_id))


@cad_bp.route('/api/cad/workspace/<ws_id>/data', methods=['POST'])
def api_save_cad_data(ws_id: str):
    if not cad_service.cad_ws_exists(_dd(), ws_id):
        abort(404)
    cad_service.save_cad_data(_dd(), ws_id, _require_json())
    _audit.info('cad_data_saved user=%s id=%s', _uid(), ws_id)
    return jsonify({'success': True})
