"""
Blueprint CAD : routes API pour les workspaces, configurations et données.
"""
from flask import Blueprint, abort, current_app, jsonify, request

import services.cad as cad_service
from services.store import ServiceError

cad_bp = Blueprint('cad', __name__)


def _dd() -> str:
    return current_app.config['DATAS_DIR']


# === Workspaces CRUD ===

@cad_bp.route('/api/cad/workspaces', methods=['GET'])
def api_get_cad_workspaces():
    from auth import get_user_resources
    from flask import session
    user_resources = get_user_resources(session.get('user_id'))
    return jsonify(cad_service.get_cad_workspaces(_dd(), user_resources))


@cad_bp.route('/api/cad/workspaces', methods=['POST'])
def api_create_cad_workspace():
    try:
        cad_service.create_cad_workspace(_dd(), request.json)
        return jsonify({'success': True})
    except ServiceError as e:
        return jsonify({'error': e.message}), e.status


@cad_bp.route('/api/cad/workspaces/<ws_id>', methods=['PUT'])
def api_update_cad_workspace(ws_id: str):
    try:
        cad_service.update_cad_workspace(_dd(), ws_id, request.json)
        return jsonify({'success': True})
    except ServiceError as e:
        return jsonify({'error': e.message}), e.status


@cad_bp.route('/api/cad/workspaces/<ws_id>', methods=['DELETE'])
def api_delete_cad_workspace(ws_id: str):
    try:
        cad_service.delete_cad_workspace(_dd(), ws_id)
        return jsonify({'success': True})
    except ServiceError as e:
        return jsonify({'error': e.message}), e.status


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
    cad_service.save_cad_config(_dd(), ws_id, request.json)
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
    cad_service.save_cad_data(_dd(), ws_id, request.json)
    return jsonify({'success': True})
