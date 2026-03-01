"""
Blueprint SRE : routes API pour les clusters, configurations, données, autoscores.
"""
from flask import Blueprint, abort, current_app, jsonify, request

import services.sre as sre_service
from services.store import ServiceError

sre_bp = Blueprint('sre', __name__)


def _dd() -> str:
    """Raccourci pour current_app.config['DATAS_DIR']."""
    return current_app.config['DATAS_DIR']


# === Clusters CRUD ===

@sre_bp.route('/api/clusters', methods=['GET'])
def api_get_clusters():
    from auth import get_user_resources
    from flask import session
    user_resources = get_user_resources(session.get('user_id'))
    return jsonify(sre_service.get_clusters(_dd(), user_resources))


@sre_bp.route('/api/clusters', methods=['POST'])
def api_create_cluster():
    try:
        sre_service.create_cluster(_dd(), request.json)
        return jsonify({'success': True})
    except ServiceError as e:
        return jsonify({'error': e.message}), e.status


@sre_bp.route('/api/clusters/<cluster_id>', methods=['PUT'])
def api_update_cluster(cluster_id: str):
    try:
        sre_service.update_cluster(_dd(), cluster_id, request.json)
        return jsonify({'success': True})
    except ServiceError as e:
        return jsonify({'error': e.message}), e.status


@sre_bp.route('/api/clusters/<cluster_id>', methods=['DELETE'])
def api_delete_cluster(cluster_id: str):
    try:
        sre_service.delete_cluster(_dd(), cluster_id)
        return jsonify({'success': True})
    except ServiceError as e:
        return jsonify({'error': e.message}), e.status


# === Config ===

@sre_bp.route('/api/cluster/<cluster_id>/config', methods=['GET'])
def api_get_config(cluster_id: str):
    if not sre_service.cluster_exists(_dd(), cluster_id):
        abort(404)
    return jsonify(sre_service.get_cluster_config(_dd(), cluster_id))


@sre_bp.route('/api/cluster/<cluster_id>/config', methods=['POST'])
def api_save_config(cluster_id: str):
    if not sre_service.cluster_exists(_dd(), cluster_id):
        abort(404)
    sre_service.save_cluster_config(_dd(), cluster_id, request.json)
    return jsonify({'success': True})


# === Data ===

@sre_bp.route('/api/cluster/<cluster_id>/data', methods=['GET'])
def api_get_data(cluster_id: str):
    if not sre_service.cluster_exists(_dd(), cluster_id):
        abort(404)
    return jsonify(sre_service.get_cluster_data(_dd(), cluster_id))


@sre_bp.route('/api/cluster/<cluster_id>/data', methods=['POST'])
def api_save_data(cluster_id: str):
    if not sre_service.cluster_exists(_dd(), cluster_id):
        abort(404)
    sre_service.save_cluster_data(_dd(), cluster_id, request.json)
    return jsonify({'success': True})


# === Autoscore ===

@sre_bp.route('/api/cluster/<cluster_id>/autoscore/<app_code>', methods=['GET'])
def api_get_autoscore(cluster_id: str, app_code: str):
    if not sre_service.cluster_exists(_dd(), cluster_id):
        abort(404)
    return jsonify(sre_service.get_autoscore(_dd(), cluster_id, app_code))


@sre_bp.route('/api/cluster/<cluster_id>/autoscore/<app_code>', methods=['POST'])
def api_save_autoscore(cluster_id: str, app_code: str):
    if not sre_service.cluster_exists(_dd(), cluster_id):
        abort(404)
    sre_service.save_autoscore(_dd(), cluster_id, app_code, request.json)
    return jsonify({'success': True})


# === Autoscore Config ===

@sre_bp.route('/api/cluster/<cluster_id>/autoscore-config', methods=['GET'])
def api_get_autoscore_config(cluster_id: str):
    if not sre_service.cluster_exists(_dd(), cluster_id):
        abort(404)
    return jsonify(sre_service.get_autoscore_config(_dd(), cluster_id))


@sre_bp.route('/api/cluster/<cluster_id>/autoscore-config', methods=['POST'])
def api_save_autoscore_config(cluster_id: str):
    if not sre_service.cluster_exists(_dd(), cluster_id):
        abort(404)
    sre_service.save_autoscore_config(_dd(), cluster_id, request.json)
    return jsonify({'success': True})
