"""
Blueprint SRE : routes API pour les clusters, configurations, données, autoscores.
"""
import logging

from flask import Blueprint, abort, current_app, jsonify, request, session

import services.sre as sre_service
from blueprints import _require_json, api_error
from services.store import ServiceError

sre_bp = Blueprint('sre', __name__)
_audit = logging.getLogger('audit')


def _dd() -> str:
    """Raccourci pour current_app.config['DATAS_DIR']."""
    return current_app.config['DATAS_DIR']


def _uid() -> str:
    """Retourne le user_id de la session courante."""
    return session.get('user_id', 'anonymous')


# === Clusters CRUD ===

@sre_bp.route('/api/clusters', methods=['GET'])
def api_get_clusters():
    """
    Liste les clusters accessibles à l'utilisateur courant.
    ---
    tags: [SRE]
    responses:
      200:
        description: Liste des clusters
    """
    from auth import get_user_resources
    user_resources = get_user_resources(_uid())
    return jsonify(sre_service.get_clusters(_dd(), user_resources))


@sre_bp.route('/api/clusters', methods=['POST'])
def api_create_cluster():
    """
    Crée un nouveau cluster.
    ---
    tags: [SRE]
    responses:
      200:
        description: Cluster créé
      400:
        description: Données invalides
    """
    try:
        body = _require_json()
        sre_service.create_cluster(_dd(), body)
        _audit.info('cluster_created user=%s id=%s', _uid(), body.get('id', '?'))
        return jsonify({'success': True})
    except ServiceError as e:
        return api_error(e.message, e.status)


@sre_bp.route('/api/clusters/<cluster_id>', methods=['PUT'])
def api_update_cluster(cluster_id: str):
    try:
        sre_service.update_cluster(_dd(), cluster_id, _require_json())
        _audit.info('cluster_updated user=%s id=%s', _uid(), cluster_id)
        return jsonify({'success': True})
    except ServiceError as e:
        return api_error(e.message, e.status)


@sre_bp.route('/api/clusters/<cluster_id>', methods=['DELETE'])
def api_delete_cluster(cluster_id: str):
    try:
        sre_service.delete_cluster(_dd(), cluster_id)
        _audit.info('cluster_deleted user=%s id=%s', _uid(), cluster_id)
        return jsonify({'success': True})
    except ServiceError as e:
        return api_error(e.message, e.status)


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
    sre_service.save_cluster_config(_dd(), cluster_id, _require_json())
    _audit.info('cluster_config_saved user=%s id=%s', _uid(), cluster_id)
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
    sre_service.save_cluster_data(_dd(), cluster_id, _require_json())
    _audit.info('cluster_data_saved user=%s id=%s', _uid(), cluster_id)
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
    sre_service.save_autoscore(_dd(), cluster_id, app_code, _require_json())
    _audit.info('autoscore_saved user=%s cluster=%s app=%s', _uid(), cluster_id, app_code)
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
    sre_service.save_autoscore_config(_dd(), cluster_id, _require_json())
    _audit.info('autoscore_config_saved user=%s cluster=%s', _uid(), cluster_id)
    return jsonify({'success': True})
