"""
Blueprint PSSIT : routes API pour les apps, configs, historique,
planifications, proxy AWX et JFrog.
"""
import logging

from flask import Blueprint, abort, current_app, jsonify, request

import services.pssit as pssit_service

logger = logging.getLogger(__name__)
from auth import get_ssl_verify
from blueprints import _require_json
from services.store import ServiceError

pssit_bp = Blueprint('pssit', __name__)


def _dd() -> str:
    return current_app.config['DATAS_DIR']


def _sk() -> str:
    return current_app.secret_key


# === Apps CRUD ===

@pssit_bp.route('/api/pssit/apps', methods=['GET'])
def api_get_pssit_apps():
    from auth import get_user_resources
    from flask import session
    user_resources = get_user_resources(session.get('user_id'))
    return jsonify(pssit_service.get_pssit_apps(_dd(), user_resources))


@pssit_bp.route('/api/pssit/apps', methods=['POST'])
def api_create_pssit_app():
    try:
        pssit_service.create_pssit_app(_dd(), _require_json())
        return jsonify({'success': True})
    except ServiceError as e:
        return jsonify({'error': e.message}), e.status


@pssit_bp.route('/api/pssit/apps/<app_id>', methods=['PUT'])
def api_update_pssit_app(app_id: str):
    try:
        pssit_service.update_pssit_app(_dd(), app_id, _require_json())
        return jsonify({'success': True})
    except ServiceError as e:
        return jsonify({'error': e.message}), e.status


@pssit_bp.route('/api/pssit/apps/<app_id>', methods=['DELETE'])
def api_delete_pssit_app(app_id: str):
    try:
        pssit_service.delete_pssit_app(_dd(), app_id)
        return jsonify({'success': True})
    except ServiceError as e:
        return jsonify({'error': e.message}), e.status


# === Config ===

@pssit_bp.route('/api/pssit/app/<app_id>/config', methods=['GET'])
def api_get_pssit_config(app_id: str):
    if not pssit_service.pssit_app_exists(_dd(), app_id):
        abort(404)
    return jsonify(pssit_service.get_pssit_config(_dd(), app_id))


@pssit_bp.route('/api/pssit/app/<app_id>/config', methods=['POST'])
def api_save_pssit_config(app_id: str):
    if not pssit_service.pssit_app_exists(_dd(), app_id):
        abort(404)
    pssit_service.save_pssit_config(_dd(), app_id, _require_json(), _sk())
    return jsonify({'success': True})


# === Historique & Planifications ===

@pssit_bp.route('/api/pssit/app/<app_id>/history', methods=['GET'])
def api_get_pssit_history(app_id: str):
    if not pssit_service.pssit_app_exists(_dd(), app_id):
        abort(404)
    try:
        limit = max(1, min(200, int(request.args.get('limit', 50))))
        offset = max(0, int(request.args.get('offset', 0)))
    except (ValueError, TypeError):
        limit, offset = 50, 0
    return jsonify(pssit_service.get_pssit_history(_dd(), app_id, limit=limit, offset=offset))


@pssit_bp.route('/api/pssit/app/<app_id>/schedules', methods=['GET'])
def api_get_pssit_schedules(app_id: str):
    if not pssit_service.pssit_app_exists(_dd(), app_id):
        abort(404)
    return jsonify(pssit_service.get_pssit_schedules(_dd(), app_id))


@pssit_bp.route('/api/pssit/app/<app_id>/schedules/<schedule_id>', methods=['DELETE'])
def api_cancel_pssit_schedule(app_id: str, schedule_id: str):
    if not pssit_service.pssit_app_exists(_dd(), app_id):
        abort(404)
    try:
        pssit_service.cancel_pssit_schedule(_dd(), app_id, schedule_id, _sk(), get_ssl_verify())
        return jsonify({'success': True})
    except ServiceError as e:
        return jsonify({'error': e.message}), e.status


# === Proxy AWX ===

@pssit_bp.route('/api/pssit/app/<app_id>/env/<env_id>/launch', methods=['POST'])
def api_pssit_launch(app_id: str, env_id: str):
    if not pssit_service.pssit_app_exists(_dd(), app_id):
        abort(404)
    try:
        entry = pssit_service.launch_pssit_workflow(_dd(), app_id, env_id, _require_json(), _sk(), get_ssl_verify())
        return jsonify(entry)
    except ServiceError as e:
        return jsonify({'error': e.message}), e.status


@pssit_bp.route('/api/pssit/app/<app_id>/env/<env_id>/job/<int:awx_job_id>/status', methods=['GET'])
def api_pssit_job_status(app_id: str, env_id: str, awx_job_id: int):
    if not pssit_service.pssit_app_exists(_dd(), app_id):
        abort(404)
    try:
        result = pssit_service.get_pssit_job_status(_dd(), app_id, env_id, awx_job_id, _sk(), get_ssl_verify())
        return jsonify(result)
    except ServiceError as e:
        return jsonify({'error': e.message}), e.status
    except Exception:
        logger.exception('Erreur inattendue lors de get_pssit_job_status app=%s env=%s job=%s', app_id, env_id, awx_job_id)
        return jsonify({'error': 'Erreur interne, veuillez réessayer.'}), 502


@pssit_bp.route('/api/pssit/app/<app_id>/env/<env_id>/schedule', methods=['POST'])
def api_pssit_schedule(app_id: str, env_id: str):
    if not pssit_service.pssit_app_exists(_dd(), app_id):
        abort(404)
    try:
        entry = pssit_service.schedule_pssit_action(_dd(), app_id, env_id, _require_json(), _sk(), get_ssl_verify())
        return jsonify(entry)
    except ServiceError as e:
        return jsonify({'error': e.message}), e.status
    except Exception:
        logger.exception('Erreur inattendue lors de schedule_pssit_action app=%s env=%s', app_id, env_id)
        return jsonify({'error': 'Erreur interne, veuillez réessayer.'}), 502


# === Proxy JFrog ===

@pssit_bp.route('/api/pssit/app/<app_id>/env/<env_id>/artifacts', methods=['GET'])
def api_pssit_artifacts(app_id: str, env_id: str):
    if not pssit_service.pssit_app_exists(_dd(), app_id):
        abort(404)
    try:
        artifacts = pssit_service.get_pssit_artifacts(_dd(), app_id, env_id, _sk(), get_ssl_verify())
        return jsonify(artifacts)
    except ServiceError as e:
        return jsonify({'error': e.message}), e.status
    except Exception:
        logger.exception('Erreur inattendue lors de get_pssit_artifacts app=%s env=%s', app_id, env_id)
        return jsonify({'error': 'Erreur interne, veuillez réessayer.'}), 502
