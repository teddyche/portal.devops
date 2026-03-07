"""
Blueprint PSSIT : routes API pour les apps, configs, historique,
planifications, proxy AWX et JFrog.
"""
import logging

from flask import Blueprint, abort, current_app, jsonify, request, session

import services.pssit as pssit_service
from auth import get_ssl_verify
from blueprints import _require_json, api_error
from services.store import ServiceError

pssit_bp = Blueprint('pssit', __name__)
logger = logging.getLogger(__name__)
_audit = logging.getLogger('audit')


def _dd() -> str:
    return current_app.config['DATAS_DIR']


def _sk() -> str:
    return current_app.secret_key


def _uid() -> str:
    return session.get('user_id', 'anonymous')


# === Apps CRUD ===

@pssit_bp.route('/api/pssit/apps', methods=['GET'])
def api_get_pssit_apps():
    """
    Liste les apps PSSIT accessibles à l'utilisateur courant.
    ---
    tags: [PSSIT]
    responses:
      200:
        description: Liste des apps
    """
    from auth import get_user_resources
    user_resources = get_user_resources(_uid())
    return jsonify(pssit_service.get_pssit_apps(_dd(), user_resources))


@pssit_bp.route('/api/pssit/apps', methods=['POST'])
def api_create_pssit_app():
    try:
        body = _require_json()
        pssit_service.create_pssit_app(_dd(), body)
        _audit.info('pssit_app_created user=%s id=%s', _uid(), body.get('id', '?'))
        return jsonify({'success': True})
    except ServiceError as e:
        return api_error(e.message, e.status)


@pssit_bp.route('/api/pssit/apps/<app_id>', methods=['PUT'])
def api_update_pssit_app(app_id: str):
    try:
        pssit_service.update_pssit_app(_dd(), app_id, _require_json())
        _audit.info('pssit_app_updated user=%s id=%s', _uid(), app_id)
        return jsonify({'success': True})
    except ServiceError as e:
        return api_error(e.message, e.status)


@pssit_bp.route('/api/pssit/apps/<app_id>', methods=['DELETE'])
def api_delete_pssit_app(app_id: str):
    try:
        pssit_service.delete_pssit_app(_dd(), app_id)
        _audit.info('pssit_app_deleted user=%s id=%s', _uid(), app_id)
        return jsonify({'success': True})
    except ServiceError as e:
        return api_error(e.message, e.status)


# === Config ===

@pssit_bp.route('/api/pssit/app/<app_id>/config', methods=['GET'])
def api_get_pssit_config(app_id: str):
    if not pssit_service.pssit_app_exists(_dd(), app_id):
        abort(404)
    return jsonify(pssit_service.get_pssit_config(_dd(), app_id, _sk()))


@pssit_bp.route('/api/pssit/app/<app_id>/config', methods=['POST'])
def api_save_pssit_config(app_id: str):
    if not pssit_service.pssit_app_exists(_dd(), app_id):
        abort(404)
    pssit_service.save_pssit_config(_dd(), app_id, _require_json(), _sk())
    _audit.info('pssit_config_saved user=%s app=%s', _uid(), app_id)
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
        _audit.info('pssit_schedule_cancelled user=%s app=%s schedule=%s', _uid(), app_id, schedule_id)
        return jsonify({'success': True})
    except ServiceError as e:
        return api_error(e.message, e.status)


# === Proxy AWX ===

@pssit_bp.route('/api/pssit/app/<app_id>/env/<env_id>/launch', methods=['POST'])
def api_pssit_launch(app_id: str, env_id: str):
    if not pssit_service.pssit_app_exists(_dd(), app_id):
        abort(404)
    try:
        entry = pssit_service.launch_pssit_workflow(_dd(), app_id, env_id, _require_json(), _sk(), get_ssl_verify())
        _audit.info('pssit_workflow_launched user=%s app=%s env=%s action=%s', _uid(), app_id, env_id, entry.get('action'))
        return jsonify(entry)
    except ServiceError as e:
        return api_error(e.message, e.status)


@pssit_bp.route('/api/pssit/app/<app_id>/env/<env_id>/job/<int:awx_job_id>/status', methods=['GET'])
def api_pssit_job_status(app_id: str, env_id: str, awx_job_id: int):
    if not pssit_service.pssit_app_exists(_dd(), app_id):
        abort(404)
    job_type = request.args.get('type', 'workflow_job')
    try:
        result = pssit_service.get_pssit_job_status(_dd(), app_id, env_id, awx_job_id, _sk(), get_ssl_verify(), job_type=job_type)
        return jsonify(result)
    except ServiceError as e:
        return api_error(e.message, e.status)
    except Exception:
        logger.exception('Erreur inattendue lors de get_pssit_job_status app=%s env=%s job=%s', app_id, env_id, awx_job_id)
        return api_error('Erreur interne, veuillez réessayer.', 502)


@pssit_bp.route('/api/pssit/app/<app_id>/env/<env_id>/schedule', methods=['POST'])
def api_pssit_schedule(app_id: str, env_id: str):
    if not pssit_service.pssit_app_exists(_dd(), app_id):
        abort(404)
    try:
        entry = pssit_service.schedule_pssit_action(_dd(), app_id, env_id, _require_json(), _sk(), get_ssl_verify())
        _audit.info('pssit_scheduled user=%s app=%s env=%s action=%s', _uid(), app_id, env_id, entry.get('action'))
        return jsonify(entry)
    except ServiceError as e:
        return api_error(e.message, e.status)
    except Exception:
        logger.exception('Erreur inattendue lors de schedule_pssit_action app=%s env=%s', app_id, env_id)
        return api_error('Erreur interne, veuillez réessayer.', 502)


# === Proxy JFrog ===

@pssit_bp.route('/api/pssit/app/<app_id>/env/<env_id>/artifacts', methods=['GET'])
def api_pssit_artifacts(app_id: str, env_id: str):
    if not pssit_service.pssit_app_exists(_dd(), app_id):
        abort(404)
    try:
        artifacts = pssit_service.get_pssit_artifacts(_dd(), app_id, env_id, _sk(), get_ssl_verify())
        return jsonify(artifacts)
    except ServiceError as e:
        return api_error(e.message, e.status)
    except Exception:
        logger.exception('Erreur inattendue lors de get_pssit_artifacts app=%s env=%s', app_id, env_id)
        return api_error('Erreur interne, veuillez réessayer.', 502)


@pssit_bp.route('/api/pssit/app/<app_id>/env/<env_id>/versions', methods=['GET'])
def api_pssit_versions(app_id: str, env_id: str):
    """Liste les versions disponibles (répertoires feuilles contenant des fichiers) dans le chemin JFrog configuré."""
    if not pssit_service.pssit_app_exists(_dd(), app_id):
        abort(404)
    try:
        versions = pssit_service.get_pssit_versions(_dd(), app_id, env_id, _sk(), get_ssl_verify())
        return jsonify(versions)
    except ServiceError as e:
        return api_error(e.message, e.status)
    except Exception:
        logger.exception('Erreur inattendue lors de get_pssit_versions app=%s env=%s', app_id, env_id)
        return api_error('Erreur interne, veuillez réessayer.', 502)


@pssit_bp.route('/api/pssit/app/<app_id>/env/<env_id>/awx-templates', methods=['GET'])
def api_pssit_awx_templates(app_id: str, env_id: str):
    """Liste les Workflow Job Templates et Job Templates disponibles dans AWX."""
    if not pssit_service.pssit_app_exists(_dd(), app_id):
        abort(404)
    try:
        result = pssit_service.browse_awx_templates(_dd(), app_id, env_id, _sk(), get_ssl_verify())
        return jsonify(result)
    except ServiceError as e:
        return api_error(e.message, e.status)
    except Exception:
        logger.exception('Erreur browse AWX templates app=%s env=%s', app_id, env_id)
        return api_error('Erreur interne', 502)


@pssit_bp.route('/api/pssit/app/<app_id>/env/<env_id>/jfrog-browse', methods=['GET'])
def api_pssit_jfrog_browse(app_id: str, env_id: str):
    """Navigation dans l'arborescence JFrog : liste des repos ou contenu d'un dossier."""
    if not pssit_service.pssit_app_exists(_dd(), app_id):
        abort(404)
    repo = request.args.get('repo', '').strip()
    path = request.args.get('path', '').strip()
    filter_text = request.args.get('filter', '').strip()
    try:
        result = pssit_service.browse_jfrog_path(
            _dd(), app_id, env_id, _sk(), get_ssl_verify(), repo, path, filter_text
        )
        return jsonify(result)
    except ServiceError as e:
        return api_error(e.message, e.status)
    except Exception:
        logger.exception('Erreur browse JFrog app=%s env=%s', app_id, env_id)
        return api_error('Erreur interne', 502)
