"""
Blueprint GitLab — consultation des tokens et accès API.

Routes :
  GET  /api/gitlab/config              → config (url, insecure — token masqué)
  POST /api/gitlab/config              → sauvegarde config
  POST /api/gitlab/test                → test de connexion
  POST /api/gitlab/tokens              → liste tous les tokens avec expiration
  POST /api/gitlab/snapshots           → sauvegarde un snapshot + purge anciens
  GET  /api/gitlab/snapshots           → liste les snapshots disponibles
  GET  /api/gitlab/snapshots/<sid>     → retourne un snapshot complet
"""
import logging

from flask import Blueprint, current_app, jsonify, session

import services.gitlab_svc as gitlab_service
from blueprints import _require_json, api_error
from services.store import ServiceError

gitlab_bp = Blueprint('gitlab', __name__)
logger = logging.getLogger(__name__)
_audit = logging.getLogger('audit')


def _dd() -> str:
    return current_app.config['DATAS_DIR']


def _uid() -> str:
    return session.get('user_id', 'anonymous')


# === Config ===

@gitlab_bp.route('/api/gitlab/config', methods=['GET'])
def api_get_gitlab_config():
    """Retourne la config GitLab (token masqué)."""
    cfg = gitlab_service.get_gitlab_config(_dd())
    # Masque le token pour l'affichage — ne retourne que les 4 derniers chars
    raw_token = cfg.get('token', '')
    masked = ('•' * (len(raw_token) - 4) + raw_token[-4:]) if len(raw_token) > 4 else '•' * len(raw_token)
    return jsonify({
        'url':      cfg.get('url', ''),
        'token':    masked,
        'has_token': bool(raw_token),
        'insecure': cfg.get('insecure', False),
    })


@gitlab_bp.route('/api/gitlab/config', methods=['POST'])
def api_save_gitlab_config():
    """Sauvegarde la config GitLab."""
    try:
        body = _require_json()
        # Si le token envoyé est le masque (•••), on garde l'ancien
        sent_token = body.get('token', '').strip()
        if set(sent_token) <= {'•'}:
            existing = gitlab_service.get_gitlab_config(_dd())
            body['token'] = existing.get('token', '')
        gitlab_service.save_gitlab_config(_dd(), body)
        _audit.info('gitlab_config_saved user=%s', _uid())
        return jsonify({'success': True})
    except ServiceError as e:
        return api_error(e.message, e.status)


# === Test connexion ===

@gitlab_bp.route('/api/gitlab/test', methods=['POST'])
def api_gitlab_test():
    """Teste la connexion GitLab et retourne les infos du token configuré."""
    try:
        cfg = gitlab_service.get_gitlab_config(_dd())
        if not cfg.get('url') or not cfg.get('token'):
            return api_error('GitLab non configuré — renseigner l\'URL et le token dans Config', 400)
        result = gitlab_service.test_connection(
            cfg['url'], cfg['token'], cfg.get('insecure', False)
        )
        return jsonify(result)
    except ServiceError as e:
        return api_error(e.message, e.status)


# === Tokens ===

@gitlab_bp.route('/api/gitlab/tokens', methods=['POST'])
def api_gitlab_tokens():
    """
    Liste tous les tokens GitLab accessibles avec leur date d'expiration.
    Triés : expirés en premier, puis par date d'expiration croissante.
    """
    try:
        cfg = gitlab_service.get_gitlab_config(_dd())
        if not cfg.get('url') or not cfg.get('token'):
            return api_error('GitLab non configuré — renseigner l\'URL et le token dans Config', 400)
        result = gitlab_service.get_all_tokens(
            cfg['url'], cfg['token'], cfg.get('insecure', False)
        )
        _audit.info('gitlab_tokens_fetched user=%s total=%d', _uid(), result['stats']['total'])
        return jsonify(result)
    except ServiceError as e:
        return api_error(e.message, e.status)


# === Snapshots ===

@gitlab_bp.route('/api/gitlab/snapshots', methods=['POST'])
def api_gitlab_snapshot_save():
    """Sauvegarde un snapshot des tokens et purge les anciens selon retention_days."""
    try:
        body = _require_json()
        tokens = body.get('tokens', [])
        stats  = body.get('stats', {})
        if not isinstance(tokens, list):
            return api_error('tokens doit être une liste', 400)

        cfg = gitlab_service.get_gitlab_config(_dd())
        retention = cfg.get('retention_days', 30)

        sid = gitlab_service.save_snapshot(_dd(), tokens, stats)
        purged = gitlab_service.purge_old_snapshots(_dd(), retention)

        _audit.info('gitlab_snapshot_saved user=%s id=%s tokens=%d purged=%d',
                    _uid(), sid, len(tokens), purged)
        return jsonify({'id': sid, 'purged': purged})
    except ServiceError as e:
        return api_error(e.message, e.status)


@gitlab_bp.route('/api/gitlab/snapshots', methods=['GET'])
def api_gitlab_snapshots_list():
    """Liste les snapshots disponibles (sans les tokens, juste les métadonnées)."""
    try:
        snapshots = gitlab_service.list_snapshots(_dd())
        return jsonify({'snapshots': snapshots})
    except ServiceError as e:
        return api_error(e.message, e.status)


@gitlab_bp.route('/api/gitlab/snapshots/<snapshot_id>', methods=['GET'])
def api_gitlab_snapshot_get(snapshot_id: str):
    """Retourne un snapshot complet avec la liste des tokens."""
    try:
        snap = gitlab_service.get_snapshot(_dd(), snapshot_id)
        return jsonify(snap)
    except ServiceError as e:
        return api_error(e.message, e.status)


@gitlab_bp.route('/api/gitlab/snapshots/<snapshot_id>', methods=['DELETE'])
def api_gitlab_snapshot_delete(snapshot_id: str):
    """Supprime un snapshot."""
    try:
        gitlab_service.delete_snapshot(_dd(), snapshot_id)
        _audit.info('gitlab_snapshot_deleted user=%s id=%s', _uid(), snapshot_id)
        return jsonify({'deleted': snapshot_id})
    except ServiceError as e:
        return api_error(e.message, e.status)
