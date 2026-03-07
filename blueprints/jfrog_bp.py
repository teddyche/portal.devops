"""
Blueprint JFrog Tokens Checker.

Routes :
  GET    /api/jfrog/instances                          → liste instances (token masqué)
  POST   /api/jfrog/instances                          → créer instance
  PUT    /api/jfrog/instances/<iid>                    → modifier instance
  DELETE /api/jfrog/instances/<iid>                    → supprimer instance + snapshots
  POST   /api/jfrog/instances/<iid>/test               → tester connexion
  POST   /api/jfrog/instances/<iid>/tokens             → fetch tokens live
  POST   /api/jfrog/instances/<iid>/snapshots          → sauvegarder snapshot
  GET    /api/jfrog/instances/<iid>/snapshots          → liste snapshots (metadata)
  GET    /api/jfrog/instances/<iid>/snapshots/<sid>    → snapshot complet
  DELETE /api/jfrog/instances/<iid>/snapshots/<sid>    → supprimer snapshot
"""
import logging

from flask import Blueprint, current_app, jsonify, session

import services.jfrog_svc as svc
from blueprints import _require_json, api_error
from services.store import ServiceError

jfrog_bp = Blueprint('jfrog', __name__)
logger   = logging.getLogger(__name__)
_audit   = logging.getLogger('audit')


def _dd():  return current_app.config['DATAS_DIR']
def _uid(): return session.get('user_id', 'anonymous')


def _mask(token):
    if not token: return ''
    return '•' * max(4, len(token) - 4) + token[-4:]


def _safe(inst):
    return {**inst, 'token': _mask(inst.get('token', ''))}


# ── Instances ──────────────────────────────────────────────────────────────────

@jfrog_bp.route('/api/jfrog/instances', methods=['GET'])
def api_list_instances():
    return jsonify({'instances': [_safe(i) for i in svc.list_instances(_dd())]})


@jfrog_bp.route('/api/jfrog/instances', methods=['POST'])
def api_create_instance():
    try:
        b    = _require_json()
        inst = svc.create_instance(
            _dd(),
            name           = b.get('name', '').strip(),
            url            = b.get('url', '').strip(),
            token          = b.get('token', '').strip(),
            color          = b.get('color', '#2196f3'),
            description    = b.get('description', ''),
            validate_certs = b.get('validate_certs', True),
        )
        _audit.info('jfrog_instance_created user=%s id=%s', _uid(), inst['id'])
        return jsonify(_safe(inst)), 201
    except ServiceError as e:
        return api_error(e.message, e.status)


@jfrog_bp.route('/api/jfrog/instances/<iid>', methods=['PUT'])
def api_update_instance(iid):
    try:
        b    = _require_json()
        inst = svc.update_instance(_dd(), iid, **b)
        _audit.info('jfrog_instance_updated user=%s id=%s', _uid(), iid)
        return jsonify(_safe(inst))
    except ServiceError as e:
        return api_error(e.message, e.status)


@jfrog_bp.route('/api/jfrog/instances/<iid>', methods=['DELETE'])
def api_delete_instance(iid):
    try:
        svc.delete_instance(_dd(), iid)
        _audit.info('jfrog_instance_deleted user=%s id=%s', _uid(), iid)
        return jsonify({'deleted': iid})
    except ServiceError as e:
        return api_error(e.message, e.status)


# ── Test connexion ─────────────────────────────────────────────────────────────

@jfrog_bp.route('/api/jfrog/instances/<iid>/test', methods=['POST'])
def api_test_instance(iid):
    try:
        inst = svc.get_instance(_dd(), iid)
        if not inst:
            return api_error('Instance introuvable', 404)
        result = svc.test_connection(inst['url'], inst['token'], inst.get('validate_certs', True))
        return jsonify(result)
    except ServiceError as e:
        return api_error(e.message, e.status)


# ── Tokens ─────────────────────────────────────────────────────────────────────

@jfrog_bp.route('/api/jfrog/instances/<iid>/tokens', methods=['POST'])
def api_fetch_tokens(iid):
    try:
        inst = svc.get_instance(_dd(), iid)
        if not inst:
            return api_error('Instance introuvable', 404)
        result = svc.fetch_tokens(inst['url'], inst['token'], inst.get('validate_certs', True))
        _audit.info('jfrog_tokens_fetched user=%s iid=%s total=%d', _uid(), iid, result['stats']['total'])
        return jsonify(result)
    except ServiceError as e:
        return api_error(e.message, e.status)


# ── Snapshots ──────────────────────────────────────────────────────────────────

@jfrog_bp.route('/api/jfrog/instances/<iid>/snapshots', methods=['POST'])
def api_save_snapshot(iid):
    try:
        inst = svc.get_instance(_dd(), iid)
        if not inst:
            return api_error('Instance introuvable', 404)
        b      = _require_json()
        tokens = b.get('tokens', [])
        stats  = b.get('stats', {})
        if not isinstance(tokens, list):
            return api_error('tokens doit être une liste', 400)
        sid    = svc.save_snapshot(_dd(), iid, tokens, stats)
        purged = svc.purge_old_snapshots(_dd(), iid)
        _audit.info('jfrog_snapshot_saved user=%s iid=%s id=%s tokens=%d purged=%d',
                    _uid(), iid, sid, len(tokens), purged)
        return jsonify({'id': sid, 'purged': purged})
    except ServiceError as e:
        return api_error(e.message, e.status)


@jfrog_bp.route('/api/jfrog/instances/<iid>/snapshots', methods=['GET'])
def api_list_snapshots(iid):
    try:
        return jsonify({'snapshots': svc.list_snapshots(_dd(), iid)})
    except ServiceError as e:
        return api_error(e.message, e.status)


@jfrog_bp.route('/api/jfrog/instances/<iid>/snapshots/<sid>', methods=['GET'])
def api_get_snapshot(iid, sid):
    try:
        return jsonify(svc.get_snapshot(_dd(), iid, sid))
    except ServiceError as e:
        return api_error(e.message, e.status)


@jfrog_bp.route('/api/jfrog/instances/<iid>/snapshots/<sid>', methods=['DELETE'])
def api_delete_snapshot(iid, sid):
    try:
        svc.delete_snapshot(_dd(), iid, sid)
        _audit.info('jfrog_snapshot_deleted user=%s iid=%s id=%s', _uid(), iid, sid)
        return jsonify({'deleted': sid})
    except ServiceError as e:
        return api_error(e.message, e.status)
