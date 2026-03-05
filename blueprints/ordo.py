"""
Blueprint Ordo Plans — référentiel visuel d'ordonnancement.

Routes :
  GET    /api/ordo/boards                          → liste des boards
  POST   /api/ordo/boards                          → créer un board
  PUT    /api/ordo/boards/<board_id>               → modifier un board
  DELETE /api/ordo/boards/<board_id>               → supprimer un board
  POST   /api/ordo/boards/<board_id>/jobs          → créer un job
  PUT    /api/ordo/boards/<board_id>/jobs/<job_id> → modifier un job
  DELETE /api/ordo/boards/<board_id>/jobs/<job_id> → supprimer un job
"""
import logging

from flask import Blueprint, current_app, jsonify

import services.ordo as svc
from blueprints import _require_json, api_error
from services.store import ServiceError

ordo_bp = Blueprint('ordo', __name__)
logger  = logging.getLogger(__name__)


def _dd() -> str:
    return current_app.config['DATAS_DIR']


# ── Boards ────────────────────────────────────────────────────────────────

@ordo_bp.route('/api/ordo/boards', methods=['GET'])
def api_list_boards():
    return jsonify({'boards': svc.list_boards(_dd())})


@ordo_bp.route('/api/ordo/boards', methods=['POST'])
def api_create_board():
    try:
        b = _require_json()
        board = svc.create_board(
            _dd(),
            name=b.get('name', ''),
            team=b.get('team', ''),
            color=b.get('color', '#326ce5'),
            description=b.get('description', ''),
        )
        return jsonify(board), 201
    except ServiceError as e:
        return api_error(e.message, e.status)


@ordo_bp.route('/api/ordo/boards/<board_id>', methods=['PUT'])
def api_update_board(board_id):
    try:
        b = _require_json()
        board = svc.update_board(
            _dd(), board_id,
            name=b.get('name'),
            team=b.get('team'),
            color=b.get('color'),
            description=b.get('description'),
        )
        return jsonify(board)
    except ServiceError as e:
        return api_error(e.message, e.status)


@ordo_bp.route('/api/ordo/boards/<board_id>', methods=['DELETE'])
def api_delete_board(board_id):
    try:
        svc.delete_board(_dd(), board_id)
        return jsonify({'ok': True})
    except ServiceError as e:
        return api_error(e.message, e.status)


# ── Jobs ──────────────────────────────────────────────────────────────────

@ordo_bp.route('/api/ordo/boards/<board_id>/jobs', methods=['POST'])
def api_create_job(board_id):
    try:
        b = _require_json()
        job = svc.create_job(
            _dd(), board_id,
            name=b.get('name', ''),
            days=b.get('days', []),
            time=b.get('time', '00:00'),
            duration_min=b.get('duration_min', 30),
            description=b.get('description', ''),
            color=b.get('color', '#4caf50'),
            freq_type=b.get('freq_type', 'weekly'),
        )
        return jsonify(job), 201
    except ServiceError as e:
        return api_error(e.message, e.status)


@ordo_bp.route('/api/ordo/boards/<board_id>/jobs/<job_id>', methods=['PUT'])
def api_update_job(board_id, job_id):
    try:
        b = _require_json()
        job = svc.update_job(
            _dd(), board_id, job_id,
            name=b.get('name'),
            days=b.get('days'),
            time=b.get('time'),
            duration_min=b.get('duration_min'),
            description=b.get('description'),
            color=b.get('color'),
            freq_type=b.get('freq_type'),
        )
        return jsonify(job)
    except ServiceError as e:
        return api_error(e.message, e.status)


@ordo_bp.route('/api/ordo/boards/<board_id>/jobs/<job_id>', methods=['DELETE'])
def api_delete_job(board_id, job_id):
    try:
        svc.delete_job(_dd(), board_id, job_id)
        return jsonify({'ok': True})
    except ServiceError as e:
        return api_error(e.message, e.status)
