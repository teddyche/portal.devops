"""
Blueprint AAP Checker — gestion des instances AAP et import de snapshots.

Routes :
  GET    /api/aap-checker/instances                             → liste instances
  POST   /api/aap-checker/instances                             → créer instance
  PUT    /api/aap-checker/instances/<iid>                       → modifier instance
  DELETE /api/aap-checker/instances/<iid>                       → supprimer instance
  GET    /api/aap-checker/instances/<iid>/config                → clé de chiffrement
  GET    /api/aap-checker/instances/<iid>/snapshots             → liste snapshots
  POST   /api/aap-checker/instances/<iid>/snapshots             → importer snapshot (.enc)
  GET    /api/aap-checker/instances/<iid>/snapshots/<sid>       → détail snapshot
  DELETE /api/aap-checker/instances/<iid>/snapshots/<sid>       → supprimer snapshot
  GET    /api/aap-checker/instances/<iid>/diff?a=<sid>&b=<sid>  → diff deux snapshots
  GET    /api/aap-checker/project.zip                           → télécharger projet Ansible
"""
import io
import logging

from flask import Blueprint, current_app, jsonify, request, send_file

import services.aap_checker as svc
from blueprints import _require_json, api_error
from services.store import ServiceError

aap_checker_bp = Blueprint('aap_checker', __name__)
logger = logging.getLogger(__name__)


def _dd() -> str:
    return current_app.config['DATAS_DIR']


def _safe(inst: dict) -> dict:
    """Retire la clé de chiffrement de la réponse listing."""
    return {k: v for k, v in inst.items() if k != 'enc_key'}


# ── Instances ──────────────────────────────────────────────────────────────────

@aap_checker_bp.route('/api/aap-checker/instances', methods=['GET'])
def api_list_instances():
    return jsonify({'instances': [_safe(i) for i in svc.list_instances(_dd())]})


@aap_checker_bp.route('/api/aap-checker/instances', methods=['POST'])
def api_create_instance():
    try:
        b = _require_json()
        inst = svc.create_instance(
            _dd(),
            name=b.get('name', ''),
            description=b.get('description', ''),
            color=b.get('color', '#c62828'),
            env_type=b.get('env_type', ''),
        )
        return jsonify({'instance': inst}), 201
    except ServiceError as e:
        return api_error(e.message, e.status)


@aap_checker_bp.route('/api/aap-checker/instances/<iid>', methods=['PUT'])
def api_update_instance(iid):
    try:
        b = _require_json()
        inst = svc.update_instance(
            _dd(), iid,
            name=b.get('name'),
            description=b.get('description'),
            color=b.get('color'),
            env_type=b.get('env_type'),
        )
        return jsonify({'instance': _safe(inst)})
    except ServiceError as e:
        return api_error(e.message, e.status)


@aap_checker_bp.route('/api/aap-checker/instances/<iid>', methods=['DELETE'])
def api_delete_instance(iid):
    try:
        svc.delete_instance(_dd(), iid)
        return jsonify({'ok': True})
    except ServiceError as e:
        return api_error(e.message, e.status)


@aap_checker_bp.route('/api/aap-checker/instances/<iid>/config', methods=['GET'])
def api_instance_config(iid):
    inst = svc.get_instance(_dd(), iid)
    if not inst:
        return api_error('Instance introuvable', 404)
    return jsonify({'enc_key': inst['enc_key'], 'name': inst['name']})


# ── Snapshots ──────────────────────────────────────────────────────────────────

@aap_checker_bp.route('/api/aap-checker/instances/<iid>/snapshots', methods=['GET'])
def api_list_snapshots(iid):
    return jsonify({'snapshots': svc.list_snapshots(_dd(), iid)})


@aap_checker_bp.route('/api/aap-checker/instances/<iid>/snapshots', methods=['POST'])
def api_import_snapshot(iid):
    if 'file' not in request.files:
        return api_error('Fichier manquant (champ : file)', 400)
    try:
        sid = svc.import_snapshot(_dd(), iid, request.files['file'].read())
        return jsonify({'snapshot_id': sid}), 201
    except ServiceError as e:
        return api_error(e.message, e.status)


@aap_checker_bp.route('/api/aap-checker/instances/<iid>/snapshots/<sid>', methods=['GET'])
def api_get_snapshot(iid, sid):
    snap = svc.get_snapshot(_dd(), iid, sid)
    if not snap:
        return api_error('Snapshot introuvable', 404)
    return jsonify(snap)


@aap_checker_bp.route('/api/aap-checker/instances/<iid>/snapshots/<sid>', methods=['DELETE'])
def api_delete_snapshot(iid, sid):
    svc.delete_snapshot(_dd(), iid, sid)
    return jsonify({'ok': True})


# ── Diff ───────────────────────────────────────────────────────────────────────

@aap_checker_bp.route('/api/aap-checker/instances/<iid>/diff', methods=['GET'])
def api_diff_snapshots(iid):
    a = request.args.get('a')
    b = request.args.get('b')
    if not a or not b:
        return api_error('Paramètres a et b requis', 400)
    try:
        return jsonify(svc.diff_snapshots(_dd(), iid, a, b))
    except ServiceError as e:
        return api_error(e.message, e.status)


# ── Téléchargement projet ZIP ──────────────────────────────────────────────────

@aap_checker_bp.route('/api/aap-checker/project.zip', methods=['GET'])
def api_download_project():
    z = svc.generate_project_zip()
    return send_file(
        io.BytesIO(z),
        mimetype='application/zip',
        as_attachment=True,
        download_name='aap-checker-project.zip',
    )
