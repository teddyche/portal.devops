"""
Blueprint CLP Builder multi-instances.
"""
import logging

from flask import Blueprint, Response, current_app, request

import services.clp_svc    as clp_svc
import services.clp_builder as clp_builder
from blueprints import _require_json, api_error
from services.store import ServiceError

clp_bp = Blueprint('clp', __name__)
logger  = logging.getLogger(__name__)
_audit  = logging.getLogger('audit')


def _uid():
    from flask import session
    return session.get('user_id', 'anonymous')


def _dd():
    return current_app.config['DATAS_DIR']


# ── Instances ─────────────────────────────────────────────────────────────────

@clp_bp.route('/api/clp/instances', methods=['GET'])
def api_list_instances():
    try:
        return {'instances': clp_svc.list_instances(_dd())}
    except ServiceError as e:
        return api_error(e.message, e.status)


@clp_bp.route('/api/clp/instances', methods=['POST'])
def api_create_instance():
    try:
        body = _require_json()
        inst = clp_svc.create_instance(
            _dd(),
            name        = body.get('name', ''),
            description = body.get('description', ''),
            color       = body.get('color', '#607d8b'),
        )
        _audit.info('clp_create_instance user=%s id=%s name=%s', _uid(), inst['id'], inst['name'])
        return inst, 201
    except ServiceError as e:
        return api_error(e.message, e.status)


@clp_bp.route('/api/clp/instances/<iid>', methods=['PUT'])
def api_update_instance(iid):
    try:
        body = _require_json()
        inst = clp_svc.update_instance(_dd(), iid,
            name        = body.get('name'),
            description = body.get('description'),
            color       = body.get('color'),
        )
        return inst
    except ServiceError as e:
        return api_error(e.message, e.status)


@clp_bp.route('/api/clp/instances/<iid>', methods=['DELETE'])
def api_delete_instance(iid):
    try:
        clp_svc.delete_instance(_dd(), iid)
        _audit.info('clp_delete_instance user=%s id=%s', _uid(), iid)
        return {'ok': True}
    except ServiceError as e:
        return api_error(e.message, e.status)


# ── Configuration ─────────────────────────────────────────────────────────────

@clp_bp.route('/api/clp/instances/<iid>/config', methods=['GET'])
def api_get_config(iid):
    try:
        return clp_svc.get_config(_dd(), iid)
    except ServiceError as e:
        return api_error(e.message, e.status)


@clp_bp.route('/api/clp/instances/<iid>/config/fqdns', methods=['PUT'])
def api_update_fqdns(iid):
    try:
        body = _require_json()
        result = clp_svc.update_fqdns(_dd(), iid,
            low  = body.get('low', ''),
            mid  = body.get('mid', ''),
            prod = body.get('prod', ''),
        )
        return {'fqdns': result}
    except ServiceError as e:
        return api_error(e.message, e.status)


# ── Middlewares ────────────────────────────────────────────────────────────────

@clp_bp.route('/api/clp/instances/<iid>/config/middlewares', methods=['POST'])
def api_add_middleware(iid):
    try:
        body = _require_json()
        mw = clp_svc.add_middleware(_dd(), iid,
            mw_id       = body.get('id', ''),
            label       = body.get('label', ''),
            icon        = body.get('icon', '🔧'),
            description = body.get('description', ''),
        )
        return mw, 201
    except ServiceError as e:
        return api_error(e.message, e.status)


@clp_bp.route('/api/clp/instances/<iid>/config/middlewares/<mid>', methods=['PUT'])
def api_update_middleware(iid, mid):
    try:
        body = _require_json()
        mw = clp_svc.update_middleware(_dd(), iid, mid,
            label       = body.get('label'),
            icon        = body.get('icon'),
            description = body.get('description'),
            status      = body.get('status'),
        )
        return mw
    except ServiceError as e:
        return api_error(e.message, e.status)


@clp_bp.route('/api/clp/instances/<iid>/config/middlewares/<mid>', methods=['DELETE'])
def api_delete_middleware(iid, mid):
    try:
        clp_svc.delete_middleware(_dd(), iid, mid)
        return {'ok': True}
    except ServiceError as e:
        return api_error(e.message, e.status)


# ── Autres rôles ──────────────────────────────────────────────────────────────

@clp_bp.route('/api/clp/instances/<iid>/config/extra-roles', methods=['POST'])
def api_add_extra_role(iid):
    try:
        body = _require_json()
        role = clp_svc.add_extra_role(_dd(), iid,
            role_id     = body.get('id', ''),
            label       = body.get('label', ''),
            description = body.get('description', ''),
        )
        return role, 201
    except ServiceError as e:
        return api_error(e.message, e.status)


@clp_bp.route('/api/clp/instances/<iid>/config/extra-roles/<rid>', methods=['DELETE'])
def api_delete_extra_role(iid, rid):
    try:
        clp_svc.delete_extra_role(_dd(), iid, rid)
        return {'ok': True}
    except ServiceError as e:
        return api_error(e.message, e.status)


# ── Templates de rôles ────────────────────────────────────────────────────────

@clp_bp.route('/api/clp/instances/<iid>/templates/<role_id>', methods=['GET'])
def api_get_all_templates(iid, role_id):
    try:
        return clp_svc.get_all_templates(_dd(), iid, role_id)
    except ServiceError as e:
        return api_error(e.message, e.status)


@clp_bp.route('/api/clp/instances/<iid>/templates/<role_id>/<file_key>', methods=['GET'])
def api_get_template(iid, role_id, file_key):
    try:
        return clp_svc.get_template(_dd(), iid, role_id, file_key)
    except ServiceError as e:
        return api_error(e.message, e.status)


@clp_bp.route('/api/clp/instances/<iid>/templates/<role_id>/<file_key>', methods=['PUT'])
def api_save_template(iid, role_id, file_key):
    try:
        body = _require_json()
        content = body.get('content', '')
        clp_svc.save_template(_dd(), iid, role_id, file_key, content)
        _audit.info('clp_save_template user=%s iid=%s role=%s file=%s', _uid(), iid, role_id, file_key)
        return {'ok': True}
    except ServiceError as e:
        return api_error(e.message, e.status)


@clp_bp.route('/api/clp/instances/<iid>/templates/<role_id>/<file_key>', methods=['DELETE'])
def api_reset_template(iid, role_id, file_key):
    try:
        content = clp_svc.reset_template(_dd(), iid, role_id, file_key)
        return {'content': content, 'custom': False}
    except ServiceError as e:
        return api_error(e.message, e.status)


# ── Génération ZIP ────────────────────────────────────────────────────────────

@clp_bp.route('/api/clp/instances/<iid>/generate', methods=['POST'])
def api_generate(iid):
    try:
        body = _require_json()
        code_app    = body.get('code_app', '').strip().lower()
        nom_app     = body.get('nom_app', '').strip()
        entite      = body.get('entite', 'caps').strip() or 'caps'
        envs        = body.get('envs', [])
        repo_type   = body.get('repo_type', 'generic').strip().lower()
        middlewares = body.get('middlewares', [])
        deploy_mode = body.get('deploy_mode', 'job').strip().lower()

        if len(code_app) < 2 or not code_app[:2].isalpha():
            return api_error('Le code appli doit commencer par 2 lettres', 400)
        if not nom_app:
            return api_error('Le nom appli est requis', 400)
        if not isinstance(envs, list):
            return api_error('envs doit être une liste', 400)
        if repo_type not in ('generic', 'maven'):
            repo_type = 'generic'
        if deploy_mode not in ('job', 'workflow'):
            deploy_mode = 'job'

        # Vérifier que les MWs demandés sont activés dans la config instance
        cfg = clp_svc.get_config(_dd(), iid)
        enabled_mws = {m['id'] for m in cfg.get('middlewares', []) if m['status'] == 'enabled'}
        middlewares = [m for m in middlewares if m in enabled_mws]

        # Charger les overrides de templates
        all_role_ids = middlewares + [r['id'] for r in cfg.get('extra_roles', [])]
        overrides = clp_svc.load_template_overrides(_dd(), iid, all_role_ids)

        extra_roles = [r['id'] for r in cfg.get('extra_roles', [])]

        zip_bytes = clp_builder.generate_ansible_zip(
            code_app, nom_app, entite, envs,
            repo_type       = repo_type,
            middlewares     = middlewares,
            deploy_mode     = deploy_mode,
            template_overrides = overrides,
            extra_roles     = extra_roles,
        )
        filename = f'{code_app}_deploy.zip'

        _audit.info('clp_generate user=%s iid=%s code_app=%s repo=%s mw=%s envs=%s',
                    _uid(), iid, code_app, repo_type, middlewares,
                    [e.get('name') for e in envs])

        return Response(
            zip_bytes,
            mimetype='application/zip',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        logger.exception('Erreur génération package CLP')
        return api_error(str(e), 500)
