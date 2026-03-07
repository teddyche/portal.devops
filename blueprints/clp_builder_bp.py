"""
Blueprint CLP Ansible Builder — génération de packages Ansible ZIP.
"""
import logging

from flask import Blueprint, Response, current_app, request

import services.clp_builder as clp_svc
from blueprints import _require_json, api_error

clp_builder_bp = Blueprint('clp_builder', __name__)
logger = logging.getLogger(__name__)
_audit = logging.getLogger('audit')


def _uid():
    from flask import session
    return session.get('user_id', 'anonymous')


@clp_builder_bp.route('/api/clp-builder/generate', methods=['POST'])
def api_clp_generate():
    """
    Génère un package Ansible ZIP à partir de la configuration fournie.
    ---
    tags: [CLP Builder]
    responses:
      200:
        description: Fichier ZIP en téléchargement
      400:
        description: Paramètres invalides
    """
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

        zip_bytes = clp_svc.generate_ansible_zip(
            code_app, nom_app, entite, envs, repo_type, middlewares, deploy_mode
        )
        filename  = f'{code_app}_deploy.zip'

        _audit.info('clp_builder_generate user=%s code_app=%s repo=%s mw=%s envs=%s',
                    _uid(), code_app, repo_type, middlewares, [e.get('name') for e in envs])

        return Response(
            zip_bytes,
            mimetype='application/zip',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        logger.exception('Erreur génération package CLP Builder')
        return api_error(str(e), 500)
