"""
Blueprint DevOps Tools — Onboarding / Deboarding (GitLab + AAP).
Les ZIPs sont génériques : tout est paramétré via Survey + Credentials AAP.
"""
import logging

from flask import Blueprint, Response

import services.devops_svc as devops_svc
from blueprints import api_error

devops_bp = Blueprint('devops', __name__)
logger    = logging.getLogger(__name__)
_audit    = logging.getLogger('audit')


def _uid():
    from flask import session
    return session.get('user_id', 'anonymous')


@devops_bp.route('/api/devops/onboarding/generate', methods=['POST'])
def api_onboarding_generate():
    try:
        zip_bytes = devops_svc.generate_onboarding_zip()
        _audit.info('devops_onboarding_dl user=%s', _uid())
        return Response(zip_bytes, mimetype='application/zip',
                        headers={'Content-Disposition': 'attachment; filename="onboarding.zip"'})
    except Exception as e:
        logger.exception('Erreur génération Onboarding')
        return api_error(str(e), 500)


@devops_bp.route('/api/devops/deboarding/generate', methods=['POST'])
def api_deboarding_generate():
    try:
        zip_bytes = devops_svc.generate_deboarding_zip()
        _audit.info('devops_deboarding_dl user=%s', _uid())
        return Response(zip_bytes, mimetype='application/zip',
                        headers={'Content-Disposition': 'attachment; filename="deboarding.zip"'})
    except Exception as e:
        logger.exception('Erreur génération Deboarding')
        return api_error(str(e), 500)
