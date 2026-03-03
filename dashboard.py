"""
Point d'entrée principal de portal.devops.
Crée l'application Flask et enregistre tous les blueprints.
"""
import json
import os
from typing import Optional

from flasgger import Swagger
from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from prometheus_flask_exporter import PrometheusMetrics


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATAS_DIR = os.path.join(BASE_DIR, 'datas')
PAGES_DIR = os.path.join(BASE_DIR, 'pages')

_SWAGGER_CONFIG = {
    'title': 'portal.devops API',
    'version': '1.0.0',
    'description': 'API interne de portal.devops — SRE, PSSIT, CAD',
    'uiversion': 3,
    'specs_route': '/api/docs/',
    'hide_top_bar': True,
}


def _load_secret_key(datas_dir: str) -> str:
    """Charge la secret key depuis config.json. Lève RuntimeError si absente."""
    config_path = os.path.join(datas_dir, 'auth', 'config.json')
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            key = json.load(f).get('secret_key', '')
        if key:
            return key
    raise RuntimeError(
        "SECRET_KEY manquante dans datas/auth/config.json — "
        "l'application ne peut pas démarrer sans clé secrète."
    )


def create_app(config: Optional[dict] = None) -> Flask:
    """Usine d'application Flask. Accepte un dict de config pour les tests."""
    app = Flask(__name__, static_folder='img', static_url_path='/img')

    datas_dir = (config or {}).get('DATAS_DIR', DATAS_DIR)
    app.config['DATAS_DIR'] = datas_dir
    app.config['PAGES_DIR'] = (config or {}).get('PAGES_DIR', PAGES_DIR)

    if config:
        app.config.update(config)

    # Secret key : priorité à SECRET_KEY passée en config (tests), sinon fichier
    if not app.secret_key:
        app.secret_key = _load_secret_key(datas_dir)

    # === Flask-CORS : origines autorisées via config ou variable d'environnement ===
    _cors_origins_raw = app.config.get(
        'CORS_ORIGINS',
        os.environ.get('CORS_ORIGINS', ''),
    )
    if isinstance(_cors_origins_raw, str):
        _cors_origins = [o.strip() for o in _cors_origins_raw.split(',') if o.strip()]
    else:
        _cors_origins = list(_cors_origins_raw)
    CORS(app, origins=_cors_origins, supports_credentials=True)

    # === Flask-Limiter : rate limiting global par IP (désactivé en test) ===
    app.config.setdefault('RATELIMIT_ENABLED', not app.config.get('TESTING', False))
    Limiter(
        get_remote_address,
        app=app,
        default_limits=['200 per minute', '20 per second'],
        storage_uri='memory://',
    )

    # === Blueprints ===
    from auth import auth_bp
    from auth_admin import auth_admin_bp
    from blueprints.pages import pages_bp
    from blueprints.sre import sre_bp
    from blueprints.pssit import pssit_bp
    from blueprints.cad import cad_bp
    from blueprints.health import health_bp
    from blueprints.ldap_checker import ldap_bp
    from blueprints.kubi import kubi_bp
    from blueprints.gitlab_bp import gitlab_bp

    for bp in (auth_bp, auth_admin_bp, pages_bp, sre_bp, pssit_bp, cad_bp, health_bp, ldap_bp, kubi_bp, gitlab_bp):
        app.register_blueprint(bp)

    # === #23 — Versioning /api/v1/ → /api/ (réécriture transparente) ===
    @app.before_request
    def _strip_api_version():
        """Accepte /api/v1/<path> comme alias de /api/<path> pour le versioning futur."""
        from flask import request
        if request.path.startswith('/api/v1/'):
            request.environ['PATH_INFO'] = '/api/' + request.path[len('/api/v1/'):]

    # === #26 — Gestionnaires d'erreurs globaux (schéma unifié) ===
    @app.errorhandler(400)
    def handle_400(e):
        return jsonify({'error': 'Requête invalide', 'status': 400}), 400

    @app.errorhandler(401)
    def handle_401(e):
        return jsonify({'error': 'Non authentifié', 'status': 401}), 401

    @app.errorhandler(403)
    def handle_403(e):
        return jsonify({'error': 'Accès refusé', 'status': 403}), 403

    @app.errorhandler(404)
    def handle_404(e):
        return jsonify({'error': 'Ressource introuvable', 'status': 404}), 404

    @app.errorhandler(405)
    def handle_405(e):
        return jsonify({'error': 'Méthode non autorisée', 'status': 405}), 405

    @app.errorhandler(429)
    def handle_429(e):
        return jsonify({'error': 'Trop de requêtes', 'status': 429}), 429

    @app.errorhandler(500)
    def handle_500(e):
        return jsonify({'error': 'Erreur interne du serveur', 'status': 500}), 500

    # === #21 — Flasgger / Swagger UI (/api/docs/) ===
    if not app.config.get('TESTING'):
        Swagger(app, config={
            'headers': [],
            'specs': [{'endpoint': 'apispec', 'route': '/api/docs/apispec.json'}],
            **_SWAGGER_CONFIG,
        })

    # === #22 — Prometheus metrics (/metrics) ===
    if not app.config.get('TESTING'):
        PrometheusMetrics(app, default_labels={'app': 'portal_devops'})

    return app


app = create_app()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
