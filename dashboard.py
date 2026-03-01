"""
Point d'entrée principal de portal.devops.
Crée l'application Flask et enregistre tous les blueprints.
"""
import json
import os
from typing import Optional

from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATAS_DIR = os.path.join(BASE_DIR, 'datas')
PAGES_DIR = os.path.join(BASE_DIR, 'pages')


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

    # Flask-CORS : origines autorisées via config ou variable d'environnement
    _cors_origins_raw = app.config.get(
        'CORS_ORIGINS',
        os.environ.get('CORS_ORIGINS', ''),
    )
    if isinstance(_cors_origins_raw, str):
        _cors_origins = [o.strip() for o in _cors_origins_raw.split(',') if o.strip()]
    else:
        _cors_origins = list(_cors_origins_raw)
    CORS(app, origins=_cors_origins, supports_credentials=True)

    # Flask-Limiter : rate limiting global par IP (désactivé en test)
    app.config.setdefault('RATELIMIT_ENABLED', not app.config.get('TESTING', False))
    Limiter(
        get_remote_address,
        app=app,
        default_limits=['200 per minute', '20 per second'],
        storage_uri='memory://',
    )

    from auth import auth_bp
    from auth_admin import auth_admin_bp
    from blueprints.pages import pages_bp
    from blueprints.sre import sre_bp
    from blueprints.pssit import pssit_bp
    from blueprints.cad import cad_bp

    for bp in (auth_bp, auth_admin_bp, pages_bp, sre_bp, pssit_bp, cad_bp):
        app.register_blueprint(bp)

    return app


app = create_app()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
