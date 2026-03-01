"""
Point d'entrée principal de portal.devops.
Crée l'application Flask et enregistre tous les blueprints.
"""
import json
import os
from typing import Optional

from flask import Flask


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATAS_DIR = os.path.join(BASE_DIR, 'datas')
PAGES_DIR = os.path.join(BASE_DIR, 'pages')


def _load_secret_key(datas_dir: str) -> str:
    config_path = os.path.join(datas_dir, 'auth', 'config.json')
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f).get('secret_key', 'dev-fallback-key')
    return 'dev-fallback-key'


def create_app(config: Optional[dict] = None) -> Flask:
    """Usine d'application Flask. Accepte un dict de config pour les tests."""
    app = Flask(__name__, static_folder='img', static_url_path='/img')

    datas_dir = (config or {}).get('DATAS_DIR', DATAS_DIR)
    app.secret_key = _load_secret_key(datas_dir)
    app.config['DATAS_DIR'] = datas_dir
    app.config['PAGES_DIR'] = (config or {}).get('PAGES_DIR', PAGES_DIR)

    if config:
        app.config.update(config)

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
