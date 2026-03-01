"""
Persistance JSON partagée pour auth.py et auth_admin.py.

AUTH_DIR est une variable de module patchable en test via
  mocker.patch.object(auth_store, 'AUTH_DIR', str(tmp_dir / 'auth'))
"""
import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_DIR = os.path.join(BASE_DIR, 'datas', 'auth')


def load_auth(name: str):
    """Charge un fichier JSON depuis AUTH_DIR. Retourne None si absent."""
    import auth_store as _self  # lecture dynamique de AUTH_DIR pour permettre le patching
    path = os.path.join(_self.AUTH_DIR, name)
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None


def save_auth(name: str, data) -> None:
    """Écrit un fichier JSON dans AUTH_DIR."""
    import auth_store as _self
    os.makedirs(_self.AUTH_DIR, exist_ok=True)
    with open(os.path.join(_self.AUTH_DIR, name), 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
