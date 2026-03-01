"""
Persistance JSON partagée pour auth.py et auth_admin.py.

Fichiers gérés dans AUTH_DIR :
  config.json   — paramètres non-sensibles (ssl_verify, adfs.authority, cors_origins…)
  secrets.json  — secrets (secret_key, local_admin.password_hash, adfs.client_id/secret…)
                  Doit avoir des permissions restrictives (chmod 600).
  users.json    — liste des utilisateurs
  teams.json    — liste des équipes

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


def load_secrets() -> dict:
    """Charge secrets.json (clés secrètes, hashes, tokens ADFS).
    Retourne un dict vide si le fichier n'existe pas (backward compat : les
    secrets restent dans config.json jusqu'à migration manuelle).
    """
    return load_auth('secrets.json') or {}


def save_secrets(data: dict) -> None:
    """Écrit secrets.json dans AUTH_DIR.
    Le fichier doit être protégé par chmod 600 sur le système de fichiers.
    """
    import auth_store as _self
    os.makedirs(_self.AUTH_DIR, exist_ok=True)
    path = os.path.join(_self.AUTH_DIR, 'secrets.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    # Restreindre les permissions (lecture propriétaire uniquement)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows ou système de fichiers sans support chmod


def merge_config_secrets(config: dict, secrets: dict) -> dict:
    """Fusionne config et secrets (deep merge sur les dicts imbriqués).
    Les valeurs de secrets prennent la priorité sur celles de config.
    """
    merged = dict(config)
    for k, v in secrets.items():
        if isinstance(v, dict) and isinstance(merged.get(k), dict):
            merged[k] = {**merged[k], **v}
        else:
            merged[k] = v
    return merged
