"""
Couche I/O JSON avec cache write-through thread-safe.
Toutes les lectures/écritures de fichiers de données passent par ce module.
"""
import json
import os
import re
import shutil
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional


class ServiceError(Exception):
    """Erreur métier renvoyée par les fonctions de service."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


# === Cache write-through ===

_cache: dict[str, tuple[Any, float]] = {}
_cache_lock = threading.Lock()
_CACHE_TTL = 30.0  # secondes


def _cache_get(path: str) -> tuple[bool, Any]:
    with _cache_lock:
        if path in _cache:
            data, ts = _cache[path]
            if time.monotonic() - ts < _CACHE_TTL:
                return True, data
    return False, None


def _cache_set(path: str, data: Any) -> None:
    with _cache_lock:
        _cache[path] = (data, time.monotonic())


def cache_invalidate(path: str) -> None:
    """Invalide manuellement une entrée du cache (ex. après suppression fichier)."""
    with _cache_lock:
        _cache.pop(path, None)


# === I/O JSON ===

def load_json(path: str) -> Optional[Any]:
    """Charge un fichier JSON avec cache TTL de 30 s. Retourne None si absent."""
    hit, data = _cache_get(path)
    if hit:
        return data
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        return None
    _cache_set(path, data)
    return data


def save_json(path: str, data: Any) -> None:
    """Écrit un fichier JSON de façon atomique (tmp + os.replace) et met à jour le cache."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    _cache_set(path, data)


# === Utilitaires ===

def safe_id(value: str) -> bool:
    """Vérifie qu'un identifiant ne contient que des caractères alphanumériques, tirets ou underscores."""
    return bool(re.match(r'^[A-Za-z0-9_-]+$', value))


def soft_delete_dir(src_dir: str, kind: str, trash_dir: str) -> None:
    """Déplace src_dir vers trash_dir/<timestamp>_<kind>_<basename>/ au lieu de le supprimer."""
    if not os.path.exists(src_dir):
        return
    os.makedirs(trash_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
    name = f'{ts}_{kind}_{os.path.basename(src_dir)}'
    dest = os.path.join(trash_dir, name)
    shutil.move(src_dir, dest)
