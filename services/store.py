"""
Couche I/O JSON avec cache write-through thread-safe.
Toutes les lectures/écritures de fichiers de données passent par ce module.
"""
import copy
import json
import os
import re
import shutil
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

_JSON_MAX_BYTES = 50_000_000  # 50 Mo


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


def cache_invalidate(path: str) -> None:
    """Invalide manuellement une entrée du cache (ex. après suppression fichier)."""
    with _cache_lock:
        _cache.pop(path, None)


# === I/O JSON ===

def load_json(path: str) -> Optional[Any]:
    """Charge un fichier JSON avec cache TTL de 30 s. Retourne None si absent.
    Lève ServiceError si le fichier est présent mais corrompu.
    """
    with _cache_lock:
        if path in _cache:
            data, ts = _cache[path]
            if time.monotonic() - ts < _CACHE_TTL:
                return copy.deepcopy(data)

    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as e:
        raise ServiceError(
            f'Fichier JSON corrompu : {os.path.basename(path)} — {e}', 500
        ) from e

    with _cache_lock:
        _cache[path] = (data, time.monotonic())
    return copy.deepcopy(data)


def save_json(path: str, data: Any) -> None:
    """Écrit un fichier JSON de façon atomique (tmp + os.replace) et met à jour le cache.
    Lève ServiceError si les données dépassent 50 Mo.
    os.replace et mise à jour du cache sont effectués sous le même verrou pour éviter
    qu'un thread concurrent lise un cache expiré entre les deux opérations.
    """
    json_str = json.dumps(data, ensure_ascii=False, indent=2)
    if len(json_str.encode()) > _JSON_MAX_BYTES:
        raise ServiceError('Données trop volumineuses (limite 50 Mo)')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(json_str)
        with _cache_lock:
            os.replace(tmp, path)
            _cache[path] = (data, time.monotonic())
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


# === Utilitaires ===

def safe_id(value: str) -> bool:
    """Vérifie qu'un identifiant ne contient que des caractères alphanumériques,
    tirets ou underscores, et ne dépasse pas 50 caractères.
    """
    return bool(value) and len(value) <= 50 and bool(re.match(r'^[A-Za-z0-9_-]+$', value))


def soft_delete_dir(src_dir: str, kind: str, trash_dir: str) -> None:
    """Déplace src_dir vers trash_dir/<timestamp>_<kind>_<basename>/ au lieu de le supprimer."""
    if not os.path.exists(src_dir):
        return
    os.makedirs(trash_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
    name = f'{ts}_{kind}_{os.path.basename(src_dir)}'
    dest = os.path.join(trash_dir, name)
    shutil.move(src_dir, dest)


def purge_trash(trash_dir: str, days: int = 90) -> int:
    """Supprime les entrées de trash_dir plus anciennes que `days` jours.
    Retourne le nombre d'entrées supprimées.
    Peut être appelée via une tâche cron ou l'IHM d'administration.
    """
    if not os.path.exists(trash_dir):
        return 0
    cutoff = time.time() - days * 86_400
    purged = 0
    for entry in os.scandir(trash_dir):
        try:
            if entry.stat().st_mtime < cutoff:
                shutil.rmtree(entry.path, ignore_errors=True)
                purged += 1
        except OSError:
            pass
    return purged
