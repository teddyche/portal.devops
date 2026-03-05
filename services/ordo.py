"""
Service Ordo Plans — référentiel visuel d'ordonnancement par équipe.
Stocke les boards (ordos) et leurs jobs dans datas/ordo_boards.json.
"""
import uuid

from services.store import load_json, save_json, ServiceError

_FILE = 'ordo_boards.json'


def _load(dd: str) -> dict:
    return load_json(dd, _FILE, default={'boards': []})


def _save(dd: str, data: dict) -> None:
    save_json(dd, _FILE, data)


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


# ── Boards ────────────────────────────────────────────────────────────────

def list_boards(dd: str) -> list:
    return _load(dd)['boards']


def get_board(dd: str, board_id: str) -> dict:
    b = next((b for b in _load(dd)['boards'] if b['id'] == board_id), None)
    if not b:
        raise ServiceError('Board introuvable', 404)
    return b


def create_board(dd: str, name: str, team: str, color: str = '#326ce5', description: str = '') -> dict:
    if not name.strip():
        raise ServiceError('Nom requis', 400)
    data = _load(dd)
    board = {
        'id':          _new_id(),
        'name':        name.strip(),
        'team':        team.strip(),
        'color':       color or '#326ce5',
        'description': description.strip(),
        'jobs':        [],
    }
    data['boards'].append(board)
    _save(dd, data)
    return board


def update_board(dd: str, board_id: str, name=None, team=None, color=None, description=None) -> dict:
    data = _load(dd)
    b = next((b for b in data['boards'] if b['id'] == board_id), None)
    if not b:
        raise ServiceError('Board introuvable', 404)
    if name        is not None: b['name']        = name.strip()
    if team        is not None: b['team']        = team.strip()
    if color       is not None: b['color']       = color
    if description is not None: b['description'] = description.strip()
    _save(dd, data)
    return b


def delete_board(dd: str, board_id: str) -> None:
    data = _load(dd)
    before = len(data['boards'])
    data['boards'] = [b for b in data['boards'] if b['id'] != board_id]
    if len(data['boards']) == before:
        raise ServiceError('Board introuvable', 404)
    _save(dd, data)


# ── Jobs ──────────────────────────────────────────────────────────────────

def create_job(
    dd: str, board_id: str,
    name: str, days: list, time: str,
    duration_min: int = 30,
    description: str = '',
    color: str = '#4caf50',
    freq_type: str = 'weekly',
) -> dict:
    if not name.strip():
        raise ServiceError('Nom requis', 400)
    data = _load(dd)
    b = next((b for b in data['boards'] if b['id'] == board_id), None)
    if not b:
        raise ServiceError('Board introuvable', 404)
    job = {
        'id':           _new_id(),
        'name':         name.strip(),
        'description':  description.strip(),
        'freq_type':    freq_type,   # 'daily' | 'weekly' | 'monthly'
        'days':         days,        # [0..6] weekly ou [1..31] monthly
        'time':         time,        # "HH:MM"
        'duration_min': int(duration_min),
        'color':        color or '#4caf50',
    }
    b['jobs'].append(job)
    _save(dd, data)
    return job


def update_job(dd: str, board_id: str, job_id: str, **kw) -> dict:
    data = _load(dd)
    b = next((b for b in data['boards'] if b['id'] == board_id), None)
    if not b:
        raise ServiceError('Board introuvable', 404)
    j = next((j for j in b['jobs'] if j['id'] == job_id), None)
    if not j:
        raise ServiceError('Job introuvable', 404)
    for k, v in kw.items():
        if v is not None:
            j[k] = v
    _save(dd, data)
    return j


def delete_job(dd: str, board_id: str, job_id: str) -> None:
    data = _load(dd)
    b = next((b for b in data['boards'] if b['id'] == board_id), None)
    if not b:
        raise ServiceError('Board introuvable', 404)
    before = len(b['jobs'])
    b['jobs'] = [j for j in b['jobs'] if j['id'] != job_id]
    if len(b['jobs']) == before:
        raise ServiceError('Job introuvable', 404)
    _save(dd, data)
