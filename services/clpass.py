"""
CLPASS — Service de gestion de secrets chiffrés.

Chiffrement : AES-256-GCM (authentifié) + PBKDF2-SHA256 600 000 itérations.
Le master password n'est jamais persisté : seul un canary chiffré permet la vérification.
"""
import base64
import os
import shutil
import uuid
from datetime import datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from services.store import ServiceError, load_json, save_json

_CANARY = 'clpass-canary-v1'
_KDF_ITER = 600_000


# ── Crypto helpers ─────────────────────────────────────────────────────────────

def _derive_key(password: str, salt_b64: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.b64decode(salt_b64),
        iterations=_KDF_ITER,
    )
    return kdf.derive(password.encode('utf-8'))


def _encrypt(data: str, key: bytes) -> dict:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, data.encode('utf-8'), None)
    return {'ct': base64.b64encode(ct).decode(), 'nonce': base64.b64encode(nonce).decode()}


def _decrypt(enc: dict, key: bytes) -> str:
    try:
        ct    = base64.b64decode(enc['ct'])
        nonce = base64.b64decode(enc['nonce'])
        return AESGCM(key).decrypt(nonce, ct, None).decode('utf-8')
    except Exception:
        raise ServiceError('Master password incorrect ou données corrompues', 401)


def _check_canary(canary: dict, key: bytes) -> bool:
    try:
        return _decrypt(canary, key) == _CANARY
    except ServiceError:
        return False


# ── Paths ──────────────────────────────────────────────────────────────────────

def _vpath(dd):         return os.path.join(dd, 'clpass', 'vaults.json')
def _edir(dd):          return os.path.join(dd, 'clpass', 'entries')
def _epath(dd, vid):    return os.path.join(_edir(dd), vid + '.json')

def _lv(dd):    return load_json(_vpath(dd)) or {'vaults': []}
def _sv(dd, d): save_json(_vpath(dd), d)


# ── Vaults ─────────────────────────────────────────────────────────────────────

def list_vaults(dd, team_ids: list, superadmin: bool = False) -> list:
    vaults = _lv(dd)['vaults']
    if superadmin:
        return [_safe_vault(v) for v in vaults]
    return [_safe_vault(v) for v in vaults if v.get('team_id') in team_ids]


def _safe_vault(v: dict) -> dict:
    """Retire le sel et le canary de la réponse publique."""
    return {k: v[k] for k in ('id', 'name', 'description', 'color', 'team_id', 'created_at', 'created_by') if k in v}


def get_vault_raw(dd, vid: str) -> dict | None:
    return next((v for v in _lv(dd)['vaults'] if v['id'] == vid), None)


def create_vault(dd, name: str, description: str, color: str,
                 team_id: str, master_pw: str, created_by: str) -> dict:
    if not name:
        raise ServiceError('Nom requis')
    if not master_pw:
        raise ServiceError('Master password requis')
    salt_b64 = base64.b64encode(os.urandom(32)).decode()
    key      = _derive_key(master_pw, salt_b64)
    d        = _lv(dd)
    vault = {
        'id':          uuid.uuid4().hex[:12],
        'name':        name,
        'description': description or '',
        'color':       color or '#6a1b9a',
        'team_id':     team_id or '',
        'salt':        salt_b64,
        'canary':      _encrypt(_CANARY, key),
        'created_at':  datetime.utcnow().isoformat(),
        'created_by':  created_by,
    }
    d['vaults'].append(vault)
    _sv(dd, d)
    os.makedirs(_edir(dd), exist_ok=True)
    save_json(_epath(dd, vault['id']), {'entries': []})
    return _safe_vault(vault)


def update_vault(dd, vid: str, **kw) -> dict:
    d = _lv(dd)
    v = next((x for x in d['vaults'] if x['id'] == vid), None)
    if not v:
        raise ServiceError('Coffre introuvable', 404)
    for k in ('name', 'description', 'color', 'team_id'):
        if k in kw and kw[k] is not None:
            v[k] = kw[k]
    _sv(dd, d)
    return _safe_vault(v)


def verify_vault(dd, vid: str, master_pw: str) -> bool:
    v = get_vault_raw(dd, vid)
    if not v:
        raise ServiceError('Coffre introuvable', 404)
    key = _derive_key(master_pw, v['salt'])
    return _check_canary(v['canary'], key)


def delete_vault(dd, vid: str, master_pw: str) -> None:
    if not verify_vault(dd, vid, master_pw):
        raise ServiceError('Master password incorrect', 401)
    d = _lv(dd)
    d['vaults'] = [x for x in d['vaults'] if x['id'] != vid]
    _sv(dd, d)
    p = _epath(dd, vid)
    if os.path.exists(p):
        os.remove(p)


def change_vault_pw(dd, vid: str, old_pw: str, new_pw: str) -> None:
    if not new_pw:
        raise ServiceError('Nouveau master password requis')
    v = get_vault_raw(dd, vid)
    if not v:
        raise ServiceError('Coffre introuvable', 404)
    old_key = _derive_key(old_pw, v['salt'])
    if not _check_canary(v['canary'], old_key):
        raise ServiceError('Master password actuel incorrect', 401)

    # Re-chiffrer toutes les entrées
    ed = load_json(_epath(dd, vid)) or {'entries': []}
    new_salt = base64.b64encode(os.urandom(32)).decode()
    new_key  = _derive_key(new_pw, new_salt)

    for e in ed['entries']:
        if 'secret_enc' in e and e['secret_enc']:
            plain = _decrypt(e['secret_enc'], old_key)
            e['secret_enc'] = _encrypt(plain, new_key)
        if 'notes_enc' in e and e['notes_enc']:
            plain = _decrypt(e['notes_enc'], old_key)
            e['notes_enc'] = _encrypt(plain, new_key)
    save_json(_epath(dd, vid), ed)

    d = _lv(dd)
    vx = next(x for x in d['vaults'] if x['id'] == vid)
    vx['salt']   = new_salt
    vx['canary'] = _encrypt(_CANARY, new_key)
    _sv(dd, d)


# ── Entries ────────────────────────────────────────────────────────────────────

def list_entries(dd, vid: str) -> list:
    """Retourne les entrées sans les champs chiffrés."""
    ed = load_json(_epath(dd, vid)) or {'entries': []}
    return [_safe_entry(e) for e in ed['entries']]


def _safe_entry(e: dict) -> dict:
    return {k: e[k] for k in ('id', 'type', 'title', 'username', 'url', 'tags', 'created_at', 'updated_at') if k in e}


def _check_vault_key(dd, vid: str, master_pw: str) -> bytes:
    v = get_vault_raw(dd, vid)
    if not v:
        raise ServiceError('Coffre introuvable', 404)
    key = _derive_key(master_pw, v['salt'])
    if not _check_canary(v['canary'], key):
        raise ServiceError('Master password incorrect', 401)
    return key


def create_entry(dd, vid: str, master_pw: str, entry_type: str,
                 title: str, username: str = '', url: str = '',
                 tags: list = None, secret: str = '', notes: str = '') -> dict:
    if not title:
        raise ServiceError('Titre requis')
    if entry_type not in ('login', 'ssh_token', 'note'):
        raise ServiceError('Type invalide')
    key = _check_vault_key(dd, vid, master_pw)
    ed  = load_json(_epath(dd, vid)) or {'entries': []}
    now = datetime.utcnow().isoformat()
    entry = {
        'id':         uuid.uuid4().hex[:12],
        'type':       entry_type,
        'title':      title,
        'username':   username or '',
        'url':        url or '',
        'tags':       tags or [],
        'secret_enc': _encrypt(secret or '', key),
        'notes_enc':  _encrypt(notes or '', key) if notes else None,
        'created_at': now,
        'updated_at': now,
    }
    ed['entries'].append(entry)
    save_json(_epath(dd, vid), ed)
    return _safe_entry(entry)


def update_entry(dd, vid: str, eid: str, master_pw: str, **kw) -> dict:
    key = _check_vault_key(dd, vid, master_pw)
    ed  = load_json(_epath(dd, vid)) or {'entries': []}
    e   = next((x for x in ed['entries'] if x['id'] == eid), None)
    if not e:
        raise ServiceError('Entrée introuvable', 404)
    for k in ('title', 'username', 'url', 'tags'):
        if k in kw and kw[k] is not None:
            e[k] = kw[k]
    if 'secret' in kw and kw['secret'] is not None:
        e['secret_enc'] = _encrypt(kw['secret'], key)
    if 'notes' in kw and kw['notes'] is not None:
        e['notes_enc']  = _encrypt(kw['notes'], key) if kw['notes'] else None
    e['updated_at'] = datetime.utcnow().isoformat()
    save_json(_epath(dd, vid), ed)
    return _safe_entry(e)


def delete_entry(dd, vid: str, eid: str) -> None:
    ed = load_json(_epath(dd, vid)) or {'entries': []}
    ed['entries'] = [x for x in ed['entries'] if x['id'] != eid]
    save_json(_epath(dd, vid), ed)


def decrypt_entry(dd, vid: str, eid: str, master_pw: str) -> dict:
    key = _check_vault_key(dd, vid, master_pw)
    ed  = load_json(_epath(dd, vid)) or {'entries': []}
    e   = next((x for x in ed['entries'] if x['id'] == eid), None)
    if not e:
        raise ServiceError('Entrée introuvable', 404)
    secret = _decrypt(e['secret_enc'], key) if e.get('secret_enc') else ''
    notes  = _decrypt(e['notes_enc'],  key) if e.get('notes_enc')  else ''
    return {'secret': secret, 'notes': notes}
