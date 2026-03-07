"""
Service AAP Checker — gestion des instances, snapshots chiffrés, diff et génération du projet ZIP.
"""
import gzip
import hashlib
import io
import json
import os
import secrets
import shutil
import subprocess
import uuid
import zipfile
from datetime import datetime

from services.store import ServiceError, load_json, save_json


def _root(dd):          return os.path.join(dd, 'aap_checker')
def _ipath(dd):         return os.path.join(_root(dd), 'instances.json')
def _sdir(dd, iid):     return os.path.join(_root(dd), 'snapshots', iid)
def _spath(dd, iid, sid): return os.path.join(_sdir(dd, iid), sid + '.json')

def _li(dd):    return load_json(_ipath(dd)) or {'instances': []}
def _si(dd, d): save_json(_ipath(dd), d)


# ── Instances ──────────────────────────────────────────────────────────────────

def list_instances(dd):
    return _li(dd)['instances']


def get_instance(dd, iid):
    return next((i for i in list_instances(dd) if i['id'] == iid), None)


def create_instance(dd, name, description='', color='#c62828', env_type=''):
    if not name:
        raise ServiceError('Nom requis')
    d = _li(dd)
    inst = {
        'id':          uuid.uuid4().hex[:12],
        'name':        name,
        'description': description,
        'color':       color,
        'env_type':    env_type,
        'enc_key':     secrets.token_hex(32),
        'created_at':  datetime.utcnow().isoformat(),
    }
    d['instances'].append(inst)
    _si(dd, d)
    return inst


def update_instance(dd, iid, **kw):
    d = _li(dd)
    inst = next((i for i in d['instances'] if i['id'] == iid), None)
    if not inst:
        raise ServiceError('Instance introuvable', 404)
    for k in ('name', 'description', 'color', 'env_type'):
        if k in kw and kw[k] is not None:
            inst[k] = kw[k]
    _si(dd, d)
    return inst


def delete_instance(dd, iid):
    d = _li(dd)
    d['instances'] = [i for i in d['instances'] if i['id'] != iid]
    _si(dd, d)
    p = _sdir(dd, iid)
    if os.path.isdir(p):
        shutil.rmtree(p)


# ── Snapshots ──────────────────────────────────────────────────────────────────

def list_snapshots(dd, iid):
    d = _sdir(dd, iid)
    if not os.path.isdir(d):
        return []
    out = []
    for f in os.listdir(d):
        if not f.endswith('.json'):
            continue
        s = load_json(os.path.join(d, f))
        if not s:
            continue
        m = s.get('manifest', {})
        out.append({
            'id':            s.get('id', f[:-5]),
            'collected_at':  m.get('collected_at', ''),
            'aap_url':       m.get('aap_url', ''),
            'aap_version':   m.get('aap_version', ''),
            'instance_name': m.get('instance_name', ''),
        })
    return sorted(out, key=lambda x: x['collected_at'], reverse=True)


def get_snapshot(dd, iid, sid):
    return load_json(_spath(dd, iid, sid))


def _decrypt_enc(enc_bytes: bytes, key_hex: str) -> bytes:
    """Déchiffre un snapshot .enc — AES-256-CBC PBKDF2-SHA256, format Salted__ (openssl/Python compat)."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        if enc_bytes[:8] != b'Salted__':
            raise ServiceError('Format invalide — header Salted__ manquant')
        salt       = enc_bytes[8:16]
        ciphertext = enc_bytes[16:]
        password   = key_hex.encode()
        key_iv     = hashlib.pbkdf2_hmac('sha256', password, salt, 100000, dklen=48)
        key, iv    = key_iv[:32], key_iv[32:]
        cipher     = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor  = cipher.decryptor()
        padded     = decryptor.update(ciphertext) + decryptor.finalize()
        pad_len    = padded[-1]
        return padded[:-pad_len] if 1 <= pad_len <= 16 else padded

    except (ImportError, ModuleNotFoundError):
        # Fallback openssl si cryptography lib absente
        r = subprocess.run(
            ['openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', '100000',
             '-pass', f'pass:{key_hex}'],
            input=enc_bytes, capture_output=True, timeout=30,
        )
        if r.returncode != 0:
            raise ServiceError('Déchiffrement échoué — clé incorrecte ou fichier corrompu')
        return r.stdout
    except ServiceError:
        raise
    except Exception as e:
        raise ServiceError(f'Déchiffrement échoué : {e}')


def import_snapshot(dd, iid, enc_bytes):
    inst = get_instance(dd, iid)
    if not inst:
        raise ServiceError('Instance introuvable', 404)
    try:
        raw  = _decrypt_enc(enc_bytes, inst['enc_key'])
        data = json.loads(gzip.decompress(raw))
    except ServiceError:
        raise
    except subprocess.TimeoutExpired:
        raise ServiceError('Timeout déchiffrement')
    except Exception as e:
        raise ServiceError(f'Format invalide : {e}')

    sid = uuid.uuid4().hex[:12]
    data['id'] = sid
    os.makedirs(_sdir(dd, iid), exist_ok=True)
    save_json(_spath(dd, iid, sid), data, max_bytes=None)
    return sid


def delete_snapshot(dd, iid, sid):
    p = _spath(dd, iid, sid)
    if os.path.exists(p):
        os.remove(p)


# ── Diff ───────────────────────────────────────────────────────────────────────

def diff_snapshots(dd, iid, sid_a, sid_b):
    a = get_snapshot(dd, iid, sid_a)
    b = get_snapshot(dd, iid, sid_b)
    if not a or not b:
        raise ServiceError('Snapshot introuvable', 404)
    result = {}
    for sec in ('job_templates', 'workflow_job_templates', 'projects', 'schedules',
                'tokens', 'credentials', 'inventories', 'hosts'):
        la = _tolist(a.get(sec))
        lb = _tolist(b.get(sec))
        ka = {_key(i, idx): i for idx, i in enumerate(la)}
        kb = {_key(i, idx): i for idx, i in enumerate(lb)}
        result[sec] = {
            'added':   [_slim(v) for k, v in kb.items() if k not in ka],
            'removed': [_slim(v) for k, v in ka.items() if k not in kb],
            'count_a': len(la),
            'count_b': len(lb),
        }
    return {
        'manifest_a': a.get('manifest', {}),
        'manifest_b': b.get('manifest', {}),
        'diff':       result,
    }


def _tolist(v):
    if isinstance(v, list): return v
    if isinstance(v, dict): return v.get('results', [])
    return []


def _key(item, idx):
    return str(item.get('id') or item.get('name') or idx)


def _slim(item):
    return {
        'id':   item.get('id'),
        'name': item.get('name') or item.get('description') or str(item.get('id', '?')),
    }


# ── Project ZIP ────────────────────────────────────────────────────────────────

def generate_project_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('aap-checker-project/README.md',                                        _README)
        zf.writestr('aap-checker-project/site.yml',                                         _SITE_YML)
        zf.writestr('aap-checker-project/group_vars/all.yml',                               _GROUP_VARS_GLOBAL)
        zf.writestr('aap-checker-project/inventories/HORS_PROD/hosts',                      _HOSTS_FILE)
        zf.writestr('aap-checker-project/inventories/HORS_PROD/group_vars/all.yml',         _GROUP_VARS_HP)
        zf.writestr('aap-checker-project/inventories/PROD/hosts',                           _HOSTS_FILE)
        zf.writestr('aap-checker-project/inventories/PROD/group_vars/all.yml',              _GROUP_VARS_PROD)
        zf.writestr('aap-checker-project/roles/collect_aap/tasks/main.yml',                 _TASKS)
        zf.writestr('aap-checker-project/collect_snapshot.py',                              _COLLECT_PY)
        zf.writestr('aap-checker-project/requirements.yml',                                 _REQUIREMENTS)
    buf.seek(0)
    return buf.read()


# ── Ansible project templates ──────────────────────────────────────────────────

_README = """\
# AAP Checker — Projet de collecte

## Structure

```
aap-checker-project/
├── site.yml
├── group_vars/all.yml          ← variables globales (défauts)
├── inventories/
│   ├── HORS_PROD/
│   │   ├── hosts
│   │   └── group_vars/all.yml  ← paramètres Hors-Production
│   └── PROD/
│       ├── hosts
│       └── group_vars/all.yml  ← paramètres Production
├── roles/collect_aap/tasks/main.yml
└── collect_snapshot.py         ← collecte paginée + gzip + chiffrement AES-256 (Python)
```

## Prérequis

- Ansible >= 2.9
- Python 3 avec `cryptography` (`pip install cryptography`)
- Collection `community.general` (module `mail`)

## Configuration

Éditez les fichiers `inventories/<ENV>/group_vars/all.yml` avec vos paramètres.
La clé `portal_enc_key` est affichée dans AppOps → AAP Checker → instance → ⚙ Config.

## Utilisation

```bash
# Hors-Production
ansible-playbook site.yml -i inventories/HORS_PROD/

# Production
ansible-playbook site.yml -i inventories/PROD/
```

Ou en job template AAP/AWX : définissez l'inventaire par environnement, cela permet
d'avoir les variables spécifiques à chaque env au niveau de l'inventaire sur AAP.

## Flux

1. `collect_snapshot.py` interroge l'API REST `/api/v2` avec pagination automatique (`next`)
2. JSON → gzip → chiffrement AES-256-CBC (tout dans `collect_snapshot.py`)
3. Envoi par mail (pièce jointe `.enc`)
4. Importation dans AppOps → AAP Checker → instance → Importer snapshot
"""

_SITE_YML = """\
---
- name: AAP Checker — Collecte et envoi snapshot
  hosts: localhost
  connection: local
  gather_facts: true
  roles:
    - collect_aap
"""

_HOSTS_FILE = """\
all:
  hosts:
    localhost:
      ansible_connection: local
"""

_GROUP_VARS_GLOBAL = """\
---
# Variables globales — surchargées par inventories/<ENV>/group_vars/all.yml
# La collecte est gérée par collect_snapshot.py avec pagination automatique (page_size=200).
"""

_GROUP_VARS_HP = """\
---
# ── Instance AAP/AWX — Hors-Production ───────────────────────────────────────
aap_url: "https://VOTRE-URL-AAP-HP"          # URL sans slash final
aap_token: "{{ api_key_aap }}"               # OAuth2 Application Token (vault ou credential AAP)
aap_validate_certs: false                    # false si certificat auto-signé

# ── Portail AppOps ────────────────────────────────────────────────────────────
instance_name: "Hors-Production"             # Identique au nom de l'instance dans le portail
portal_enc_key: "VOTRE-CLE-DU-PORTAIL-HP"   # AppOps → AAP Checker → instance → ⚙ Config

# ── Configuration mail ────────────────────────────────────────────────────────
mail_host: "smtp.example.com"
mail_port: 25
mail_from: "aap-checker-hp@example.com"
mail_to: "ops@example.com"
"""

_GROUP_VARS_PROD = """\
---
# ── Instance AAP/AWX — Production ────────────────────────────────────────────
aap_url: "https://VOTRE-URL-AAP-PROD"        # URL sans slash final
aap_token: "{{ api_key_aap }}"               # OAuth2 Application Token (vault ou credential AAP)
aap_validate_certs: true                     # false si certificat auto-signé

# ── Portail AppOps ────────────────────────────────────────────────────────────
instance_name: "Production"                  # Identique au nom de l'instance dans le portail
portal_enc_key: "VOTRE-CLE-DU-PORTAIL-PROD" # AppOps → AAP Checker → instance → ⚙ Config

# ── Configuration mail ────────────────────────────────────────────────────────
mail_host: "smtp.example.com"
mail_port: 25
mail_from: "aap-checker-prod@example.com"
mail_to: "ops@example.com"
"""

_TASKS = """\
---
# ── Collecte AAP via collect_snapshot.py (pagination automatique) ────────────

- name: "AAP | Ping (version check)"
  uri:
    url: "{{ aap_url }}/api/v2/ping/"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _ping

- name: "PKG | Collecter + chiffrer snapshot"
  script:
    cmd: collect_snapshot.py
  args:
    executable: python3
  environment:
    AAP_URL:        "{{ aap_url }}"
    AAP_TOKEN:      "{{ aap_token }}"
    SNAP_OUTPUT:    "/tmp/aap_snap_{{ instance_name | replace(' ', '_') }}.enc"
    ENC_KEY:        "{{ portal_enc_key }}"
    INSTANCE_NAME:  "{{ instance_name }}"
    VALIDATE_CERTS: "{{ aap_validate_certs | default(true) }}"
  no_log: true
  register: _collect

- name: "PKG | Résumé collecte"
  debug:
    msg: "{{ _collect.stdout_lines }}"

- name: "MAIL | Envoyer snapshot"
  community.general.mail:
    host:    "{{ mail_host }}"
    port:    "{{ mail_port | default(25) }}"
    from:    "{{ mail_from }}"
    to:      "{{ mail_to }}"
    subject: "AAP Checker — {{ instance_name }} — {{ ansible_date_time.date }}"
    body: |
      Snapshot AAP Checker
      Instance  : {{ instance_name }}
      URL AAP   : {{ aap_url }}
      Version   : {{ _ping.json.version | default('?') }}
      Collecté  : {{ ansible_date_time.iso8601 }}

      → Importer le fichier joint dans AppOps > AAP Checker > {{ instance_name }} > Importer snapshot
    attach:
      - "/tmp/aap_snap_{{ instance_name | replace(' ', '_') }}.enc"

- name: "PKG | Nettoyage"
  file:
    path: "/tmp/aap_snap_{{ instance_name | replace(' ', '_') }}.enc"
    state: absent
"""

_COLLECT_PY = """\
#!/usr/bin/env python3
\"\"\"
collect_snapshot.py — Collecte paginée AAP API v2 + gzip + chiffrement AES-256-CBC
Variables d'environnement : AAP_URL, AAP_TOKEN, SNAP_OUTPUT, ENC_KEY, INSTANCE_NAME, VALIDATE_CERTS
\"\"\"
import gzip
import hashlib
import json
import os
import ssl
from datetime import datetime
from urllib.request import Request, urlopen


def collect_all(base_url, token, path, ctx, page_size=200):
    \"\"\"Suit la pagination `next` jusqu'à épuisement des résultats.\"\"\"
    results = []
    sep = '&' if '?' in path else '?'
    url = f"{base_url}{path}{sep}page_size={page_size}"
    while url:
        req = Request(url, headers={"Authorization": f"Bearer {token}"})
        with urlopen(req, context=ctx, timeout=60) as r:
            data = json.loads(r.read().decode())
        results.extend(data.get("results", []))
        nxt = data.get("next")
        url = (nxt if nxt.startswith("http") else base_url + nxt) if nxt else None
    return results


def collect_scalar(base_url, token, path, ctx):
    req = Request(f"{base_url}{path}", headers={"Authorization": f"Bearer {token}"})
    with urlopen(req, context=ctx, timeout=30) as r:
        return json.loads(r.read().decode())


aap_url        = os.environ['AAP_URL'].rstrip('/')
aap_token      = os.environ['AAP_TOKEN']
snap_output    = os.environ['SNAP_OUTPUT']
enc_key        = os.environ['ENC_KEY']
instance_name  = os.environ.get('INSTANCE_NAME', 'AAP')
validate_certs = os.environ.get('VALIDATE_CERTS', 'true').lower() not in ('false', '0', 'no')

ctx = ssl.create_default_context() if validate_certs else ssl._create_unverified_context()

print(f"[collect] Connexion à {aap_url}...", flush=True)
ping = collect_scalar(aap_url, aap_token, '/api/v2/ping/', ctx)
aap_version = ping.get('version', 'unknown')
print(f"[collect] Version AAP : {aap_version}", flush=True)

endpoints = [
    ('job_templates',          '/api/v2/job_templates/?order_by=name',          200),
    ('jobs',                   '/api/v2/jobs/?order_by=-finished',               200),
    ('workflow_job_templates', '/api/v2/workflow_job_templates/?order_by=name',  200),
    ('workflow_jobs',          '/api/v2/workflow_jobs/?order_by=-finished',      200),
    ('projects',               '/api/v2/projects/?order_by=name',                200),
    ('schedules',              '/api/v2/schedules/',                              200),
    ('tokens',                 '/api/v2/tokens/',                                 200),
    ('credentials',            '/api/v2/credentials/?order_by=name',             200),
    ('inventories',            '/api/v2/inventories/?order_by=name',             200),
    ('hosts',                  '/api/v2/hosts/?order_by=name',                   500),
    ('organizations',          '/api/v2/organizations/',                          200),
    ('teams',                  '/api/v2/teams/',                                  200),
]

snap = {
    'manifest': {
        'instance_name': instance_name,
        'aap_url':       aap_url,
        'aap_version':   aap_version,
        'collected_at':  datetime.utcnow().isoformat() + 'Z',
    }
}

for key, path, page_size in endpoints:
    print(f"[collect] {key}...", flush=True)
    snap[key] = collect_all(aap_url, aap_token, path, ctx, page_size)
    print(f"[collect]   → {len(snap[key])} éléments", flush=True)

# Gzip + chiffrement AES-256-CBC (format Salted__, compatible openssl)
raw = gzip.compress(json.dumps(snap).encode('utf-8'))
print(f"[collect] Compressé : {len(raw)} bytes", flush=True)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

password  = enc_key.encode()
salt      = os.urandom(8)
key_iv    = hashlib.pbkdf2_hmac('sha256', password, salt, 100000, dklen=48)
key, iv   = key_iv[:32], key_iv[32:]
pad_len   = 16 - (len(raw) % 16)
raw      += bytes([pad_len]) * pad_len
cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
encrypted = encryptor.update(raw) + encryptor.finalize()

with open(snap_output, 'wb') as f:
    f.write(b'Salted__' + salt + encrypted)

print(f"[collect] Snapshot chiffré → {snap_output}", flush=True)
"""

_REQUIREMENTS = """\
---
collections:
  - name: community.general
    version: ">=7.0.0"
"""
