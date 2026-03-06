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
    save_json(_spath(dd, iid, sid), data)
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
        zf.writestr('aap-checker-project/encrypt_snapshot.py',                              _ENCRYPT_PY)
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
└── encrypt_snapshot.py         ← chiffrement AES-256 (Python)
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

1. Collecte des données via API REST `/api/v2` (aucune collection awx/controller requise)
2. JSON → gzip → chiffrement AES-256-CBC (Python — `encrypt_snapshot.py`)
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

# ── Limites de collecte ───────────────────────────────────────────────────────
# Nombre d'objets récupérés par endpoint (job templates, workflows, credentials…)
aap_page_size_objects: 400
# Nombre de jobs/workflow_jobs récents récupérés
aap_page_size_jobs: 400
# Nombre de hosts récupérés
aap_page_size_hosts: 1000
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
# ── Collecte AAP via API REST v2 (pas de collection awx/controller requise) ────

- name: "AAP | Version"
  uri:
    url: "{{ aap_url }}/api/v2/ping/"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _ping

- name: "AAP | Job templates"
  uri:
    url: "{{ aap_url }}/api/v2/job_templates/?page_size={{ aap_page_size_objects | default(400) }}&order_by=name"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _jt

- name: "AAP | Jobs récents"
  uri:
    url: "{{ aap_url }}/api/v2/jobs/?page_size={{ aap_page_size_jobs | default(400) }}&order_by=-finished"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _jobs

- name: "AAP | Workflow job templates"
  uri:
    url: "{{ aap_url }}/api/v2/workflow_job_templates/?page_size={{ aap_page_size_objects | default(400) }}&order_by=name"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _wfjt

- name: "AAP | Workflow jobs récents"
  uri:
    url: "{{ aap_url }}/api/v2/workflow_jobs/?page_size={{ aap_page_size_jobs | default(400) }}&order_by=-finished"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _wfjobs

- name: "AAP | Projects"
  uri:
    url: "{{ aap_url }}/api/v2/projects/?page_size={{ aap_page_size_objects | default(400) }}&order_by=name"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _projects

- name: "AAP | Schedules"
  uri:
    url: "{{ aap_url }}/api/v2/schedules/?page_size={{ aap_page_size_objects | default(400) }}"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _schedules

- name: "AAP | Tokens"
  uri:
    url: "{{ aap_url }}/api/v2/tokens/?page_size={{ aap_page_size_objects | default(400) }}"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _tokens

- name: "AAP | Credentials"
  uri:
    url: "{{ aap_url }}/api/v2/credentials/?page_size={{ aap_page_size_objects | default(400) }}&order_by=name"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _creds

- name: "AAP | Inventories"
  uri:
    url: "{{ aap_url }}/api/v2/inventories/?page_size={{ aap_page_size_objects | default(400) }}&order_by=name"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _inv

- name: "AAP | Hosts"
  uri:
    url: "{{ aap_url }}/api/v2/hosts/?page_size={{ aap_page_size_hosts | default(1000) }}&order_by=name"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _hosts

- name: "AAP | Organizations"
  uri:
    url: "{{ aap_url }}/api/v2/organizations/?page_size={{ aap_page_size_objects | default(400) }}"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _orgs

- name: "AAP | Teams"
  uri:
    url: "{{ aap_url }}/api/v2/teams/?page_size={{ aap_page_size_objects | default(400) }}"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _teams

- name: "AAP | Assembler snapshot"
  set_fact:
    _snap:
      manifest:
        instance_name: "{{ instance_name }}"
        aap_url:       "{{ aap_url }}"
        aap_version:   "{{ _ping.json.version | default('unknown') }}"
        collected_at:  "{{ ansible_date_time.iso8601 }}"
      job_templates:          "{{ _jt.json.results       | default([]) }}"
      jobs:                   "{{ _jobs.json.results     | default([]) }}"
      workflow_job_templates: "{{ _wfjt.json.results     | default([]) }}"
      workflow_jobs:          "{{ _wfjobs.json.results   | default([]) }}"
      projects:               "{{ _projects.json.results | default([]) }}"
      schedules:              "{{ _schedules.json.results | default([]) }}"
      tokens:                 "{{ _tokens.json.results   | default([]) }}"
      credentials:            "{{ _creds.json.results    | default([]) }}"
      inventories:            "{{ _inv.json.results      | default([]) }}"
      hosts:                  "{{ _hosts.json.results    | default([]) }}"
      organizations:          "{{ _orgs.json.results     | default([]) }}"
      teams:                  "{{ _teams.json.results    | default([]) }}"

- name: "PKG | Écrire JSON"
  copy:
    content: "{{ _snap | to_json }}"
    dest: "/tmp/aap_snap_{{ instance_name | replace(' ', '_') }}.json"

- name: "PKG | Compresser"
  command: "gzip -f '/tmp/aap_snap_{{ instance_name | replace(' ', '_') }}.json'"

- name: "PKG | Chiffrer (AES-256-CBC Python)"
  vars:
    _snap_base: "/tmp/aap_snap_{{ instance_name | replace(' ', '_') }}"
  script:
    cmd: encrypt_snapshot.py
  args:
    executable: python3
  environment:
    SNAP_INPUT:  "{{ _snap_base }}.json.gz"
    SNAP_OUTPUT: "{{ _snap_base }}.enc"
    ENC_KEY:     "{{ portal_enc_key }}"

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
    path: "{{ item }}"
    state: absent
  loop:
    - "/tmp/aap_snap_{{ instance_name | replace(' ', '_') }}.json.gz"
    - "/tmp/aap_snap_{{ instance_name | replace(' ', '_') }}.enc"
"""

_ENCRYPT_PY = """\
#!/usr/bin/env python3
\"\"\"
encrypt_snapshot.py — Chiffrement AES-256-CBC PBKDF2-SHA256 (compatible openssl Salted__)
Variables d'environnement : SNAP_INPUT, SNAP_OUTPUT, ENC_KEY
\"\"\"
import hashlib
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

password = os.environ['ENC_KEY'].encode()
salt     = os.urandom(8)
key_iv   = hashlib.pbkdf2_hmac('sha256', password, salt, 100000, dklen=48)
key, iv  = key_iv[:32], key_iv[32:]

with open(os.environ['SNAP_INPUT'], 'rb') as f:
    data = f.read()

# PKCS7 padding
pad_len = 16 - (len(data) % 16)
data += bytes([pad_len]) * pad_len

cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
encrypted = encryptor.update(data) + encryptor.finalize()

# Format Salted__ (compatible openssl -aes-256-cbc -pbkdf2)
with open(os.environ['SNAP_OUTPUT'], 'wb') as f:
    f.write(b'Salted__' + salt + encrypted)
"""

_REQUIREMENTS = """\
---
collections:
  - name: community.general
    version: ">=7.0.0"
"""
