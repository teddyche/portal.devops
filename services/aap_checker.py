"""
Service AAP Checker — gestion des instances, snapshots chiffrés, diff et génération du projet ZIP.
"""
import gzip
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


def import_snapshot(dd, iid, enc_bytes):
    inst = get_instance(dd, iid)
    if not inst:
        raise ServiceError('Instance introuvable', 404)
    try:
        r = subprocess.run(
            ['openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', '100000',
             '-pass', f'pass:{inst["enc_key"]}'],
            input=enc_bytes, capture_output=True, timeout=30,
        )
        if r.returncode != 0:
            raise ServiceError('Déchiffrement échoué — clé incorrecte ou fichier corrompu')
        data = json.loads(gzip.decompress(r.stdout))
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
    for sec in ('job_templates', 'workflow_job_templates', 'schedules',
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
        zf.writestr('aap-checker-project/README.md',                          _README)
        zf.writestr('aap-checker-project/site.yml',                           _SITE_YML)
        zf.writestr('aap-checker-project/group_vars/all.yml',                 _GROUP_VARS)
        zf.writestr('aap-checker-project/roles/collect_aap/tasks/main.yml',   _TASKS)
        zf.writestr('aap-checker-project/requirements.yml',                   _REQUIREMENTS)
    buf.seek(0)
    return buf.read()


# ── Ansible project templates ──────────────────────────────────────────────────

_README = """\
# AAP Checker — Projet de collecte

## Prérequis
- Ansible >= 2.9
- `openssl` disponible sur le nœud d'exécution
- Collection `community.general` (module `mail`)

## Configuration
Éditez `group_vars/all.yml` avec vos paramètres.
La clé `portal_enc_key` est affichée dans AppOps → AAP Checker → instance → ⚙ Config.

## Utilisation
Importez ce projet dans AAP/AWX, créez un Job Template avec `site.yml` et lancez-le.
Ou en ligne de commande : `ansible-playbook site.yml`

## Flux
1. Collecte des données via API REST `/api/v2` (pas de collection awx/controller requise)
2. JSON → gzip → chiffrement AES-256-CBC (openssl)
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

_GROUP_VARS = """\
---
# ── Instance AAP/AWX ────────────────────────────────────────────────────────────
aap_url: "https://VOTRE-URL-AAP"           # URL sans slash final
aap_token: "VOTRE-TOKEN"                   # OAuth2 Application Token
aap_validate_certs: true                   # false si certificat auto-signé

# ── Portail AppOps ──────────────────────────────────────────────────────────────
instance_name: "Production"                # Identique au nom de l'instance dans le portail
portal_enc_key: "VOTRE-CLE-DU-PORTAIL"    # AppOps → AAP Checker → instance → ⚙ Config

# ── Configuration mail ──────────────────────────────────────────────────────────
mail_host: "smtp.example.com"
mail_port: 25
mail_from: "aap-checker@example.com"
mail_to: "ops@example.com"
# mail_username: ""
# mail_password: ""
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
    url: "{{ aap_url }}/api/v2/job_templates/?page_size=200&order_by=name"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _jt

- name: "AAP | Jobs récents (200)"
  uri:
    url: "{{ aap_url }}/api/v2/jobs/?page_size=200&order_by=-finished"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _jobs

- name: "AAP | Workflow job templates"
  uri:
    url: "{{ aap_url }}/api/v2/workflow_job_templates/?page_size=200&order_by=name"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _wfjt

- name: "AAP | Workflow jobs récents (200)"
  uri:
    url: "{{ aap_url }}/api/v2/workflow_jobs/?page_size=200&order_by=-finished"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _wfjobs

- name: "AAP | Schedules"
  uri:
    url: "{{ aap_url }}/api/v2/schedules/?page_size=200"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _schedules

- name: "AAP | Tokens"
  uri:
    url: "{{ aap_url }}/api/v2/tokens/?page_size=200"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _tokens

- name: "AAP | Credentials"
  uri:
    url: "{{ aap_url }}/api/v2/credentials/?page_size=200&order_by=name"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _creds

- name: "AAP | Inventories"
  uri:
    url: "{{ aap_url }}/api/v2/inventories/?page_size=200&order_by=name"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _inv

- name: "AAP | Hosts"
  uri:
    url: "{{ aap_url }}/api/v2/hosts/?page_size=500&order_by=name"
    headers: {Authorization: "Bearer {{ aap_token }}"}
    validate_certs: "{{ aap_validate_certs | default(true) }}"
  register: _hosts

- name: "AAP | Assembler snapshot"
  set_fact:
    _snap:
      manifest:
        instance_name: "{{ instance_name }}"
        aap_url:       "{{ aap_url }}"
        aap_version:   "{{ _ping.json.version | default('unknown') }}"
        collected_at:  "{{ ansible_date_time.iso8601 }}"
      job_templates:          "{{ _jt.json.results      | default([]) }}"
      jobs:                   "{{ _jobs.json.results    | default([]) }}"
      workflow_job_templates: "{{ _wfjt.json.results    | default([]) }}"
      workflow_jobs:          "{{ _wfjobs.json.results  | default([]) }}"
      schedules:              "{{ _schedules.json.results | default([]) }}"
      tokens:                 "{{ _tokens.json.results  | default([]) }}"
      credentials:            "{{ _creds.json.results   | default([]) }}"
      inventories:            "{{ _inv.json.results     | default([]) }}"
      hosts:                  "{{ _hosts.json.results   | default([]) }}"

- name: "PKG | Écrire JSON"
  copy:
    content: "{{ _snap | to_json }}"
    dest: "/tmp/aap_snap_{{ instance_name | replace(' ', '_') }}.json"

- name: "PKG | Compresser"
  command: "gzip -f '/tmp/aap_snap_{{ instance_name | replace(' ', '_') }}.json'"

- name: "PKG | Chiffrer (AES-256-CBC)"
  command: >
    openssl enc -aes-256-cbc -pbkdf2 -iter 100000
    -in  "/tmp/aap_snap_{{ instance_name | replace(' ', '_') }}.json.gz"
    -out "/tmp/aap_snap_{{ instance_name | replace(' ', '_') }}.enc"
    -pass "pass:{{ portal_enc_key }}"

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

_REQUIREMENTS = """\
---
collections:
  - name: community.general
    version: ">=7.0.0"
"""
