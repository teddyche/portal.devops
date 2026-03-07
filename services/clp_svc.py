"""
Service CLP Builder — gestion des instances, configurations et templates de rôles.
"""
import os
import shutil
import uuid
from datetime import datetime, timezone, timedelta

from services import store
from services.store import ServiceError

# ── Middlewares intégrés (builtin) ───────────────────────────────────────────

_BUILTIN_MWS = [
    {'id': 'apache',    'label': 'Apache httpd',    'icon': 'apache',    'description': 'Serveur web Apache HTTP Server',          'builtin': True},
    {'id': 'tomcat',    'label': 'Tomcat',          'icon': 'tomcat',    'description': 'Serveur d\'application Java Tomcat',        'builtin': True},
    {'id': 'mq',        'label': 'IBM MQ',          'icon': 'mq',        'description': 'Middleware de messagerie IBM MQ',           'builtin': True},
    {'id': 'websphere', 'label': 'WebSphere AS',    'icon': 'websphere', 'description': 'Serveur d\'application IBM WebSphere',      'builtin': True},
    {'id': 'php',       'label': 'PHP-FPM',         'icon': 'php',       'description': 'FastCGI Process Manager PHP',               'builtin': True},
    {'id': 'jboss',     'label': 'JBoss/WildFly',   'icon': 'jboss',     'description': 'Serveur d\'application JBoss EAP/WildFly',  'builtin': True},
    {'id': 'cft',       'label': 'Axway CFT',       'icon': 'cft',       'description': 'Transfert de fichiers Axway CFT',           'builtin': True},
]

_FILE_KEYS = ('defaults', 'tasks_main', 'tasks_stop', 'tasks_start', 'tasks_status', 'handlers')

# ── Chemins ──────────────────────────────────────────────────────────────────

def _instances_file(dd: str) -> str:
    return os.path.join(dd, 'clp', 'instances.json')

def _instance_dir(dd: str, iid: str) -> str:
    return os.path.join(dd, 'clp', 'instances', iid)

def _config_file(dd: str, iid: str) -> str:
    return os.path.join(_instance_dir(dd, iid), 'config.json')

def _template_path(dd: str, iid: str, role_id: str, file_key: str) -> str:
    return os.path.join(_instance_dir(dd, iid), 'templates', role_id, file_key + '.yml')

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

# ── Instances ─────────────────────────────────────────────────────────────────

def _load_instances(dd: str) -> dict:
    return store.load_json(_instances_file(dd)) or {'instances': []}

def _save_instances(dd: str, data: dict) -> None:
    store.save_json(_instances_file(dd), data)

def list_instances(dd: str) -> list:
    return _load_instances(dd)['instances']

def get_instance(dd: str, iid: str) -> dict:
    for inst in _load_instances(dd)['instances']:
        if inst['id'] == iid:
            return inst
    raise ServiceError('Instance introuvable', 404)

def create_instance(dd: str, name: str, description: str = '', color: str = '#607d8b') -> dict:
    name = name.strip()
    if not name:
        raise ServiceError('Nom requis', 400)
    data = _load_instances(dd)
    iid  = uuid.uuid4().hex[:12]
    inst = {'id': iid, 'name': name, 'description': description.strip(),
            'color': color or '#607d8b', 'created_at': _now()}
    data['instances'].append(inst)
    _save_instances(dd, data)
    _init_config(dd, iid)
    return inst

def _init_config(dd: str, iid: str) -> None:
    now = _now()
    cfg = {
        'fqdns': {'low': '', 'mid': '', 'prod': ''},
        'middlewares': [{**mw, 'status': 'enabled', 'added_at': now} for mw in _BUILTIN_MWS],
        'extra_roles': [],
    }
    store.save_json(_config_file(dd, iid), cfg)

def update_instance(dd: str, iid: str, name: str = None, description: str = None,
                    color: str = None) -> dict:
    data = _load_instances(dd)
    for inst in data['instances']:
        if inst['id'] == iid:
            if name        is not None: inst['name']        = name.strip()
            if description is not None: inst['description'] = description.strip()
            if color       is not None: inst['color']       = color
            _save_instances(dd, data)
            return inst
    raise ServiceError('Instance introuvable', 404)

def delete_instance(dd: str, iid: str) -> None:
    data = _load_instances(dd)
    before = len(data['instances'])
    data['instances'] = [i for i in data['instances'] if i['id'] != iid]
    if len(data['instances']) == before:
        raise ServiceError('Instance introuvable', 404)
    _save_instances(dd, data)
    trash = os.path.join(dd, 'clp', '.trash')
    store.soft_delete_dir(_instance_dir(dd, iid), 'clp_instance', trash)

# ── Configuration ─────────────────────────────────────────────────────────────

def get_config(dd: str, iid: str) -> dict:
    get_instance(dd, iid)
    cfg = store.load_json(_config_file(dd, iid))
    if cfg is None:
        _init_config(dd, iid)
        cfg = store.load_json(_config_file(dd, iid))
    now = datetime.now(timezone.utc)
    for item in cfg.get('middlewares', []) + cfg.get('extra_roles', []):
        try:
            added = datetime.fromisoformat(item['added_at'])
            item['is_new'] = (now - added).days < 30
        except Exception:
            item['is_new'] = False
    return cfg

def update_fqdns(dd: str, iid: str, low: str, mid: str, prod: str) -> dict:
    get_instance(dd, iid)
    cfg = store.load_json(_config_file(dd, iid)) or {}
    cfg['fqdns'] = {'low': low.strip(), 'mid': mid.strip(), 'prod': prod.strip()}
    store.save_json(_config_file(dd, iid), cfg)
    return cfg['fqdns']

# ── Middlewares ────────────────────────────────────────────────────────────────

def add_middleware(dd: str, iid: str, mw_id: str, label: str,
                   icon: str = '🔧', description: str = '') -> dict:
    get_instance(dd, iid)
    mw_id = mw_id.strip().lower().replace(' ', '_')
    if not mw_id or not store.safe_id(mw_id):
        raise ServiceError('ID middleware invalide (alphanumérique, tirets, underscores)', 400)
    cfg = store.load_json(_config_file(dd, iid)) or {}
    if any(m['id'] == mw_id for m in cfg.get('middlewares', [])):
        raise ServiceError(f'Middleware "{mw_id}" déjà présent', 409)
    mw = {'id': mw_id, 'label': label.strip() or mw_id, 'icon': icon or '🔧',
          'description': description.strip(), 'status': 'enabled',
          'added_at': _now(), 'builtin': False}
    cfg.setdefault('middlewares', []).append(mw)
    store.save_json(_config_file(dd, iid), cfg)
    return mw

def update_middleware(dd: str, iid: str, mid: str, **kw) -> dict:
    get_instance(dd, iid)
    cfg = store.load_json(_config_file(dd, iid)) or {}
    for mw in cfg.get('middlewares', []):
        if mw['id'] == mid:
            for k in ('label', 'icon', 'description', 'status'):
                if k in kw and kw[k] is not None:
                    mw[k] = kw[k]
            store.save_json(_config_file(dd, iid), cfg)
            return mw
    raise ServiceError('Middleware introuvable', 404)

def delete_middleware(dd: str, iid: str, mid: str) -> None:
    get_instance(dd, iid)
    cfg = store.load_json(_config_file(dd, iid)) or {}
    before = len(cfg.get('middlewares', []))
    cfg['middlewares'] = [m for m in cfg.get('middlewares', []) if m['id'] != mid]
    if len(cfg['middlewares']) == before:
        raise ServiceError('Middleware introuvable', 404)
    store.save_json(_config_file(dd, iid), cfg)
    tpl_dir = os.path.join(_instance_dir(dd, iid), 'templates', mid)
    shutil.rmtree(tpl_dir, ignore_errors=True)

# ── Autres rôles ──────────────────────────────────────────────────────────────

def add_extra_role(dd: str, iid: str, role_id: str, label: str, description: str = '') -> dict:
    get_instance(dd, iid)
    role_id = role_id.strip().lower().replace(' ', '_')
    if not role_id or not store.safe_id(role_id):
        raise ServiceError('ID rôle invalide', 400)
    cfg = store.load_json(_config_file(dd, iid)) or {}
    all_ids = ([m['id'] for m in cfg.get('middlewares', [])] +
               [r['id'] for r in cfg.get('extra_roles', [])])
    if role_id in all_ids:
        raise ServiceError(f'ID "{role_id}" déjà utilisé', 409)
    role = {'id': role_id, 'label': label.strip() or role_id,
            'description': description.strip(), 'added_at': _now()}
    cfg.setdefault('extra_roles', []).append(role)
    store.save_json(_config_file(dd, iid), cfg)
    return role

def delete_extra_role(dd: str, iid: str, rid: str) -> None:
    get_instance(dd, iid)
    cfg = store.load_json(_config_file(dd, iid)) or {}
    before = len(cfg.get('extra_roles', []))
    cfg['extra_roles'] = [r for r in cfg.get('extra_roles', []) if r['id'] != rid]
    if len(cfg['extra_roles']) == before:
        raise ServiceError('Rôle introuvable', 404)
    store.save_json(_config_file(dd, iid), cfg)
    tpl_dir = os.path.join(_instance_dir(dd, iid), 'templates', rid)
    shutil.rmtree(tpl_dir, ignore_errors=True)

# ── Templates de rôles ────────────────────────────────────────────────────────

def get_template(dd: str, iid: str, role_id: str, file_key: str) -> dict:
    if file_key not in _FILE_KEYS:
        raise ServiceError(f'Clé invalide: {file_key}', 400)
    path = _template_path(dd, iid, role_id, file_key)
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return {'content': f.read(), 'custom': True}
    return {'content': _builtin_template(role_id, file_key), 'custom': False}

def save_template(dd: str, iid: str, role_id: str, file_key: str, content: str) -> None:
    if file_key not in _FILE_KEYS:
        raise ServiceError(f'Clé invalide: {file_key}', 400)
    path = _template_path(dd, iid, role_id, file_key)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    store.cache_invalidate(path)

def reset_template(dd: str, iid: str, role_id: str, file_key: str) -> str:
    path = _template_path(dd, iid, role_id, file_key)
    if os.path.exists(path):
        os.unlink(path)
    return _builtin_template(role_id, file_key)

def get_all_templates(dd: str, iid: str, role_id: str) -> dict:
    return {k: get_template(dd, iid, role_id, k) for k in _FILE_KEYS}

def load_template_overrides(dd: str, iid: str, role_ids: list) -> dict:
    """Charge tous les fichiers de template custom pour les rôles donnés."""
    overrides = {}
    for rid in role_ids:
        mw_ovr = {}
        for fk in _FILE_KEYS:
            path = _template_path(dd, iid, rid, fk)
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    mw_ovr[fk] = f.read()
        if mw_ovr:
            overrides[rid] = mw_ovr
    return overrides

def _builtin_template(role_id: str, file_key: str) -> str:
    """Retourne le template builtin d'un rôle MW, ou un squelette pour les rôles custom."""
    import services.clp_builder as b
    _MAP = {
        'apache':    {'defaults': b._apache_defaults,    'tasks_main': b._apache_tasks,    'tasks_stop': b._APACHE_STOP,  'tasks_start': b._APACHE_START,  'tasks_status': b._APACHE_STATUS,  'handlers': b._apache_handlers},
        'tomcat':    {'defaults': b._tomcat_defaults,    'tasks_main': b._tomcat_tasks,    'tasks_stop': b._TOMCAT_STOP,  'tasks_start': b._TOMCAT_START,  'tasks_status': b._TOMCAT_STATUS,  'handlers': b._tomcat_handlers},
        'mq':        {'defaults': b._mq_defaults,        'tasks_main': b._mq_tasks,        'tasks_stop': b._MQ_STOP,      'tasks_start': b._MQ_START,      'tasks_status': b._MQ_STATUS,      'handlers': b._mq_handlers},
        'websphere': {'defaults': b._websphere_defaults, 'tasks_main': b._websphere_tasks, 'tasks_stop': b._WAS_STOP,     'tasks_start': b._WAS_START,     'tasks_status': b._WAS_STATUS,     'handlers': b._websphere_handlers},
        'php':       {'defaults': b._php_defaults,       'tasks_main': b._php_tasks,       'tasks_stop': b._PHP_STOP,     'tasks_start': b._PHP_START,     'tasks_status': b._PHP_STATUS,     'handlers': b._php_handlers},
        'jboss':     {'defaults': b._jboss_defaults,     'tasks_main': b._jboss_tasks,     'tasks_stop': b._JBOSS_STOP,   'tasks_start': b._JBOSS_START,   'tasks_status': b._JBOSS_STATUS,   'handlers': b._jboss_handlers},
        'cft':       {'defaults': b._cft_defaults,       'tasks_main': b._cft_tasks,       'tasks_stop': b._CFT_STOP,     'tasks_start': b._CFT_START,     'tasks_status': b._CFT_STATUS,     'handlers': b._cft_handlers},
    }
    mw_map = _MAP.get(role_id, {})
    if file_key in mw_map:
        val = mw_map[file_key]
        return val() if callable(val) else val
    # Squelette générique pour rôles custom
    _SKEL = {
        'defaults':     f'# Rôle : {role_id} — Variables par défaut\n',
        'tasks_main':   f'---\n# Rôle : {role_id} — Tâches principales\n',
        'tasks_stop':   f'---\n# Rôle : {role_id} — Arrêt du service\n',
        'tasks_start':  f'---\n# Rôle : {role_id} — Démarrage du service\n',
        'tasks_status': f'---\n# Rôle : {role_id} — Statut du service\n',
        'handlers':     f'---\n# Rôle : {role_id} — Handlers\n',
    }
    return _SKEL.get(file_key, '')
