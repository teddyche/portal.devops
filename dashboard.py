from flask import Flask, jsonify, request, send_file, abort
import json
import os
import shutil
import re
import uuid
from datetime import date, datetime

import requests as http_requests
from crypto import encrypt_token, decrypt_token, mask_token
from auth import get_ssl_verify

app = Flask(__name__, static_folder='img', static_url_path='/img')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATAS_DIR = os.path.join(BASE_DIR, 'datas')

# === Auth setup ===
AUTH_CONFIG_PATH = os.path.join(DATAS_DIR, 'auth', 'config.json')
if os.path.exists(AUTH_CONFIG_PATH):
    with open(AUTH_CONFIG_PATH, 'r', encoding='utf-8') as _f:
        _auth_cfg = json.load(_f)
    app.secret_key = _auth_cfg.get('secret_key', 'dev-fallback-key')
else:
    app.secret_key = 'dev-fallback-key'

from auth import auth_bp
from auth_admin import auth_admin_bp
app.register_blueprint(auth_bp)
app.register_blueprint(auth_admin_bp)
CLUSTERS_FILE = os.path.join(DATAS_DIR, 'clusters.json')
PSSIT_APPS_FILE = os.path.join(DATAS_DIR, 'pssit_apps.json')
CAD_WORKSPACES_FILE = os.path.join(DATAS_DIR, 'cad_workspaces.json')


# === Helpers ===

def load_json(path):
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None

def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def get_cluster_dir(cluster_id):
    return os.path.join(DATAS_DIR, cluster_id)

def cluster_exists(cluster_id):
    clusters = load_json(CLUSTERS_FILE) or []
    return any(c['id'] == cluster_id for c in clusters)

def safe_id(cluster_id):
    return bool(re.match(r'^[A-Za-z0-9_-]+$', cluster_id))

def get_default_config():
    from migrate import DEFAULT_CONFIG
    return DEFAULT_CONFIG

def get_default_autoscore_config():
    from migrate import DEFAULT_AUTOSCORE_CONFIG
    return DEFAULT_AUTOSCORE_CONFIG


# === PSSIT Helpers ===

def get_pssit_app_dir(app_id):
    return os.path.join(DATAS_DIR, 'pssit', app_id)

def pssit_app_exists(app_id):
    apps = load_json(PSSIT_APPS_FILE) or []
    return any(a['id'] == app_id for a in apps)

def get_pssit_env_config(app_id, env_id):
    config = load_json(os.path.join(get_pssit_app_dir(app_id), 'config.json')) or {}
    envs = config.get('environments', [])
    env = next((e for e in envs if e['id'] == env_id), None)
    if env is None:
        return None
    # Déchiffre les tokens pour usage interne (appels AWX/JFrog)
    secret = app.secret_key
    awx = env.get('awx', {})
    if awx.get('token'):
        awx['token'] = decrypt_token(awx['token'], secret)
    jfrog = env.get('jfrog', {})
    if jfrog.get('token'):
        jfrog['token'] = decrypt_token(jfrog['token'], secret)
    return env

def add_pssit_history(app_id, entry):
    path = os.path.join(get_pssit_app_dir(app_id), 'history.json')
    history = load_json(path) or []
    history.insert(0, entry)
    save_json(path, history)
    return entry


# === CAD Helpers ===

def get_cad_ws_dir(ws_id):
    return os.path.join(DATAS_DIR, 'cad', ws_id)

def cad_ws_exists(ws_id):
    workspaces = load_json(CAD_WORKSPACES_FILE) or []
    return any(w['id'] == ws_id for w in workspaces)

def get_default_cad_config():
    from migrate import DEFAULT_CAD_CONFIG
    return DEFAULT_CAD_CONFIG


# === Page routes ===

@app.route('/')
def home():
    return send_file(os.path.join(BASE_DIR, 'pages', 'home.html'))

@app.route('/sre')
def landing():
    return send_file(os.path.join(BASE_DIR, 'pages', 'landing.html'))

@app.route('/ldap-checker')
def placeholder():
    return send_file(os.path.join(BASE_DIR, 'pages', 'placeholder.html'))

# CAD page routes
@app.route('/cad')
def cad_landing():
    return send_file(os.path.join(BASE_DIR, 'pages', 'cad_landing.html'))

@app.route('/cad/admin')
def cad_admin():
    return send_file(os.path.join(BASE_DIR, 'pages', 'cad_admin.html'))

@app.route('/cad/workspace/<ws_id>')
def cad_dashboard(ws_id):
    if not cad_ws_exists(ws_id):
        abort(404)
    return send_file(os.path.join(BASE_DIR, 'pages', 'dashboard.html'))

@app.route('/cad/workspace/<ws_id>/config')
def cad_config_page(ws_id):
    if not cad_ws_exists(ws_id):
        abort(404)
    return send_file(os.path.join(BASE_DIR, 'pages', 'config.html'))

@app.route('/cad/workspace/<ws_id>/board')
def cad_board(ws_id):
    if not cad_ws_exists(ws_id):
        abort(404)
    return send_file(os.path.join(BASE_DIR, 'pages', 'board.html'))

# PSSIT page routes
@app.route('/pssit')
def pssit_landing():
    return send_file(os.path.join(BASE_DIR, 'pages', 'pssit_landing.html'))

@app.route('/pssit/admin')
def pssit_admin():
    return send_file(os.path.join(BASE_DIR, 'pages', 'pssit_admin.html'))

@app.route('/pssit/app/<app_id>')
def pssit_app_detail(app_id):
    if not pssit_app_exists(app_id):
        abort(404)
    return send_file(os.path.join(BASE_DIR, 'pages', 'pssit_app.html'))

@app.route('/pssit/app/<app_id>/config')
def pssit_app_config(app_id):
    if not pssit_app_exists(app_id):
        abort(404)
    return send_file(os.path.join(BASE_DIR, 'pages', 'pssit_config.html'))

@app.route('/admin')
def admin():
    return send_file(os.path.join(BASE_DIR, 'pages', 'admin.html'))

@app.route('/auth-admin')
def auth_admin_page():
    return send_file(os.path.join(BASE_DIR, 'pages', 'auth_admin.html'))

@app.route('/cluster/<cluster_id>')
def cluster_dashboard(cluster_id):
    if not cluster_exists(cluster_id):
        abort(404)
    return send_file(os.path.join(BASE_DIR, 'pages', 'dashboard.html'))

@app.route('/cluster/<cluster_id>/config')
def cluster_config_page(cluster_id):
    if not cluster_exists(cluster_id):
        abort(404)
    return send_file(os.path.join(BASE_DIR, 'pages', 'config.html'))

@app.route('/cluster/<cluster_id>/autoscore')
def cluster_autoscore(cluster_id):
    if not cluster_exists(cluster_id):
        abort(404)
    return send_file(os.path.join(BASE_DIR, 'pages', 'autoscore.html'))

@app.route('/cluster/<cluster_id>/autoscore-config')
def cluster_autoscore_config(cluster_id):
    if not cluster_exists(cluster_id):
        abort(404)
    return send_file(os.path.join(BASE_DIR, 'pages', 'autoscore_config.html'))

@app.route('/cluster/<cluster_id>/board')
def cluster_board(cluster_id):
    if not cluster_exists(cluster_id):
        abort(404)
    return send_file(os.path.join(BASE_DIR, 'pages', 'board.html'))


# === API: Clusters ===

@app.route('/api/clusters', methods=['GET'])
def api_get_clusters():
    from auth import get_user_resources
    from flask import session
    clusters = load_json(CLUSTERS_FILE) or []
    user_id = session.get('user_id')
    if user_id:
        resources = get_user_resources(user_id)
        if resources is not None:
            allowed = {r['resource_id'] for r in resources if r['module'] == 'sre'}
            clusters = [c for c in clusters if c['id'] in allowed]
    return jsonify(clusters)

@app.route('/api/clusters', methods=['POST'])
def api_create_cluster():
    body = request.json
    cid = body.get('id', '').strip()
    name = body.get('name', '').strip()
    desc = body.get('description', '').strip()

    if not cid or not safe_id(cid):
        return jsonify({'error': 'ID invalide (alphanum, tirets, underscores)'}), 400

    clusters = load_json(CLUSTERS_FILE) or []
    if any(c['id'] == cid for c in clusters):
        return jsonify({'error': 'Ce cluster existe déjà'}), 400

    cluster_dir = get_cluster_dir(cid)
    os.makedirs(os.path.join(cluster_dir, 'autoscore'), exist_ok=True)
    save_json(os.path.join(cluster_dir, 'config.json'), get_default_config())
    save_json(os.path.join(cluster_dir, 'autoscore_config.json'), get_default_autoscore_config())
    save_json(os.path.join(cluster_dir, 'data.json'), [])

    clusters.append({'id': cid, 'name': name or cid, 'description': desc, 'created': date.today().isoformat()})
    save_json(CLUSTERS_FILE, clusters)
    return jsonify({'success': True})

@app.route('/api/clusters/<cluster_id>', methods=['PUT'])
def api_update_cluster(cluster_id):
    clusters = load_json(CLUSTERS_FILE) or []
    cluster = next((c for c in clusters if c['id'] == cluster_id), None)
    if not cluster:
        return jsonify({'error': 'Cluster non trouvé'}), 404

    body = request.json
    if 'name' in body:
        cluster['name'] = body['name']
    if 'description' in body:
        cluster['description'] = body['description']
    save_json(CLUSTERS_FILE, clusters)
    return jsonify({'success': True})

@app.route('/api/clusters/<cluster_id>', methods=['DELETE'])
def api_delete_cluster(cluster_id):
    clusters = load_json(CLUSTERS_FILE) or []
    if not any(c['id'] == cluster_id for c in clusters):
        return jsonify({'error': 'Cluster non trouvé'}), 404

    clusters = [c for c in clusters if c['id'] != cluster_id]
    save_json(CLUSTERS_FILE, clusters)

    cluster_dir = get_cluster_dir(cluster_id)
    if os.path.exists(cluster_dir):
        shutil.rmtree(cluster_dir)
    return jsonify({'success': True})


# === API: Cluster Config ===

@app.route('/api/cluster/<cluster_id>/config', methods=['GET'])
def api_get_config(cluster_id):
    if not cluster_exists(cluster_id):
        abort(404)
    config = load_json(os.path.join(get_cluster_dir(cluster_id), 'config.json'))
    return jsonify(config or {})

@app.route('/api/cluster/<cluster_id>/config', methods=['POST'])
def api_save_config(cluster_id):
    if not cluster_exists(cluster_id):
        abort(404)
    save_json(os.path.join(get_cluster_dir(cluster_id), 'config.json'), request.json)
    return jsonify({'success': True})


# === API: Cluster Data ===

@app.route('/api/cluster/<cluster_id>/data', methods=['GET'])
def api_get_data(cluster_id):
    if not cluster_exists(cluster_id):
        abort(404)
    data = load_json(os.path.join(get_cluster_dir(cluster_id), 'data.json'))
    return jsonify(data or [])

@app.route('/api/cluster/<cluster_id>/data', methods=['POST'])
def api_save_data(cluster_id):
    if not cluster_exists(cluster_id):
        abort(404)
    save_json(os.path.join(get_cluster_dir(cluster_id), 'data.json'), request.json)
    return jsonify({'success': True})


# === API: Autoscore ===

@app.route('/api/cluster/<cluster_id>/autoscore/<app_code>', methods=['GET'])
def api_get_autoscore(cluster_id, app_code):
    if not cluster_exists(cluster_id):
        abort(404)
    path = os.path.join(get_cluster_dir(cluster_id), 'autoscore', f'{app_code}.json')
    data = load_json(path)
    return jsonify(data or {})

@app.route('/api/cluster/<cluster_id>/autoscore/<app_code>', methods=['POST'])
def api_save_autoscore(cluster_id, app_code):
    if not cluster_exists(cluster_id):
        abort(404)

    autoscore_data = request.json
    as_path = os.path.join(get_cluster_dir(cluster_id), 'autoscore', f'{app_code}.json')
    save_json(as_path, autoscore_data)

    # Update score and note in data.json
    data_path = os.path.join(get_cluster_dir(cluster_id), 'data.json')
    apps = load_json(data_path) or []
    score = autoscore_data.get('score', 0)
    note = autoscore_data.get('note', '')
    for app_entry in apps:
        if app_entry.get('code') == app_code:
            app_entry['score'] = score
            app_entry['note'] = note
            break
    save_json(data_path, apps)
    return jsonify({'success': True})


# === API: Autoscore Config ===

@app.route('/api/cluster/<cluster_id>/autoscore-config', methods=['GET'])
def api_get_autoscore_config(cluster_id):
    if not cluster_exists(cluster_id):
        abort(404)
    path = os.path.join(get_cluster_dir(cluster_id), 'autoscore_config.json')
    config = load_json(path)
    if config is None:
        config = get_default_autoscore_config()
        save_json(path, config)
    return jsonify(config)

@app.route('/api/cluster/<cluster_id>/autoscore-config', methods=['POST'])
def api_save_autoscore_config(cluster_id):
    if not cluster_exists(cluster_id):
        abort(404)
    data = request.json
    if not data or not isinstance(data, dict):
        # Reset to default
        data = get_default_autoscore_config()
    save_json(os.path.join(get_cluster_dir(cluster_id), 'autoscore_config.json'), data)
    return jsonify({'success': True})


# === API: PSSIT Apps CRUD ===

@app.route('/api/pssit/apps', methods=['GET'])
def api_get_pssit_apps():
    from auth import get_user_resources
    from flask import session
    apps = load_json(PSSIT_APPS_FILE) or []
    user_id = session.get('user_id')
    if user_id:
        resources = get_user_resources(user_id)
        if resources is not None:
            allowed = {r['resource_id'] for r in resources if r['module'] == 'pssit'}
            apps = [a for a in apps if a['id'] in allowed]
    return jsonify(apps)

@app.route('/api/pssit/apps', methods=['POST'])
def api_create_pssit_app():
    body = request.json
    aid = body.get('id', '').strip().upper()
    name = body.get('name', '').strip()
    team = body.get('team', '').strip()
    desc = body.get('description', '').strip()

    if not aid or not safe_id(aid):
        return jsonify({'error': 'ID invalide'}), 400

    apps = load_json(PSSIT_APPS_FILE) or []
    if any(a['id'] == aid for a in apps):
        return jsonify({'error': 'Cette application existe déjà'}), 400

    app_dir = get_pssit_app_dir(aid)
    os.makedirs(app_dir, exist_ok=True)
    save_json(os.path.join(app_dir, 'config.json'), {'environments': []})
    save_json(os.path.join(app_dir, 'history.json'), [])
    save_json(os.path.join(app_dir, 'schedules.json'), [])

    apps.append({'id': aid, 'name': name or aid, 'team': team, 'description': desc, 'created': date.today().isoformat()})
    save_json(PSSIT_APPS_FILE, apps)
    return jsonify({'success': True})

@app.route('/api/pssit/apps/<app_id>', methods=['PUT'])
def api_update_pssit_app(app_id):
    apps = load_json(PSSIT_APPS_FILE) or []
    app_entry = next((a for a in apps if a['id'] == app_id), None)
    if not app_entry:
        return jsonify({'error': 'Application non trouvée'}), 404

    body = request.json
    if 'name' in body:
        app_entry['name'] = body['name']
    if 'team' in body:
        app_entry['team'] = body['team']
    if 'description' in body:
        app_entry['description'] = body['description']
    save_json(PSSIT_APPS_FILE, apps)
    return jsonify({'success': True})

@app.route('/api/pssit/apps/<app_id>', methods=['DELETE'])
def api_delete_pssit_app(app_id):
    apps = load_json(PSSIT_APPS_FILE) or []
    if not any(a['id'] == app_id for a in apps):
        return jsonify({'error': 'Application non trouvée'}), 404

    apps = [a for a in apps if a['id'] != app_id]
    save_json(PSSIT_APPS_FILE, apps)

    app_dir = get_pssit_app_dir(app_id)
    if os.path.exists(app_dir):
        shutil.rmtree(app_dir)
    return jsonify({'success': True})


# === API: PSSIT App Config ===

@app.route('/api/pssit/app/<app_id>/config', methods=['GET'])
def api_get_pssit_config(app_id):
    if not pssit_app_exists(app_id):
        abort(404)
    config = load_json(os.path.join(get_pssit_app_dir(app_id), 'config.json')) or {'environments': []}
    # Masque les tokens chiffrés avant d'envoyer au frontend
    for env in config.get('environments', []):
        awx = env.get('awx', {})
        if awx.get('token'):
            awx['token'] = mask_token(awx['token'])
        jfrog = env.get('jfrog', {})
        if jfrog.get('token'):
            jfrog['token'] = mask_token(jfrog['token'])
    return jsonify(config)

@app.route('/api/pssit/app/<app_id>/config', methods=['POST'])
def api_save_pssit_config(app_id):
    if not pssit_app_exists(app_id):
        abort(404)
    new_config = request.json
    secret = app.secret_key
    # Préserve ou chiffre les tokens
    old_config = load_json(os.path.join(get_pssit_app_dir(app_id), 'config.json')) or {'environments': []}
    old_envs = {e['id']: e for e in old_config.get('environments', [])}
    for env in new_config.get('environments', []):
        old_env = old_envs.get(env['id'], {})
        awx = env.get('awx', {})
        if awx.get('token') == '__UNCHANGED__':
            awx['token'] = old_env.get('awx', {}).get('token', '')
        elif awx.get('token'):
            awx['token'] = encrypt_token(awx['token'], secret)
        jfrog = env.get('jfrog', {})
        if jfrog.get('token') == '__UNCHANGED__':
            jfrog['token'] = old_env.get('jfrog', {}).get('token', '')
        elif jfrog.get('token'):
            jfrog['token'] = encrypt_token(jfrog['token'], secret)
    save_json(os.path.join(get_pssit_app_dir(app_id), 'config.json'), new_config)
    return jsonify({'success': True})


# === API: PSSIT History & Schedules ===

@app.route('/api/pssit/app/<app_id>/history', methods=['GET'])
def api_get_pssit_history(app_id):
    if not pssit_app_exists(app_id):
        abort(404)
    history = load_json(os.path.join(get_pssit_app_dir(app_id), 'history.json'))
    return jsonify(history or [])

@app.route('/api/pssit/app/<app_id>/schedules', methods=['GET'])
def api_get_pssit_schedules(app_id):
    if not pssit_app_exists(app_id):
        abort(404)
    schedules = load_json(os.path.join(get_pssit_app_dir(app_id), 'schedules.json'))
    return jsonify(schedules or [])

@app.route('/api/pssit/app/<app_id>/schedules/<schedule_id>', methods=['DELETE'])
def api_cancel_pssit_schedule(app_id, schedule_id):
    if not pssit_app_exists(app_id):
        abort(404)
    path = os.path.join(get_pssit_app_dir(app_id), 'schedules.json')
    schedules = load_json(path) or []
    schedule = next((s for s in schedules if s['id'] == schedule_id), None)
    if not schedule:
        return jsonify({'error': 'Schedule non trouvé'}), 404

    env_config = get_pssit_env_config(app_id, schedule['envId'])
    if env_config:
        awx = env_config.get('awx', {})
        awx_url = awx.get('url', '').rstrip('/')
        awx_token = awx.get('token', '')
        awx_sid = schedule.get('awxScheduleId')
        if awx_url and awx_token and awx_sid:
            try:
                http_requests.delete(
                    f'{awx_url}/api/v2/schedules/{awx_sid}/',
                    headers={'Authorization': f'Bearer {awx_token}'},
                    timeout=15, verify=env_config.get('ssl_verify', get_ssl_verify())
                )
            except Exception:
                pass

    schedule['status'] = 'cancelled'
    save_json(path, schedules)
    return jsonify({'success': True})


# === API: PSSIT AWX Proxy ===

@app.route('/api/pssit/app/<app_id>/env/<env_id>/launch', methods=['POST'])
def api_pssit_launch(app_id, env_id):
    if not pssit_app_exists(app_id):
        abort(404)
    env_config = get_pssit_env_config(app_id, env_id)
    if not env_config:
        return jsonify({'error': 'Environnement non trouvé'}), 404

    body = request.json
    action = body.get('action')
    params = body.get('params', {})

    if action not in ('stop', 'start', 'status', 'deploy', 'patch'):
        return jsonify({'error': 'Action invalide'}), 400

    awx = env_config.get('awx', {})
    template_id = awx.get('workflows', {}).get(action)
    if not template_id:
        return jsonify({'error': f'Workflow non configuré pour {action}'}), 400

    awx_url = awx.get('url', '').rstrip('/')
    awx_token = awx.get('token', '')
    extra_vars = {**env_config.get('extraParams', {}), **params}

    history_id = uuid.uuid4().hex[:8]
    entry = {
        'id': history_id,
        'action': action,
        'envId': env_id,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'awxJobId': None,
        'awxJobUrl': None,
        'status': 'pending',
        'params': extra_vars,
        'artifact': params.get('artifact')
    }

    try:
        resp = http_requests.post(
            f'{awx_url}/api/v2/workflow_job_templates/{template_id}/launch/',
            headers={'Authorization': f'Bearer {awx_token}', 'Content-Type': 'application/json'},
            json={'extra_vars': json.dumps(extra_vars)} if extra_vars else {},
            timeout=30, verify=env_config.get('ssl_verify', get_ssl_verify())
        )
        if resp.status_code in (200, 201):
            job_data = resp.json()
            awx_job_id = job_data.get('id') or job_data.get('workflow_job')
            entry['awxJobId'] = awx_job_id
            entry['awxJobUrl'] = f'{awx_url}/#/jobs/workflow/{awx_job_id}'
            entry['status'] = 'running'
        else:
            entry['status'] = 'error'
            entry['params']['_error'] = resp.text[:500]
    except Exception as e:
        entry['status'] = 'error'
        entry['params']['_error'] = str(e)[:500]

    add_pssit_history(app_id, entry)
    return jsonify(entry)

@app.route('/api/pssit/app/<app_id>/env/<env_id>/job/<int:awx_job_id>/status', methods=['GET'])
def api_pssit_job_status(app_id, env_id, awx_job_id):
    if not pssit_app_exists(app_id):
        abort(404)
    env_config = get_pssit_env_config(app_id, env_id)
    if not env_config:
        return jsonify({'error': 'Environnement non trouvé'}), 404

    awx = env_config.get('awx', {})
    awx_url = awx.get('url', '').rstrip('/')
    awx_token = awx.get('token', '')

    try:
        resp = http_requests.get(
            f'{awx_url}/api/v2/workflow_jobs/{awx_job_id}/',
            headers={'Authorization': f'Bearer {awx_token}'},
            timeout=15, verify=env_config.get('ssl_verify', get_ssl_verify())
        )
        if resp.status_code == 200:
            job = resp.json()
            status_map = {
                'new': 'pending', 'pending': 'pending', 'waiting': 'pending',
                'running': 'running', 'successful': 'successful',
                'failed': 'failed', 'error': 'error', 'canceled': 'canceled'
            }
            mapped = status_map.get(job.get('status', ''), job.get('status', 'unknown'))

            hist_path = os.path.join(get_pssit_app_dir(app_id), 'history.json')
            history = load_json(hist_path) or []
            for h in history:
                if h.get('awxJobId') == awx_job_id:
                    h['status'] = mapped
                    break
            save_json(hist_path, history)

            return jsonify({'awxJobId': awx_job_id, 'status': mapped, 'finished': job.get('finished'), 'started': job.get('started')})
        else:
            return jsonify({'error': f'AWX returned {resp.status_code}'}), 502
    except Exception as e:
        return jsonify({'error': str(e)}), 502

@app.route('/api/pssit/app/<app_id>/env/<env_id>/schedule', methods=['POST'])
def api_pssit_schedule(app_id, env_id):
    if not pssit_app_exists(app_id):
        abort(404)
    env_config = get_pssit_env_config(app_id, env_id)
    if not env_config:
        return jsonify({'error': 'Environnement non trouvé'}), 404

    body = request.json
    action = body.get('action')
    scheduled_dt = body.get('datetime')

    if action not in ('stop', 'start'):
        return jsonify({'error': 'Seuls stop et start sont planifiables'}), 400

    awx = env_config.get('awx', {})
    template_id = awx.get('workflows', {}).get(action)
    if not template_id:
        return jsonify({'error': f'Workflow non configuré pour {action}'}), 400

    awx_url = awx.get('url', '').rstrip('/')
    awx_token = awx.get('token', '')
    schedule_name = f'pssit-{app_id}-{env_id}-{action}-{uuid.uuid4().hex[:6]}'

    dt = datetime.fromisoformat(scheduled_dt.replace('Z', '+00:00') if 'Z' in scheduled_dt else scheduled_dt)
    dtstart = dt.strftime('%Y%m%dT%H%M%SZ')

    try:
        resp = http_requests.post(
            f'{awx_url}/api/v2/workflow_job_templates/{template_id}/schedules/',
            headers={'Authorization': f'Bearer {awx_token}', 'Content-Type': 'application/json'},
            json={
                'name': schedule_name,
                'rrule': f'DTSTART:{dtstart} RRULE:FREQ=MINUTELY;INTERVAL=1;COUNT=1',
                'extra_data': env_config.get('extraParams', {})
            },
            timeout=30, verify=env_config.get('ssl_verify', get_ssl_verify())
        )
        if resp.status_code in (200, 201):
            awx_data = resp.json()
            schedule_id = uuid.uuid4().hex[:8]
            entry = {
                'id': schedule_id,
                'awxScheduleId': awx_data.get('id'),
                'action': action,
                'envId': env_id,
                'scheduledAt': scheduled_dt,
                'createdAt': datetime.utcnow().isoformat() + 'Z',
                'status': 'active'
            }
            path = os.path.join(get_pssit_app_dir(app_id), 'schedules.json')
            schedules = load_json(path) or []
            schedules.insert(0, entry)
            save_json(path, schedules)
            return jsonify(entry)
        else:
            return jsonify({'error': 'AWX schedule failed: ' + resp.text[:500]}), 502
    except Exception as e:
        return jsonify({'error': str(e)}), 502


# === API: PSSIT JFrog Proxy ===

@app.route('/api/pssit/app/<app_id>/env/<env_id>/artifacts', methods=['GET'])
def api_pssit_artifacts(app_id, env_id):
    if not pssit_app_exists(app_id):
        abort(404)
    env_config = get_pssit_env_config(app_id, env_id)
    if not env_config:
        return jsonify({'error': 'Environnement non trouvé'}), 404

    jfrog = env_config.get('jfrog', {})
    jfrog_url = jfrog.get('url', '').rstrip('/')
    jfrog_token = jfrog.get('token', '')
    repo = jfrog.get('repo', '')
    path = jfrog.get('path', '')

    if not jfrog_url or not repo:
        return jsonify([])

    try:
        api_path = f'{jfrog_url}/api/storage/{repo}/{path}'
        resp = http_requests.get(
            api_path,
            headers={'Authorization': f'Bearer {jfrog_token}', 'X-JFrog-Art-Api': jfrog_token},
            params={'list': '', 'deep': '0', 'listFolders': '0'},
            timeout=15, verify=env_config.get('ssl_verify', get_ssl_verify())
        )
        if resp.status_code == 200:
            data = resp.json()
            files = data.get('files', data.get('children', []))
            artifacts = []
            for f in files:
                name = f.get('uri', f.get('name', '')).lstrip('/')
                if f.get('folder', False):
                    continue
                artifacts.append({
                    'name': name,
                    'size': f.get('size', 0),
                    'lastModified': f.get('lastModified', f.get('modified', ''))
                })
            artifacts.sort(key=lambda x: x.get('lastModified', ''), reverse=True)
            return jsonify(artifacts)
        else:
            return jsonify({'error': f'JFrog returned {resp.status_code}'}), 502
    except Exception as e:
        return jsonify({'error': str(e)}), 502


# === API: CAD Workspaces CRUD ===

@app.route('/api/cad/workspaces', methods=['GET'])
def api_get_cad_workspaces():
    from auth import get_user_resources
    from flask import session
    workspaces = load_json(CAD_WORKSPACES_FILE) or []
    user_id = session.get('user_id')
    if user_id:
        resources = get_user_resources(user_id)
        if resources is not None:
            allowed = {r['resource_id'] for r in resources if r['module'] == 'cad'}
            workspaces = [w for w in workspaces if w['id'] in allowed]
    return jsonify(workspaces)

@app.route('/api/cad/workspaces', methods=['POST'])
def api_create_cad_workspace():
    body = request.json
    wid = body.get('id', '').strip().upper()
    name = body.get('name', '').strip()
    desc = body.get('description', '').strip()

    if not wid or not safe_id(wid):
        return jsonify({'error': 'ID invalide'}), 400

    workspaces = load_json(CAD_WORKSPACES_FILE) or []
    if any(w['id'] == wid for w in workspaces):
        return jsonify({'error': 'Ce workspace existe déjà'}), 400

    ws_dir = get_cad_ws_dir(wid)
    os.makedirs(ws_dir, exist_ok=True)
    save_json(os.path.join(ws_dir, 'config.json'), get_default_cad_config())
    save_json(os.path.join(ws_dir, 'data.json'), [])

    workspaces.append({'id': wid, 'name': name or wid, 'description': desc, 'created': date.today().isoformat()})
    save_json(CAD_WORKSPACES_FILE, workspaces)
    return jsonify({'success': True})

@app.route('/api/cad/workspaces/<ws_id>', methods=['PUT'])
def api_update_cad_workspace(ws_id):
    workspaces = load_json(CAD_WORKSPACES_FILE) or []
    ws = next((w for w in workspaces if w['id'] == ws_id), None)
    if not ws:
        return jsonify({'error': 'Workspace non trouvé'}), 404

    body = request.json
    if 'name' in body:
        ws['name'] = body['name']
    if 'description' in body:
        ws['description'] = body['description']
    save_json(CAD_WORKSPACES_FILE, workspaces)
    return jsonify({'success': True})

@app.route('/api/cad/workspaces/<ws_id>', methods=['DELETE'])
def api_delete_cad_workspace(ws_id):
    workspaces = load_json(CAD_WORKSPACES_FILE) or []
    if not any(w['id'] == ws_id for w in workspaces):
        return jsonify({'error': 'Workspace non trouvé'}), 404

    workspaces = [w for w in workspaces if w['id'] != ws_id]
    save_json(CAD_WORKSPACES_FILE, workspaces)

    ws_dir = get_cad_ws_dir(ws_id)
    if os.path.exists(ws_dir):
        shutil.rmtree(ws_dir)
    return jsonify({'success': True})


# === API: CAD Workspace Config & Data ===

@app.route('/api/cad/workspace/<ws_id>/config', methods=['GET'])
def api_get_cad_config(ws_id):
    if not cad_ws_exists(ws_id):
        abort(404)
    config = load_json(os.path.join(get_cad_ws_dir(ws_id), 'config.json'))
    return jsonify(config or {})

@app.route('/api/cad/workspace/<ws_id>/config', methods=['POST'])
def api_save_cad_config(ws_id):
    if not cad_ws_exists(ws_id):
        abort(404)
    save_json(os.path.join(get_cad_ws_dir(ws_id), 'config.json'), request.json)
    return jsonify({'success': True})

@app.route('/api/cad/workspace/<ws_id>/data', methods=['GET'])
def api_get_cad_data(ws_id):
    if not cad_ws_exists(ws_id):
        abort(404)
    data = load_json(os.path.join(get_cad_ws_dir(ws_id), 'data.json'))
    return jsonify(data or [])

@app.route('/api/cad/workspace/<ws_id>/data', methods=['POST'])
def api_save_cad_data(ws_id):
    if not cad_ws_exists(ws_id):
        abort(404)
    save_json(os.path.join(get_cad_ws_dir(ws_id), 'data.json'), request.json)
    return jsonify({'success': True})


if __name__ == '__main__':
    app.run(debug=True, port=5000)
