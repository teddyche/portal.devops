"""Tests d'intégration des routes API PSSIT."""
import json

import pytest

import services.store as store


@pytest.fixture(autouse=True)
def clear_cache():
    store._cache.clear()
    yield
    store._cache.clear()


def _json(rv):
    return json.loads(rv.data)


# === GET /api/pssit/apps ===

def test_get_pssit_apps_empty(authed_client):
    rv = authed_client.get('/api/pssit/apps')
    assert rv.status_code == 200
    assert _json(rv) == []


# === POST /api/pssit/apps ===

def test_create_pssit_app_valid(authed_client):
    rv = authed_client.post('/api/pssit/apps',
                            json={'id': 'MYAPP', 'name': 'My App'},
                            headers={'X-CSRF-Token': 'test_csrf'})
    assert rv.status_code == 200
    assert _json(rv)['success'] is True


def test_create_pssit_app_invalid_id(authed_client):
    rv = authed_client.post('/api/pssit/apps',
                            json={'id': 'bad id!'},
                            headers={'X-CSRF-Token': 'test_csrf'})
    assert rv.status_code == 400


# === DELETE /api/pssit/apps/<id> ===

def test_delete_pssit_app_not_found(authed_client):
    rv = authed_client.delete('/api/pssit/apps/INCONNU', headers={'X-CSRF-Token': 'test_csrf'})
    assert rv.status_code == 404


def test_delete_pssit_app_ok(authed_client):
    authed_client.post('/api/pssit/apps', json={'id': 'MYAPP'}, headers={'X-CSRF-Token': 'test_csrf'})
    store._cache.clear()
    rv = authed_client.delete('/api/pssit/apps/MYAPP', headers={'X-CSRF-Token': 'test_csrf'})
    assert rv.status_code == 200


# === GET /api/pssit/app/<id>/config ===

def test_get_pssit_config_ok(authed_client):
    authed_client.post('/api/pssit/apps', json={'id': 'MYAPP'}, headers={'X-CSRF-Token': 'test_csrf'})
    store._cache.clear()
    rv = authed_client.get('/api/pssit/app/MYAPP/config')
    assert rv.status_code == 200
    data = _json(rv)
    assert 'environments' in data


# === GET /api/pssit/app/<id>/history ===

def test_get_pssit_history_empty(authed_client):
    authed_client.post('/api/pssit/apps', json={'id': 'MYAPP'}, headers={'X-CSRF-Token': 'test_csrf'})
    store._cache.clear()
    rv = authed_client.get('/api/pssit/app/MYAPP/history')
    assert rv.status_code == 200
    assert _json(rv) == []


# === POST /api/pssit/app/<id>/env/<env_id>/schedule — datetime invalide ===

def test_schedule_invalid_datetime(authed_client):
    authed_client.post('/api/pssit/apps', json={'id': 'MYAPP'}, headers={'X-CSRF-Token': 'test_csrf'})
    store._cache.clear()
    # Patch env config to avoid 404 on env
    import services.pssit as pssit_service
    import services.store as s
    import os, json as _json_mod
    app_dir = os.path.join(authed_client.application.config['DATAS_DIR'], 'pssit', 'MYAPP')
    config = {'environments': [{'id': 'prod', 'awx': {'url': 'http://awx', 'token': '', 'workflows': {'start': '1'}}, 'jfrog': {}}]}
    with open(os.path.join(app_dir, 'config.json'), 'w') as f:
        _json_mod.dump(config, f)
    s._cache.clear()

    rv = authed_client.post(
        '/api/pssit/app/MYAPP/env/prod/schedule',
        json={'action': 'start', 'datetime': 'NOT_A_DATE'},
        headers={'X-CSRF-Token': 'test_csrf'},
    )
    assert rv.status_code == 400
    assert 'date' in json.loads(rv.data)['error'].lower()
