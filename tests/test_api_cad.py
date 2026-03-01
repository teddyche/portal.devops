"""Tests d'intégration des routes API CAD."""
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


# === GET /api/cad/workspaces ===

def test_get_cad_workspaces_empty(authed_client):
    rv = authed_client.get('/api/cad/workspaces')
    assert rv.status_code == 200
    assert _json(rv) == []


# === POST /api/cad/workspaces ===

def test_create_cad_workspace_valid(authed_client):
    rv = authed_client.post('/api/cad/workspaces',
                            json={'id': 'WS01', 'name': 'Workspace 1'},
                            headers={'X-CSRF-Token': 'test_csrf'})
    assert rv.status_code == 200
    assert _json(rv)['success'] is True


def test_create_cad_workspace_invalid_id(authed_client):
    rv = authed_client.post('/api/cad/workspaces',
                            json={'id': 'bad id!'},
                            headers={'X-CSRF-Token': 'test_csrf'})
    assert rv.status_code == 400


def test_create_cad_workspace_duplicate(authed_client):
    authed_client.post('/api/cad/workspaces', json={'id': 'WS01'}, headers={'X-CSRF-Token': 'test_csrf'})
    store._cache.clear()
    rv = authed_client.post('/api/cad/workspaces', json={'id': 'WS01'}, headers={'X-CSRF-Token': 'test_csrf'})
    assert rv.status_code == 400


# === PUT /api/cad/workspaces/<id> ===

def test_update_cad_workspace_not_found(authed_client):
    rv = authed_client.put('/api/cad/workspaces/INCONNU',
                           json={'name': 'X'},
                           headers={'X-CSRF-Token': 'test_csrf'})
    assert rv.status_code == 404


# === DELETE /api/cad/workspaces/<id> ===

def test_delete_cad_workspace_not_found(authed_client):
    rv = authed_client.delete('/api/cad/workspaces/INCONNU', headers={'X-CSRF-Token': 'test_csrf'})
    assert rv.status_code == 404


def test_delete_cad_workspace_ok(authed_client):
    authed_client.post('/api/cad/workspaces', json={'id': 'WS01'}, headers={'X-CSRF-Token': 'test_csrf'})
    store._cache.clear()
    rv = authed_client.delete('/api/cad/workspaces/WS01', headers={'X-CSRF-Token': 'test_csrf'})
    assert rv.status_code == 200
