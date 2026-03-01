"""Tests d'intégration des routes API SRE via le client Flask."""
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


# === GET /api/clusters ===

def test_get_clusters_empty(authed_client):
    rv = authed_client.get('/api/clusters')
    assert rv.status_code == 200
    assert _json(rv) == []


# === POST /api/clusters ===

def test_create_cluster_valid(authed_client):
    rv = authed_client.post('/api/clusters',
                            json={'id': 'CLP01', 'name': 'Cluster 1'},
                            headers={'X-CSRF-Token': 'test_csrf'})
    assert rv.status_code == 200
    assert _json(rv)['success'] is True


def test_create_cluster_invalid_id(authed_client):
    rv = authed_client.post('/api/clusters',
                            json={'id': 'bad id!'},
                            headers={'X-CSRF-Token': 'test_csrf'})
    assert rv.status_code == 400


def test_create_cluster_duplicate(authed_client):
    authed_client.post('/api/clusters', json={'id': 'CLP01'}, headers={'X-CSRF-Token': 'test_csrf'})
    store._cache.clear()
    rv = authed_client.post('/api/clusters', json={'id': 'CLP01'}, headers={'X-CSRF-Token': 'test_csrf'})
    assert rv.status_code == 400


# === PUT /api/clusters/<id> ===

def test_update_cluster_not_found(authed_client):
    rv = authed_client.put('/api/clusters/INCONNU',
                           json={'name': 'X'},
                           headers={'X-CSRF-Token': 'test_csrf'})
    assert rv.status_code == 404


def test_update_cluster_ok(authed_client):
    authed_client.post('/api/clusters', json={'id': 'CLP01', 'name': 'Old'}, headers={'X-CSRF-Token': 'test_csrf'})
    store._cache.clear()
    rv = authed_client.put('/api/clusters/CLP01', json={'name': 'New'}, headers={'X-CSRF-Token': 'test_csrf'})
    assert rv.status_code == 200


# === DELETE /api/clusters/<id> ===

def test_delete_cluster_not_found(authed_client):
    rv = authed_client.delete('/api/clusters/INCONNU', headers={'X-CSRF-Token': 'test_csrf'})
    assert rv.status_code == 404


def test_delete_cluster_ok(authed_client):
    authed_client.post('/api/clusters', json={'id': 'CLP01'}, headers={'X-CSRF-Token': 'test_csrf'})
    store._cache.clear()
    rv = authed_client.delete('/api/clusters/CLP01', headers={'X-CSRF-Token': 'test_csrf'})
    assert rv.status_code == 200


# === GET /api/cluster/<id>/config ===

def test_get_cluster_config_ok(authed_client):
    authed_client.post('/api/clusters', json={'id': 'CLP01'}, headers={'X-CSRF-Token': 'test_csrf'})
    store._cache.clear()
    rv = authed_client.get('/api/cluster/CLP01/config')
    assert rv.status_code == 200
    data = _json(rv)
    assert isinstance(data, dict)


# === POST /api/cluster/<id>/config ===

def test_save_cluster_config_ok(authed_client):
    authed_client.post('/api/clusters', json={'id': 'CLP01'}, headers={'X-CSRF-Token': 'test_csrf'})
    store._cache.clear()
    rv = authed_client.post('/api/cluster/CLP01/config',
                            json={'groups': []},
                            headers={'X-CSRF-Token': 'test_csrf'})
    assert rv.status_code == 200
