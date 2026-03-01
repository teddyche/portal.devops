"""Tests unitaires de services/cad.py."""
import os

import pytest

import services.store as store
import services.cad as cad


@pytest.fixture(autouse=True)
def clear_cache():
    store._cache.clear()
    yield
    store._cache.clear()


@pytest.fixture
def datas_dir(tmp_path):
    (tmp_path / 'cad').mkdir()
    return str(tmp_path)


# === cad_ws_exists ===

def test_cad_ws_exists_false(datas_dir):
    assert cad.cad_ws_exists(datas_dir, 'INCONNU') is False


# === create_cad_workspace ===

def test_create_cad_workspace_invalid_id(datas_dir):
    from services.store import ServiceError
    with pytest.raises(ServiceError, match='ID invalide'):
        cad.create_cad_workspace(datas_dir, {'id': 'bad id!'})


def test_create_cad_workspace_creates_files(datas_dir):
    cad.create_cad_workspace(datas_dir, {'id': 'WS01', 'name': 'Workspace 1'})
    ws_dir = os.path.join(datas_dir, 'cad', 'WS01')
    assert os.path.isdir(ws_dir)
    assert os.path.isfile(os.path.join(ws_dir, 'config.json'))
    assert os.path.isfile(os.path.join(ws_dir, 'data.json'))


def test_create_cad_workspace_duplicate(datas_dir):
    from services.store import ServiceError
    cad.create_cad_workspace(datas_dir, {'id': 'WS01'})
    store._cache.clear()
    with pytest.raises(ServiceError, match='existe déjà'):
        cad.create_cad_workspace(datas_dir, {'id': 'WS01'})


# === get_cad_workspaces ===

def test_get_cad_workspaces_all(datas_dir):
    cad.create_cad_workspace(datas_dir, {'id': 'WS01'})
    cad.create_cad_workspace(datas_dir, {'id': 'WS02'})
    store._cache.clear()
    result = cad.get_cad_workspaces(datas_dir)
    assert len(result) == 2


def test_get_cad_workspaces_with_rbac(datas_dir):
    cad.create_cad_workspace(datas_dir, {'id': 'WS01'})
    cad.create_cad_workspace(datas_dir, {'id': 'WS02'})
    store._cache.clear()
    resources = [{'resource_id': 'WS01', 'module': 'cad'}]
    result = cad.get_cad_workspaces(datas_dir, user_resources=resources)
    assert len(result) == 1
    assert result[0]['id'] == 'WS01'


# === delete_cad_workspace ===

def test_delete_cad_workspace_soft_deletes(datas_dir):
    cad.create_cad_workspace(datas_dir, {'id': 'WS01'})
    ws_dir = os.path.join(datas_dir, 'cad', 'WS01')
    assert os.path.isdir(ws_dir)
    store._cache.clear()
    cad.delete_cad_workspace(datas_dir, 'WS01')
    assert not os.path.isdir(ws_dir)
    assert not cad.cad_ws_exists(datas_dir, 'WS01')
    trash = os.path.join(datas_dir, '_trash')
    assert any('WS01' in f for f in os.listdir(trash))
