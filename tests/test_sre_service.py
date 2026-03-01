"""Tests unitaires de services/sre.py."""
import json
import os

import pytest

import services.store as store
import services.sre as sre


@pytest.fixture(autouse=True)
def clear_cache():
    store._cache.clear()
    yield
    store._cache.clear()


@pytest.fixture
def datas_dir(tmp_path):
    return str(tmp_path)


# === cluster_exists ===

def test_cluster_exists_false_for_unknown(datas_dir):
    assert sre.cluster_exists(datas_dir, 'INCONNU') is False


def test_cluster_exists_true_after_create(datas_dir):
    sre.create_cluster(datas_dir, {'id': 'CLP01', 'name': 'Cluster 1'})
    assert sre.cluster_exists(datas_dir, 'CLP01') is True


# === create_cluster ===

def test_create_cluster_invalid_id(datas_dir):
    from services.store import ServiceError
    with pytest.raises(ServiceError, match='ID invalide'):
        sre.create_cluster(datas_dir, {'id': 'bad id!'})


def test_create_cluster_duplicate(datas_dir):
    from services.store import ServiceError
    sre.create_cluster(datas_dir, {'id': 'CLP01'})
    with pytest.raises(ServiceError, match='existe déjà'):
        sre.create_cluster(datas_dir, {'id': 'CLP01'})


def test_create_cluster_creates_files(datas_dir):
    sre.create_cluster(datas_dir, {'id': 'CLP01', 'name': 'Test'})
    cluster_dir = os.path.join(datas_dir, 'CLP01')
    assert os.path.isdir(cluster_dir)
    assert os.path.isfile(os.path.join(cluster_dir, 'config.json'))
    assert os.path.isfile(os.path.join(cluster_dir, 'data.json'))
    assert os.path.isfile(os.path.join(cluster_dir, 'autoscore_config.json'))


# === get_clusters ===

def test_get_clusters_empty(datas_dir):
    assert sre.get_clusters(datas_dir) == []


def test_get_clusters_with_rbac(datas_dir):
    sre.create_cluster(datas_dir, {'id': 'A'})
    sre.create_cluster(datas_dir, {'id': 'B'})
    resources = [{'resource_id': 'A', 'module': 'sre'}]
    result = sre.get_clusters(datas_dir, user_resources=resources)
    assert len(result) == 1
    assert result[0]['id'] == 'A'


# === update_cluster ===

def test_update_cluster_name(datas_dir):
    sre.create_cluster(datas_dir, {'id': 'CLP01', 'name': 'Old'})
    store._cache.clear()
    sre.update_cluster(datas_dir, 'CLP01', {'name': 'New'})
    clusters = sre.get_clusters(datas_dir)
    assert clusters[0]['name'] == 'New'


def test_update_cluster_not_found(datas_dir):
    from services.store import ServiceError
    with pytest.raises(ServiceError) as exc_info:
        sre.update_cluster(datas_dir, 'INCONNU', {'name': 'X'})
    assert exc_info.value.status == 404


# === delete_cluster ===

def test_delete_cluster_removes_from_list(datas_dir):
    sre.create_cluster(datas_dir, {'id': 'CLP01'})
    store._cache.clear()
    sre.delete_cluster(datas_dir, 'CLP01')
    assert sre.cluster_exists(datas_dir, 'CLP01') is False


def test_delete_cluster_soft_deletes_dir(datas_dir):
    sre.create_cluster(datas_dir, {'id': 'CLP01'})
    cluster_dir = os.path.join(datas_dir, 'CLP01')
    assert os.path.isdir(cluster_dir)
    store._cache.clear()
    sre.delete_cluster(datas_dir, 'CLP01')
    assert not os.path.isdir(cluster_dir)
    trash = os.path.join(datas_dir, '_trash')
    assert any('CLP01' in f for f in os.listdir(trash))


# === get/save_autoscore ===

def test_get_autoscore_missing(datas_dir):
    sre.create_cluster(datas_dir, {'id': 'CLP01'})
    store._cache.clear()
    result = sre.get_autoscore(datas_dir, 'CLP01', 'MYAPP')
    assert result == {}


def test_save_and_get_autoscore(datas_dir):
    sre.create_cluster(datas_dir, {'id': 'CLP01'})
    store._cache.clear()
    data = {'score': 85, 'note': 'B'}
    sre.save_autoscore(datas_dir, 'CLP01', 'MYAPP', data)
    store._cache.clear()
    result = sre.get_autoscore(datas_dir, 'CLP01', 'MYAPP')
    assert result['score'] == 85
