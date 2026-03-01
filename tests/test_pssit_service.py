"""Tests unitaires de services/pssit.py."""
import json
import os

import pytest

import services.store as store
import services.pssit as pssit

SECRET = 'test-secret-key-32chars-padding!!'


@pytest.fixture(autouse=True)
def clear_cache():
    store._cache.clear()
    yield
    store._cache.clear()


@pytest.fixture
def datas_dir(tmp_path):
    (tmp_path / 'pssit').mkdir()
    return str(tmp_path)


# === pssit_app_exists ===

def test_pssit_app_exists_false(datas_dir):
    assert pssit.pssit_app_exists(datas_dir, 'INCONNU') is False


# === create_pssit_app ===

def test_create_pssit_app_invalid_id(datas_dir):
    from services.store import ServiceError
    with pytest.raises(ServiceError, match='ID invalide'):
        pssit.create_pssit_app(datas_dir, {'id': 'bad id!'})


def test_create_pssit_app_creates_structure(datas_dir):
    pssit.create_pssit_app(datas_dir, {'id': 'MYAPP', 'name': 'My App'})
    app_dir = os.path.join(datas_dir, 'pssit', 'MYAPP')
    assert os.path.isdir(app_dir)
    assert os.path.isfile(os.path.join(app_dir, 'config.json'))
    assert os.path.isfile(os.path.join(app_dir, 'history.json'))
    assert os.path.isfile(os.path.join(app_dir, 'schedules.json'))


# === get_pssit_config / save_pssit_config (masquage / chiffrement) ===

def test_get_pssit_config_masks_tokens(datas_dir):
    pssit.create_pssit_app(datas_dir, {'id': 'MYAPP'})
    config = {
        'environments': [{'id': 'prod', 'awx': {'token': 'secret-awx'}, 'jfrog': {'token': 'secret-jfrog'}}]
    }
    store._cache.clear()
    pssit.save_pssit_config(datas_dir, 'MYAPP', config, SECRET)
    store._cache.clear()
    result = pssit.get_pssit_config(datas_dir, 'MYAPP')
    env = result['environments'][0]
    assert env['awx']['token'] == '__UNCHANGED__'
    assert env['jfrog']['token'] == '__UNCHANGED__'


def test_save_pssit_config_encrypts_tokens(datas_dir):
    pssit.create_pssit_app(datas_dir, {'id': 'MYAPP'})
    config = {
        'environments': [{'id': 'prod', 'awx': {'token': 'myrawtoken'}, 'jfrog': {'token': ''}}]
    }
    store._cache.clear()
    pssit.save_pssit_config(datas_dir, 'MYAPP', config, SECRET)
    store._cache.clear()
    raw = store.load_json(os.path.join(datas_dir, 'pssit', 'MYAPP', 'config.json'))
    awx_token = raw['environments'][0]['awx']['token']
    assert awx_token.startswith('enc:')


# === get_pssit_env_config (déchiffrement) ===

def test_get_pssit_env_config_decrypts(datas_dir):
    pssit.create_pssit_app(datas_dir, {'id': 'MYAPP'})
    config = {
        'environments': [{'id': 'prod', 'awx': {'token': 'cleartoken', 'url': 'http://awx'}, 'jfrog': {'token': ''}}]
    }
    store._cache.clear()
    pssit.save_pssit_config(datas_dir, 'MYAPP', config, SECRET)
    store._cache.clear()
    env = pssit.get_pssit_env_config(datas_dir, 'MYAPP', 'prod', SECRET)
    assert env is not None
    assert env['awx']['token'] == 'cleartoken'


def test_get_pssit_env_config_unknown_env(datas_dir):
    pssit.create_pssit_app(datas_dir, {'id': 'MYAPP'})
    store._cache.clear()
    assert pssit.get_pssit_env_config(datas_dir, 'MYAPP', 'absent', SECRET) is None


# === add_pssit_history ===

def test_add_pssit_history_prepends(datas_dir):
    pssit.create_pssit_app(datas_dir, {'id': 'MYAPP'})
    store._cache.clear()
    pssit.add_pssit_history(datas_dir, 'MYAPP', {'id': 'e1', 'action': 'start'})
    pssit.add_pssit_history(datas_dir, 'MYAPP', {'id': 'e2', 'action': 'stop'})
    store._cache.clear()
    history = pssit.get_pssit_history(datas_dir, 'MYAPP')
    assert history[0]['id'] == 'e2'
    assert history[1]['id'] == 'e1'


def test_add_pssit_history_caps_at_100(datas_dir):
    pssit.create_pssit_app(datas_dir, {'id': 'MYAPP'})
    store._cache.clear()
    for i in range(105):
        pssit.add_pssit_history(datas_dir, 'MYAPP', {'id': str(i)})
    store._cache.clear()
    history = pssit.get_pssit_history(datas_dir, 'MYAPP')
    assert len(history) == 100


# === delete_pssit_app ===

def test_delete_pssit_app_soft_deletes(datas_dir):
    pssit.create_pssit_app(datas_dir, {'id': 'MYAPP'})
    app_dir = os.path.join(datas_dir, 'pssit', 'MYAPP')
    assert os.path.isdir(app_dir)
    store._cache.clear()
    pssit.delete_pssit_app(datas_dir, 'MYAPP')
    assert not os.path.isdir(app_dir)
    assert not pssit.pssit_app_exists(datas_dir, 'MYAPP')
