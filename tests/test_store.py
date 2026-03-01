"""Tests de la couche I/O JSON et du cache dans services/store.py."""
import json
import os

import pytest

import services.store as store


@pytest.fixture(autouse=True)
def clear_cache():
    """Vide le cache entre chaque test."""
    store._cache.clear()
    yield
    store._cache.clear()


# === load_json ===

def test_load_json_missing_file(tmp_path):
    result = store.load_json(str(tmp_path / 'absent.json'))
    assert result is None


def test_load_json_existing_file(tmp_path):
    path = str(tmp_path / 'data.json')
    (tmp_path / 'data.json').write_text(json.dumps({'key': 'value'}), encoding='utf-8')
    result = store.load_json(path)
    assert result == {'key': 'value'}


def test_load_json_cache_hit(tmp_path, mocker):
    """La 2e lecture utilise le cache, sans toucher au disque."""
    path = str(tmp_path / 'data.json')
    (tmp_path / 'data.json').write_text(json.dumps([1, 2, 3]), encoding='utf-8')
    store.load_json(path)  # 1re lecture → disque + cache

    mock_open = mocker.patch('builtins.open', side_effect=AssertionError('ne devrait pas lire le disque'))
    result = store.load_json(path)  # 2e lecture → cache
    assert result == [1, 2, 3]


# === save_json ===

def test_save_json_creates_file(tmp_path):
    path = str(tmp_path / 'sub' / 'out.json')
    store.save_json(path, {'a': 1})
    assert os.path.exists(path)
    with open(path, encoding='utf-8') as f:
        assert json.load(f) == {'a': 1}


def test_save_json_updates_cache(tmp_path):
    path = str(tmp_path / 'out.json')
    store.save_json(path, {'x': 42})
    # La lecture doit retourner la valeur sans toucher au disque
    hit, data = store._cache_get(path)
    assert hit is True
    assert data == {'x': 42}


def test_save_json_write_through(tmp_path):
    """Après save, load retourne les nouvelles données immédiatement."""
    path = str(tmp_path / 'data.json')
    store.save_json(path, {'v': 1})
    store.save_json(path, {'v': 2})
    assert store.load_json(path) == {'v': 2}


# === soft_delete_dir ===

def test_soft_delete_moves_to_trash(tmp_path):
    src = tmp_path / 'my_dir'
    src.mkdir()
    (src / 'file.txt').write_text('hello')
    trash = tmp_path / '_trash'

    store.soft_delete_dir(str(src), 'cluster', str(trash))

    assert not src.exists()
    trashed = list(trash.iterdir())
    assert len(trashed) == 1
    assert 'cluster' in trashed[0].name
    assert (trashed[0] / 'file.txt').exists()


def test_soft_delete_missing_dir_is_noop(tmp_path):
    """Ne doit pas lever d'exception si le dossier n'existe pas."""
    store.soft_delete_dir(str(tmp_path / 'absent'), 'kind', str(tmp_path / '_trash'))


# === safe_id ===

def test_safe_id_valid():
    for v in ('ABC', 'abc-123', 'my_cluster', 'CLP01'):
        assert store.safe_id(v) is True


def test_safe_id_invalid():
    for v in ('', 'a b', 'a/b', 'a.b', '../etc', 'toto!'):
        assert store.safe_id(v) is False
