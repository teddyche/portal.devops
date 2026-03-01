"""Tests auth : CSRF enforcement et validation JWT audience."""
import base64
import json
import time

import pytest

import services.store as store


@pytest.fixture(autouse=True)
def clear_cache():
    store._cache.clear()
    yield
    store._cache.clear()


def _b64(data: dict) -> str:
    """Encode un dict en base64url sans padding (format JWT)."""
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')


# === CSRF ===

def test_post_without_csrf_token_returns_403(authed_client):
    """POST sans header X-CSRF-Token doit être rejeté par require_auth (403)."""
    rv = authed_client.post('/api/clusters', json={'id': 'CLP01'})
    assert rv.status_code == 403


def test_put_without_csrf_token_returns_403(authed_client):
    """PUT sans header X-CSRF-Token doit être rejeté."""
    rv = authed_client.put('/api/clusters/CLP01', json={'name': 'X'})
    assert rv.status_code == 403


def test_delete_without_csrf_token_returns_403(authed_client):
    """DELETE sans header X-CSRF-Token doit être rejeté."""
    rv = authed_client.delete('/api/clusters/CLP01')
    assert rv.status_code == 403


def test_post_with_wrong_csrf_token_returns_403(authed_client):
    """POST avec un X-CSRF-Token incorrect doit être rejeté."""
    rv = authed_client.post(
        '/api/clusters',
        json={'id': 'CLP01'},
        headers={'X-CSRF-Token': 'wrong_token'},
    )
    assert rv.status_code == 403


# === JWT audience ===

def test_verify_id_token_wrong_audience_raises(mocker):
    """verify_id_token doit lever ValueError quand aud != client_id."""
    from auth import verify_id_token

    header  = _b64({'alg': 'RS256', 'kid': 'k1'})
    payload = _b64({'aud': 'WRONG_CLIENT', 'exp': int(time.time()) + 3600})
    n_b64   = base64.urlsafe_b64encode(b'\x01' * 128).decode().rstrip('=')
    fake_jwt = f'{header}.{payload}.dummysig'

    mocker.patch('auth._fetch_jwks', return_value={
        'keys': [{'kid': 'k1', 'n': n_b64, 'e': 'AQAB'}]
    })
    mock_key = mocker.MagicMock()
    mock_key.verify.return_value = None
    mocker.patch('auth.RSAPublicNumbers').return_value.public_key.return_value = mock_key

    adfs = {
        'client_id': 'CORRECT_CLIENT',
        'jwks_uri': 'https://fake/jwks',
        'authority': 'https://fake',
    }
    with pytest.raises(ValueError, match='Audience'):
        verify_id_token(fake_jwt, adfs)


def test_verify_id_token_list_audience_ok(mocker):
    """verify_id_token accepte un aud sous forme de liste contenant le client_id."""
    from auth import verify_id_token

    header  = _b64({'alg': 'RS256', 'kid': 'k1'})
    payload = _b64({'aud': ['CORRECT_CLIENT', 'other'], 'exp': int(time.time()) + 3600})
    n_b64   = base64.urlsafe_b64encode(b'\x01' * 128).decode().rstrip('=')
    fake_jwt = f'{header}.{payload}.dummysig'

    mocker.patch('auth._fetch_jwks', return_value={
        'keys': [{'kid': 'k1', 'n': n_b64, 'e': 'AQAB'}]
    })
    mock_key = mocker.MagicMock()
    mock_key.verify.return_value = None
    mocker.patch('auth.RSAPublicNumbers').return_value.public_key.return_value = mock_key

    adfs = {
        'client_id': 'CORRECT_CLIENT',
        'jwks_uri': 'https://fake/jwks',
        'authority': 'https://fake',
    }
    claims = verify_id_token(fake_jwt, adfs)
    assert claims['aud'] == ['CORRECT_CLIENT', 'other']


def test_verify_id_token_expired_raises(mocker):
    """verify_id_token doit rejeter un token expiré."""
    from auth import verify_id_token

    header  = _b64({'alg': 'RS256', 'kid': 'k1'})
    payload = _b64({'aud': 'MY_CLIENT', 'exp': int(time.time()) - 60})  # expired
    n_b64   = base64.urlsafe_b64encode(b'\x01' * 128).decode().rstrip('=')
    fake_jwt = f'{header}.{payload}.dummysig'

    mocker.patch('auth._fetch_jwks', return_value={
        'keys': [{'kid': 'k1', 'n': n_b64, 'e': 'AQAB'}]
    })
    mock_key = mocker.MagicMock()
    mock_key.verify.return_value = None
    mocker.patch('auth.RSAPublicNumbers').return_value.public_key.return_value = mock_key

    adfs = {
        'client_id': 'MY_CLIENT',
        'jwks_uri': 'https://fake/jwks',
        'authority': 'https://fake',
    }
    with pytest.raises(ValueError, match='expiré'):
        verify_id_token(fake_jwt, adfs)
