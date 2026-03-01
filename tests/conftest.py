"""
Fixtures pytest partagées pour tous les tests.
"""
import json
import pytest


@pytest.fixture
def tmp_data_dir(tmp_path):
    """Crée une structure de répertoires datas/ temporaire avec un utilisateur test."""
    for d in ('auth', 'pssit', 'cad', '_trash'):
        (tmp_path / d).mkdir()

    secret = 'test-secret-key-32chars-padding!!'
    (tmp_path / 'auth' / 'config.json').write_text(
        json.dumps({'secret_key': secret, 'local_admin': {}, 'ssl_verify': True}),
        encoding='utf-8',
    )
    # Utilisateur superadmin — nécessaire pour que require_auth le reconnaisse
    (tmp_path / 'auth' / 'users.json').write_text(
        json.dumps([{'id': 'test_user', 'role': 'superadmin', 'display_name': 'Test User'}]),
        encoding='utf-8',
    )
    return tmp_path


@pytest.fixture
def app(tmp_data_dir):
    """Application Flask en mode test avec un datas_dir temporaire."""
    from dashboard import create_app
    application = create_app({
        'TESTING': True,
        'DATAS_DIR': str(tmp_data_dir),
    })
    application.secret_key = 'test-secret-key-32chars-padding!!'
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def authed_client(client, tmp_data_dir, mocker):
    """Client HTTP avec session authentifiée (superadmin).
    Redirige auth.AUTH_DIR vers le répertoire temporaire pour que
    require_auth trouve l'utilisateur test dans users.json.
    """
    import auth
    mocker.patch.object(auth, 'AUTH_DIR', str(tmp_data_dir / 'auth'))

    with client.session_transaction() as sess:
        sess['user_id'] = 'test_user'
        sess['role'] = 'superadmin'
        sess['display_name'] = 'Test User'
        sess['csrf_token'] = 'test_csrf'
    return client
