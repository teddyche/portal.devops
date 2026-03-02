"""
Tests unitaires pour blueprints/ldap_checker.py.

Stratégie : subprocess.run est mocké pour retourner des sorties LDIF
prédéfinies — aucun vrai serveur AD n'est requis.
"""
import pytest
from unittest.mock import patch, MagicMock
import sys
import os

# S'assurer que le répertoire racine est dans le path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blueprints.ldap_checker import (
    _escape_ldap,
    _ldap_pattern,
    parse_ldif,
)


# ─────────────────────────────────────────────────────────────────────────────
# Tests unitaires purs (pas besoin de Flask)
# ─────────────────────────────────────────────────────────────────────────────

class TestEscapeLdap:
    """_escape_ldap doit neutraliser les chars dangereux sans toucher aux *."""

    def test_parentheses_escaped(self):
        assert '\\28' in _escape_ldap('test(')
        assert '\\29' in _escape_ldap('test)')

    def test_backslash_escaped_first(self):
        # Le \ doit être traité avant les autres pour éviter double-escape
        result = _escape_ldap('a\\b')
        assert result == 'a\\5cb'

    def test_null_byte_escaped(self):
        assert '\\00' in _escape_ldap('test\x00end')

    def test_wildcard_preserved(self):
        """* ne doit JAMAIS être échappé — c'est un wildcard LDAP voulu."""
        assert _escape_ldap('*CLP*EXE*') == '*CLP*EXE*'

    def test_clean_string_unchanged(self):
        assert _escape_ldap('jean.dupont') == 'jean.dupont'
        assert _escape_ldap('G_ZOE_ORG_CLP_ADMIN') == 'G_ZOE_ORG_CLP_ADMIN'

    def test_injection_attempt_parentheses(self):
        """Tentative classique d'injection LDAP : )(|(mail=* """
        result = _escape_ldap('*)(|(mail=*')
        assert '(' not in result.replace('\\28', '')
        assert ')' not in result.replace('\\29', '')
        # Les parenthèses échappées ne ferment pas le filtre
        assert '\\29' in result
        assert '\\28' in result


class TestLdapPattern:
    """_ldap_pattern : wildcards, espaces, contains par défaut."""

    def test_wildcard_preserved(self):
        assert _ldap_pattern('*CLP*EXE*') == '*CLP*EXE*'

    def test_no_wildcard_wrapped(self):
        """Sans *, le pattern est encadré de * (recherche contient)."""
        result = _ldap_pattern('dupont')
        assert result == '*dupont*'

    def test_space_becomes_wildcard(self):
        """Espace = * (séparateur de mots)."""
        result = _ldap_pattern('CLP EXE')
        assert result == 'CLP*EXE'

    def test_space_no_extra_wrap_if_wildcard_present(self):
        """Si des * sont déjà présents (via espace converti), pas de re-wrap."""
        result = _ldap_pattern('CLP EXE')
        # 'CLP*EXE' contient *, pas de wrap supplémentaire
        assert not result.startswith('**')

    def test_injection_attempt_sanitized(self):
        """Injection avec parenthèses : les chars dangereux sont échappés."""
        result = _ldap_pattern('*)(|(mail=*')
        # L'* de début et fin est conservé, les ( et ) sont échappés
        assert '\\28' in result or '\\29' in result

    def test_mixed_pattern(self):
        """Pattern G_ZOE_* → unchanged (déjà un *)."""
        assert _ldap_pattern('G_ZOE_*') == 'G_ZOE_*'

    def test_complex_pattern(self):
        """Pattern avec espaces et wildcards explicites."""
        result = _ldap_pattern('G_ZOE *CLP*')
        assert result == 'G_ZOE**CLP*'  # espace → *, déjà des *, pas de wrap


class TestParseLdif:
    """parse_ldif : extraction LDIF → liste de dicts."""

    def test_simple_entry(self):
        ldif = """dn: CN=TestUser,DC=zoe,DC=gca
cn: TestUser
sAMAccountName: t.user
mail: t.user@zoe.gca
"""
        entries = parse_ldif(ldif)
        assert len(entries) == 1
        assert entries[0]['cn'] == 'TestUser'
        assert entries[0]['sAMAccountName'] == 't.user'

    def test_multi_value_attribute(self):
        ldif = """dn: CN=TestUser,DC=zoe,DC=gca
cn: TestUser
memberOf: CN=GroupA,DC=zoe,DC=gca
memberOf: CN=GroupB,DC=zoe,DC=gca
"""
        entries = parse_ldif(ldif)
        raw = entries[0]['memberOf']
        assert isinstance(raw, list)
        assert len(raw) == 2

    def test_base64_attribute(self):
        # CN: TestUser encodé en base64 → VGVzdFVzZXI=
        ldif = """dn: CN=TestUser,DC=zoe,DC=gca
cn:: VGVzdFVzZXI=
"""
        entries = parse_ldif(ldif)
        assert entries[0]['cn'] == 'TestUser'

    def test_multiple_entries(self):
        ldif = """dn: CN=User1,DC=zoe,DC=gca
cn: User1

dn: CN=User2,DC=zoe,DC=gca
cn: User2
"""
        entries = parse_ldif(ldif)
        assert len(entries) == 2
        assert entries[0]['cn'] == 'User1'
        assert entries[1]['cn'] == 'User2'

    def test_empty_output(self):
        assert parse_ldif('') == []
        assert parse_ldif('\n\n') == []


# ─────────────────────────────────────────────────────────────────────────────
# Tests d'intégration avec Flask + mock subprocess
# ─────────────────────────────────────────────────────────────────────────────

LDIF_USER1 = """dn: CN=Jean Dupont,OU=Users,DC=zoe,DC=gca
cn: Jean Dupont
sAMAccountName: j.dupont
mail: j.dupont@zoe.gca
memberOf: CN=G_ZOE_PROD_READ,DC=zoe,DC=gca
memberOf: CN=G_ZOE_DEV_WRITE,DC=zoe,DC=gca
memberOf: CN=G_ZOE_ALL,DC=zoe,DC=gca
"""

LDIF_USER2 = """dn: CN=Marie Martin,OU=Users,DC=zoe,DC=gca
cn: Marie Martin
sAMAccountName: m.martin
mail: m.martin@zoe.gca
memberOf: CN=G_ZOE_PROD_READ,DC=zoe,DC=gca
memberOf: CN=G_ZOE_ALL,DC=zoe,DC=gca
"""

LDIF_GROUPS = """dn: CN=G_ZOE_ORG_CLP,DC=zoe,DC=gca
cn: G_ZOE_ORG_CLP
description: Groupe CLP
member: CN=Jean Dupont,OU=Users,DC=zoe,DC=gca

dn: CN=G_ZOE_ORG_MON,DC=zoe,DC=gca
cn: G_ZOE_ORG_MON
description: Groupe MON
"""

LDIF_GROUP_DETAILS = """dn: CN=G_ZOE_ORG_CLP,DC=zoe,DC=gca
cn: G_ZOE_ORG_CLP
description: Groupe CLP
"""


def _make_proc(stdout='', returncode=0):
    """Helper : crée un mock subprocess.CompletedProcess."""
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = ''
    return m


@pytest.fixture
def ldap_client(authed_client, mocker):
    """Client authentifié portail + session LDAP injectée.

    authed_client gère déjà le patch auth_store.AUTH_DIR et la session portail ;
    ici on ajoute uniquement les variables LDAP et la config AD mockée.
    """
    # Config LDAP minimale — évite tout accès disque/réseau réel
    mocker.patch('blueprints.ldap_checker.get_auth_config', return_value={
        'ldap_servers': [{
            'id': 'default',
            'name': 'Test AD',
            'host': 'ldaps://test.local',
            'base_dn': 'DC=zoe,DC=gca',
            'tls_verify': False,
        }]
    })

    with authed_client.session_transaction() as sess:
        sess['ldap_user'] = 'test.user'
        sess['ldap_pass'] = 'testpass'
        sess['ldap_server_id'] = 'default'

    return authed_client


class TestSearchGroups:
    def test_search_returns_results(self, ldap_client, mocker):
        mocker.patch('subprocess.run', return_value=_make_proc(LDIF_GROUPS))
        r = ldap_client.post('/api/ldap/search/groups',
                             json={'pattern': '*CLP*'},
                             headers={'X-CSRF-Token': 'test_csrf'})
        assert r.status_code == 200
        data = r.get_json()
        assert data['count'] == 2
        cns = [g['cn'] for g in data['results']]
        assert 'G_ZOE_ORG_CLP' in cns

    def test_pattern_required(self, ldap_client):
        r = ldap_client.post('/api/ldap/search/groups',
                             json={},
                             headers={'X-CSRF-Token': 'test_csrf'})
        assert r.status_code == 400
        assert 'pattern' in r.get_json()['error']

    def test_injection_attempt_does_not_crash(self, ldap_client, mocker):
        """Une tentative d'injection LDAP ne doit pas crasher ni retourner 500."""
        mocker.patch('subprocess.run', return_value=_make_proc(''))
        r = ldap_client.post('/api/ldap/search/groups',
                             json={'pattern': '*)(|(cn=*'},
                             headers={'X-CSRF-Token': 'test_csrf'})
        # Doit retourner 200 avec 0 résultats (pattern échappé, filtre invalide côté AD)
        assert r.status_code == 200
        assert r.get_json()['count'] == 0


class TestSearchUsers:
    def test_search_returns_users(self, ldap_client, mocker):
        mocker.patch('subprocess.run', return_value=_make_proc(LDIF_USER1))
        r = ldap_client.post('/api/ldap/search/users',
                             json={'pattern': 'dupont', 'by': 'all'},
                             headers={'X-CSRF-Token': 'test_csrf'})
        assert r.status_code == 200
        data = r.get_json()
        assert data['count'] == 1
        assert data['results'][0]['username'] == 'j.dupont'

    def test_space_in_pattern_becomes_wildcard(self, ldap_client, mocker):
        """Un espace dans le pattern doit être converti en * côté LDAP."""
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return _make_proc(LDIF_USER1)

        mocker.patch('subprocess.run', side_effect=mock_run)
        ldap_client.post('/api/ldap/search/users',
                         json={'pattern': 'jean dupont', 'by': 'cn'},
                         headers={'X-CSRF-Token': 'test_csrf'})
        # Le filtre construit doit contenir * à la place de l'espace
        last_cmd = ' '.join(calls[-1])
        assert 'jean*dupont' in last_cmd

    def test_injection_with_parentheses(self, ldap_client, mocker):
        """Les parenthèses dans un pattern doivent être échappées."""
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return _make_proc('')

        mocker.patch('subprocess.run', side_effect=mock_run)
        ldap_client.post('/api/ldap/search/users',
                         json={'pattern': 'test)(|(password=*'},
                         headers={'X-CSRF-Token': 'test_csrf'})
        last_cmd = ' '.join(calls[-1])
        # Les ( et ) doivent être échappés en \28 et \29
        assert '\\28' in last_cmd or '(' not in last_cmd.split('(objectClass')[1]


class TestCompareUsers:
    def test_compare_two_users(self, ldap_client, mocker):
        side_effects = [
            _make_proc(LDIF_USER1),  # j.dupont
            _make_proc(LDIF_USER2),  # m.martin
        ]
        mocker.patch('subprocess.run', side_effect=side_effects)
        r = ldap_client.post('/api/ldap/compare-users',
                             json={'users': ['j.dupont', 'm.martin']},
                             headers={'X-CSRF-Token': 'test_csrf'})
        assert r.status_code == 200
        data = r.get_json()
        assert len(data['users']) == 2
        assert data['stats']['total'] == 3   # G_ZOE_ALL, G_ZOE_PROD_READ, G_ZOE_DEV_WRITE
        assert data['stats']['common'] == 2  # G_ZOE_ALL + G_ZOE_PROD_READ
        assert data['stats']['exclusive'] == 1  # G_ZOE_DEV_WRITE (j.dupont seulement)

    def test_compare_requires_two_users(self, ldap_client, mocker):
        r = ldap_client.post('/api/ldap/compare-users',
                             json={'users': ['j.dupont']},
                             headers={'X-CSRF-Token': 'test_csrf'})
        assert r.status_code == 400

    def test_compare_max_8_users(self, ldap_client, mocker):
        r = ldap_client.post('/api/ldap/compare-users',
                             json={'users': [f'user{i}' for i in range(9)]},
                             headers={'X-CSRF-Token': 'test_csrf'})
        assert r.status_code == 400
        assert '8' in r.get_json()['error']

    def test_user_not_found_returns_404(self, ldap_client, mocker):
        mocker.patch('subprocess.run', return_value=_make_proc(''))  # aucun résultat
        r = ldap_client.post('/api/ldap/compare-users',
                             json={'users': ['fantome', 'inconnu']},
                             headers={'X-CSRF-Token': 'test_csrf'})
        assert r.status_code == 404

    def test_retrocompat_user1_user2(self, ldap_client, mocker):
        """L'ancien format {user1, user2} doit toujours fonctionner."""
        mocker.patch('subprocess.run', side_effect=[
            _make_proc(LDIF_USER1),
            _make_proc(LDIF_USER2),
        ])
        r = ldap_client.post('/api/ldap/compare-users',
                             json={'user1': 'j.dupont', 'user2': 'm.martin'},
                             headers={'X-CSRF-Token': 'test_csrf'})
        assert r.status_code == 200
        assert len(r.get_json()['users']) == 2


class TestCompareGroupUsers:
    def test_compare_group_members(self, ldap_client, mocker):
        mocker.patch('subprocess.run', side_effect=[
            _make_proc(LDIF_GROUP_DETAILS),   # résolution du groupe
            _make_proc(LDIF_USER1 + '\n' + LDIF_USER2),  # membres
        ])
        r = ldap_client.post('/api/ldap/compare-group-users',
                             json={'group': 'G_ZOE_ORG_CLP'},
                             headers={'X-CSRF-Token': 'test_csrf'})
        assert r.status_code == 200
        data = r.get_json()
        assert data['group']['cn'] == 'G_ZOE_ORG_CLP'
        assert len(data['users']) == 2
        assert data['stats']['common'] == 2   # G_ZOE_ALL + G_ZOE_PROD_READ
        assert data['stats']['exclusive'] == 1  # G_ZOE_DEV_WRITE

    def test_group_not_found(self, ldap_client, mocker):
        mocker.patch('subprocess.run', return_value=_make_proc(''))
        r = ldap_client.post('/api/ldap/compare-group-users',
                             json={'group': 'FANTOME'},
                             headers={'X-CSRF-Token': 'test_csrf'})
        assert r.status_code == 404

    def test_group_required(self, ldap_client):
        r = ldap_client.post('/api/ldap/compare-group-users',
                             json={},
                             headers={'X-CSRF-Token': 'test_csrf'})
        assert r.status_code == 400

    def test_group_too_many_members(self, ldap_client, mocker):
        # Générer 31 entrées LDIF
        big_ldif = '\n'.join(
            f'dn: CN=User{i},DC=zoe,DC=gca\ncn: User{i}\nsAMAccountName: user{i}\n'
            for i in range(31)
        )
        mocker.patch('subprocess.run', side_effect=[
            _make_proc(LDIF_GROUP_DETAILS),
            _make_proc(big_ldif),
        ])
        r = ldap_client.post('/api/ldap/compare-group-users',
                             json={'group': 'G_ZOE_ORG_CLP'},
                             headers={'X-CSRF-Token': 'test_csrf'})
        assert r.status_code == 400
        assert '30' in r.get_json()['error']


class TestLdapAuth:
    def test_auth_required_for_all_endpoints(self, authed_client):
        """Sans session LDAP, tous les endpoints doivent retourner 401."""
        endpoints = [
            ('/api/ldap/search/groups', {'pattern': '*'}),
            ('/api/ldap/search/users', {'pattern': '*'}),
            ('/api/ldap/search/user-groups', {'username': 'test'}),
            ('/api/ldap/search/group-members', {'group': 'G_TEST'}),
            ('/api/ldap/compare-users', {'users': ['a', 'b']}),
            ('/api/ldap/compare-group-users', {'group': 'G_TEST'}),
        ]
        for url, body in endpoints:
            r = authed_client.post(url, json=body,
                                   headers={'X-CSRF-Token': 'test_csrf'})
            assert r.status_code == 401, f'{url} devrait retourner 401 sans LDAP auth'
