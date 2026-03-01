"""
Chiffrement symétrique des tokens sensibles (AWX, JFrog, client_secret ADFS).

Deux versions de dérivation de clé :
  enc:   SHA-256  — legacy, lecture seule pour rétrocompatibilité
  enc2:  PBKDF2-HMAC-SHA256 (480 000 itérations) — utilisé pour tous les nouveaux chiffrements

Les valeurs chiffrées sont préfixées par 'enc:' ou 'enc2:' afin de distinguer
les tokens existants en clair.
"""
import base64
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_PREFIX_V1 = 'enc:'   # SHA-256 — legacy
_PREFIX_V2 = 'enc2:'  # PBKDF2-HMAC-SHA256
_PBKDF2_SALT = b'portal.devops.v2'
_PBKDF2_ITER = 480_000


def _fernet_v1(secret_key: str) -> Fernet:
    key_bytes = hashlib.sha256(secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key_bytes))


def _fernet_v2(secret_key: str) -> Fernet:
    key_bytes = hashlib.pbkdf2_hmac('sha256', secret_key.encode(), _PBKDF2_SALT, _PBKDF2_ITER)
    return Fernet(base64.urlsafe_b64encode(key_bytes))


def encrypt_token(value: str, secret_key: str) -> str:
    """Chiffre un token avec PBKDF2 (enc2:). Retourne inchangé si vide ou déjà chiffré."""
    if not value or value == '__UNCHANGED__':
        return value
    if value.startswith(_PREFIX_V1) or value.startswith(_PREFIX_V2):
        return value
    return _PREFIX_V2 + _fernet_v2(secret_key).encrypt(value.encode()).decode()


def decrypt_token(value: str, secret_key: str) -> str:
    """Déchiffre un token enc2: (PBKDF2) ou enc: (SHA-256 legacy). Retourne brut si non chiffré."""
    if not value:
        return value
    if value.startswith(_PREFIX_V2):
        try:
            return _fernet_v2(secret_key).decrypt(value[len(_PREFIX_V2):].encode()).decode()
        except (InvalidToken, Exception) as e:
            logger.warning('decrypt_token enc2: déchiffrement échoué : %s', e)
            return ''
    if value.startswith(_PREFIX_V1):
        try:
            return _fernet_v1(secret_key).decrypt(value[len(_PREFIX_V1):].encode()).decode()
        except (InvalidToken, Exception) as e:
            logger.warning('decrypt_token enc: déchiffrement échoué : %s', e)
            return ''
    return value


def mask_token(value: str) -> str:
    """Remplace un token (chiffré ou non) par le sentinel '__UNCHANGED__' pour le frontend."""
    if not value:
        return ''
    return '__UNCHANGED__'
