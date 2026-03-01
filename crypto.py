"""
Chiffrement symétrique des tokens sensibles (AWX, JFrog) stockés en JSON.

La clé Fernet est dérivée du SECRET_KEY Flask via SHA-256.
Les valeurs chiffrées sont préfixées par 'enc:' pour distinguer
les tokens existants en clair (rétrocompatibilité).
"""
import hashlib
import base64
from cryptography.fernet import Fernet, InvalidToken

_PREFIX = 'enc:'


def _get_fernet(secret_key: str) -> Fernet:
    key_bytes = hashlib.sha256(secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key_bytes))


def encrypt_token(value: str, secret_key: str) -> str:
    """Chiffre un token. Retourne la valeur inchangée si vide ou déjà chiffrée."""
    if not value or value == '__UNCHANGED__' or value.startswith(_PREFIX):
        return value
    f = _get_fernet(secret_key)
    return _PREFIX + f.encrypt(value.encode()).decode()


def decrypt_token(value: str, secret_key: str) -> str:
    """Déchiffre un token. Retourne la valeur brute si non chiffrée (legacy)."""
    if not value or not value.startswith(_PREFIX):
        return value
    try:
        f = _get_fernet(secret_key)
        return f.decrypt(value[len(_PREFIX):].encode()).decode()
    except (InvalidToken, Exception):
        return ''


def mask_token(value: str) -> str:
    """Remplace un token (chiffré ou non) par le sentinel '__UNCHANGED__' pour le frontend."""
    if not value:
        return ''
    return '__UNCHANGED__'
