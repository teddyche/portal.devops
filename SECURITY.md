# Sécurité — portal.devops

> Document de référence interne. Décrit les mécanismes de sécurité existants,
> les points d'attention identifiés et les recommandations d'amélioration.
> **Dernière mise à jour : 2026-03-02**

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Authentification](#2-authentification)
3. [Autorisation et RBAC](#3-autorisation-et-rbac)
4. [Protection CSRF](#4-protection-csrf)
5. [Chiffrement des tokens sensibles](#5-chiffrement-des-tokens-sensibles)
6. [Stockage des données](#6-stockage-des-données)
7. [Validation des entrées](#7-validation-des-entrées)
8. [Vérification SSL/TLS](#8-vérification-ssltls)
9. [Rate limiting](#9-rate-limiting)
10. [Journalisation et audit](#10-journalisation-et-audit)
11. [CORS](#11-cors)
12. [Points d'attention et recommandations](#12-points-dattention-et-recommandations)

---

## 1. Vue d'ensemble

portal.devops est un portail interne qui orchestre des opérations sur trois modules :
**SRE** (clusters), **PSSIT** (applications) et **CAD** (workspaces). Il pilote des
systèmes tiers sensibles (AWX/Ansible, JFrog Artifactory, LDAP/ADFS).

À ce titre, la surface d'attaque comprend :
- Des tokens d'API tiers stockés sur disque (AWX, JFrog, ADFS client_secret)
- Un flux OAuth2 Authorization Code vers ADFS
- Un accès LDAP en lecture (annuaire Active Directory)
- Des appels HTTP sortants vers des systèmes internes avec authentification Bearer

---

## 2. Authentification

### 2.1 Admin local (`auth.py`)

| Aspect | Implémentation |
|--------|---------------|
| Hashage | **bcrypt** (salt aléatoire via `bcrypt.gensalt()`) |
| Vérification | `bcrypt.checkpw()` — résistant aux attaques timing |
| Rate limiting | 5 tentatives / 5 min → verrouillage 15 min |
| Thread-safety | `threading.Lock()` sur le compteur de tentatives |
| Audit | Toute tentative (succès/échec) journalisée avec IP + hash SHA-256[:8] du login |

```python
# auth.py — lockout
_MAX_ATTEMPTS = 5
_LOCKOUT_SEC  = 900   # 15 min
_WINDOW_SEC   = 300   # fenêtre 5 min
```

**⚠ Limite** : le compteur de tentatives est **en mémoire** — il est perdu au
redémarrage. Un attaquant qui redémarre l'app (ou attend un rechargement) contourne
le verrouillage.

---

### 2.2 ADFS / OAuth2 (`auth.py`)

Flux complet **Authorization Code** avec :

| Mécanisme | Détail |
|-----------|--------|
| State token | `secrets.token_hex(16)` — protège contre le CSRF OAuth2 |
| Vérification JWT | Signature **RS256** via JWKS (clé publique ADFS) |
| Bibliothèque crypto | `cryptography.hazmat.primitives.asymmetric` (RSA-PKCS1v15 ou PSS) |
| Validation `exp` | Vérifiée : `payload.get('exp', now+1) < now` → 401 |
| Validation `aud` | Vérifiée contre `client_id` configuré |
| Cache JWKS | TTL 600 s — recharge automatiquement les clés en cas de rotation ADFS |
| Whitelist erreurs ADFS | `_ADFS_SAFE_ERRORS` (frozenset) — empêche l'injection XSS via le paramètre `error` |
| Rate limiting callback | Par IP, via Flask-Limiter |

```python
# auth.py — whitelist des codes d'erreur ADFS autorisés dans les redirections
_ADFS_SAFE_ERRORS = frozenset({
    'access_denied', 'invalid_request', 'unauthorized_client',
    'unsupported_response_type', 'invalid_scope', 'server_error',
    'temporarily_unavailable', 'too_many_requests',
})
```

**⚠ Limites** :
- Pas de **PKCE** (RFC 7636) — recommandé pour les web apps même avec client_secret
- Pas de validation du claim **`nonce`** dans le JWT — léger risque de rejeu
- Le `kid` JWKS : si absent du JWT, la première clé du JWKS est utilisée par fallback
  (risque de sélection de mauvaise clé si ADFS en rotation)

---

### 2.3 Gestion de session

| Aspect | Détail |
|--------|--------|
| Stockage | Cookie signé côté client (Flask session — HMAC avec `secret_key`) |
| CSRF token | Généré à la connexion : `secrets.token_hex(32)` = 256 bits |
| Déconnexion | `session.clear()` — invalide immédiatement le cookie |
| Invalidation auto | Si l'utilisateur n'existe plus en base, session effacée |

**⚠ Limite** : **pas de timeout de session** — une session reste valide indéfiniment
jusqu'à déconnexion explicite. Sur un poste partagé, cela pose un risque.

---

## 3. Autorisation et RBAC

### 3.1 Modèle de données (`auth_store.py`)

```
Utilisateurs  →  Rôle (superadmin | admin | user)
     │
     └─ Équipes  →  Ressources (module + resource_id)
                       Modules : sre | cad | pssit | api_docs
```

- Un **superadmin** contourne toutes les vérifications de ressource.
- Un **admin** a les droits d'administration d'au moins une équipe.
- Un **user** n'accède qu'aux ressources explicitement assignées à son équipe.

### 3.2 Vérification des accès (`auth.py — require_auth / has_resource_access`)

La fonction `before_request` vérifie pour chaque appel :
1. Présence d'une session valide (sinon 401)
2. Appartenance à la ressource demandée via regex sur le chemin :

```python
_checks = [
    (re.match(r'^(?:/api)?/cluster/([A-Za-z0-9_-]+)',  path), 'sre'),
    (re.match(r'^(?:/api)?/cad/workspace/([A-Za-z0-9_-]+)', path), 'cad'),
    (re.match(r'^(?:/api)?/pssit/app/([A-Za-z0-9_-]+)', path), 'pssit'),
]
```

3. Les IDs de ressources n'acceptent que `[A-Za-z0-9_-]` — pas d'injection possible.

**⚠ Limite** : les regex ci-dessus **n'ont pas d'ancre de fin** (`$`). Un chemin comme
`/api/pssit/app/FOO/config` matche `FOO` → OK dans la pratique (l'ID est extrait du
segment), mais un chemin `…/app/ADMIN/../../other` pourrait théoriquement extraire
`ADMIN` et passer la vérification si `ADMIN` est une ressource autorisée.
**→ Recommandation : ancrer les regex avec `$` après le groupe capturant.**

---

## 4. Protection CSRF

Chaque requête `POST`, `PUT` ou `DELETE` est validée par double-submit :

| Élément | Valeur |
|---------|--------|
| Token | `secrets.token_hex(32)` — généré à la connexion |
| Stockage serveur | Flask session (signé, HttpOnly implicite) |
| Envoi client | Header `X-CSRF-Token` |
| Vérification | `session['csrf_token'] == request.headers.get('X-CSRF-Token')` |

```python
# auth.py — validation CSRF
if request.method in ('POST', 'PUT', 'DELETE'):
    client_tok = request.headers.get('X-CSRF-Token', '')
    if not secrets.compare_digest(session.get('csrf_token', ''), client_tok):
        abort(403)
```

Le token est transmis au frontend via l'endpoint `/api/auth/me` (réponse JSON) afin
que les SPA puissent l'inclure dans leurs requêtes sans accès aux cookies.

**⚠ Limite** : exposer le token CSRF dans une réponse JSON est une pratique courante
pour les SPA mais signifie que tout script s'exécutant sur la page peut le lire.
L'efficacité repose donc sur l'absence de XSS. La **politique CSP** n'est pas
configurée au niveau de l'application — c'est au reverse-proxy de la définir.

---

## 5. Chiffrement des tokens sensibles

### 5.1 Module `crypto.py`

Tous les tokens tiers (AWX, JFrog, ADFS client_secret, SMTP) sont chiffrés au repos
via **Fernet** (AES-128-CBC + HMAC-SHA256 pour l'intégrité).

Deux schémas de dérivation de clé coexistent pour la rétrocompatibilité :

| Préfixe | Algorithme | Itérations | Statut |
|---------|-----------|------------|--------|
| `enc:`  | SHA-256(secret_key) → clé Fernet | — | **Legacy** — lecture seule |
| `enc2:` | PBKDF2-HMAC-SHA256(secret_key, salt, 600 000 iter) | 600 000 | **Actuel** — tous les nouveaux chiffrements |

```python
_PREFIX_V1   = 'enc:'               # SHA-256 — legacy
_PREFIX_V2   = 'enc2:'              # PBKDF2-HMAC-SHA256
_PBKDF2_SALT = b'portal.devops.v2'  # sel fixe
_PBKDF2_ITER = 600_000
```

- La fonction `encrypt_token()` chiffre uniquement si la valeur n'est pas déjà
  préfixée et n'est pas le sentinel `__UNCHANGED__`.
- La fonction `decrypt_token()` supporte les deux préfixes — les valeurs sans préfixe
  sont retournées telles quelles (tokens en clair présents avant l'introduction du
  chiffrement).
- `mask_token()` remplace tout token non-vide par `'__UNCHANGED__'` avant de l'envoyer
  au frontend — le token réel n'est jamais exposé dans l'API de lecture.

### 5.2 Sentinel `__UNCHANGED__`

Le flux de mise à jour des tokens est le suivant :

```
Chargement config  →  mask_token() → '__UNCHANGED__' envoyé au frontend
Sauvegarde config  →  si valeur == '__UNCHANGED__' ou vide → conserver ancien token
                   →  sinon → encrypt_token(nouvelle_valeur)
```

Ce mécanisme évite la ré-saisie systématique des tokens à chaque enregistrement de
configuration.

### 5.3 Clé secrète (`dashboard.py`)

La `secret_key` Flask est chargée depuis `datas/auth/config.json`. Elle sert à la
fois à :
- Signer les cookies de session Flask
- Dériver la clé de chiffrement Fernet via PBKDF2

**⚠ Points d'attention** :
- Le **sel PBKDF2 est fixe** (`b'portal.devops.v2'`). Si `datas/auth/config.json`
  est compromis, un attaquant connaissant le sel peut tenter une attaque par
  dictionnaire sur les tokens chiffrés. Un sel aléatoire par token stocké à côté du
  ciphertext serait plus robuste.
- La clé est stockée **en clair** dans `config.json`. Les permissions fichier
  (`chmod 600`) sont la seule protection au niveau OS. Un accès en lecture au
  système de fichiers compromet l'ensemble des tokens chiffrés.
- **Aucun mécanisme de rotation** — changer la clé invalide tous les tokens chiffrés
  existants.

---

## 6. Stockage des données

### 6.1 Format et organisation (`services/store.py`)

Toutes les données sont stockées en JSON dans `datas/` :

```
datas/
├── auth/
│   ├── config.json      # config générale + secret_key
│   └── secrets.json     # ADFS client_secret, SMTP password (chiffrés enc2:)
├── pssit/
│   └── <app_id>/
│       ├── config.json  # tokens AWX/JFrog chiffrés enc2:
│       ├── history.json
│       └── schedules.json
├── sre/
│   └── <cluster_id>/
│       └── config.json
├── cad/
│   └── <ws_id>/
│       └── config.json
└── _trash/              # soft-delete — données supprimées conservées 90 j
```

### 6.2 Écriture atomique

`save_json()` utilise un fichier `.tmp` + `os.replace()` sous verrou — garantit
qu'aucun lecteur concurrent ne verra un fichier partiellement écrit.

### 6.3 Cache en mémoire

Un cache write-through thread-safe avec TTL 30 s évite les I/O répétées. Le cache
retourne systématiquement un **`copy.deepcopy()`** pour prévenir les mutations
accidentelles du cache par les appelants.

> **Note historique** : l'absence de deepcopy sur la première lecture disque (cache
> miss) causait un empoisonnement silencieux du cache (`token → '__UNCHANGED__'`).
> Ce bug a été corrigé (commit `e18f416`).

### 6.4 Suppression douce (_trash)

Les entités supprimées sont déplacées dans `datas/_trash/<timestamp>_<type>_<id>/`
et non immédiatement effacées. La purge automatique intervient après 90 jours.
Cela constitue un filet de sécurité contre les suppressions accidentelles mais
signifie que des données potentiellement sensibles restent sur le disque pendant
cette période.

---

## 7. Validation des entrées

### 7.1 Identifiants (`services/store.py — safe_id`)

Tous les identifiants créés par les utilisateurs (cluster_id, app_id, workspace_id)
sont validés par :

```python
def safe_id(value: str) -> bool:
    return bool(value) and len(value) <= 50 and bool(re.match(r'^[A-Za-z0-9_-]+$', value))
```

- Whitelist stricte : alphanumériques, tiret, underscore
- Longueur max 50 caractères
- Empêche l'injection de chemin (`../`, `/`, etc.)

### 7.2 Paramètres AWX (`services/pssit.py — _validate_params`)

Les `extra_vars` envoyées à AWX sont validées :

| Contrainte | Valeur |
|-----------|--------|
| Nombre max de clés | 20 |
| Format clé | `^[A-Za-z0-9_-]{1,64}$` |
| Types valeurs autorisés | `str`, `int`, `float`, `bool` uniquement |
| Longueur max d'une valeur str | 512 caractères |

### 7.3 Corps JSON (`blueprints/__init__.py`)

`_require_json()` utilise `request.get_json(force=True, silent=True)` — accepte tout
corps JSON valide quel que soit le Content-Type. Cela est intentionnel (clients variés)
mais signifie que l'en-tête `Content-Type` n'est pas vérifié.

---

## 8. Vérification SSL/TLS

### 8.1 Configuration globale (`auth.py — get_ssl_verify`)

```python
def get_ssl_verify() -> bool | str:
    val = get_auth_config().get('ssl_verify', True)
    if isinstance(val, str) and not os.path.isfile(val):
        logger.warning('CA bundle introuvable — SSL verify forcé à True')
        return True
    return val
```

- Défaut : `True` (vérification stricte)
- Peut pointer vers un **bundle CA personnalisé** (chemin absolu) pour les PKI internes
- Si le fichier CA est introuvable, retombe sur `True` (jamais de désactivation silencieuse)

### 8.2 Vérification par environnement PSSIT

Chaque environnement PSSIT peut surcharger la vérification SSL globale via
`env.ssl_verify`. Cela permet de gérer les serveurs AWX/JFrog avec certificats
auto-signés ou PKI interne non reconnue.

```python
verify = env_config.get('ssl_verify', ssl_verify)
```

**⚠ Risque** : désactiver `ssl_verify` sur un environnement de production expose les
tokens Bearer envoyés à AWX/JFrog à une attaque MITM. À n'utiliser qu'en
développement/lab. **En production, configurer le bundle CA plutôt que de désactiver.**

---

## 9. Rate limiting

Flask-Limiter est configuré avec les limites globales :

```python
Limiter(
    get_remote_address,
    app=app,
    default_limits=['200 per minute', '20 per second'],
    storage_uri='memory://',
)
```

Limites spécifiques additionnelles sur :
- `POST /auth/login` — 10 tentatives / minute par IP (en plus du lockout applicatif)
- `GET /auth/callback` (ADFS) — protégé par rate limiting IP

**⚠ Limite** : le stockage est **en mémoire** (`memory://`). Sous gunicorn multi-worker
ou après redémarrage, les compteurs sont réinitialisés. Pour un déploiement en
production scalé, utiliser `storage_uri='redis://...'`.

---

## 10. Journalisation et audit

### 10.1 Logger d'audit

Un logger dédié `audit` (séparé du logger applicatif) trace les opérations
sensibles :

```python
_audit = logging.getLogger('audit')
```

**Événements audités :**

| Module | Événements |
|--------|-----------|
| auth | login succès/échec, callback ADFS, logout |
| pssit | création/modification/suppression app, sauvegarde config, lancement workflow, planification |
| sre | création/modification/suppression cluster, sauvegarde config |
| cad | création/modification/suppression workspace, sauvegarde config |

**Format type :**
```
pssit_workflow_launched user=jdupont app=YA env=PROD action=deploy
```

### 10.2 Hachage des logins dans les logs d'authentification

Pour respecter le RGPD, les noms d'utilisateurs dans les logs d'échec de connexion
sont hachés :

```python
def _hash_for_log(username: str) -> str:
    return hashlib.sha256(username.encode()).hexdigest()[:8]
```

### 10.3 Lacunes d'audit actuelles

- **Pas de journalisation des refus d'autorisation (403)** — impossible de détecter
  une tentative d'accès à des ressources non autorisées
- **Pas d'identifiant de corrélation** par requête — difficile de reconstituer un
  flux d'actions d'un même utilisateur
- **Les suppressions (soft-delete)** ne sont pas auditées

---

## 11. CORS

```python
CORS(app, origins=_cors_origins, supports_credentials=True)
```

Les origines autorisées sont configurées via :
1. La variable d'environnement `CORS_ORIGINS` (liste séparée par virgules)
2. La clé `CORS_ORIGINS` dans la config Flask (tests)

Si `CORS_ORIGINS` est vide, **aucune origine n'est autorisée** par Flask-CORS
(comportement restrictif par défaut).

**⚠ Attention** : `supports_credentials=True` combiné à une liste d'origines trop
permissive (ex: `*`) permettrait à n'importe quel site d'effectuer des requêtes
authentifiées. En pratique, `*` est incompatible avec `supports_credentials=True`
côté navigateur (CORS spec), mais **ne jamais mettre `*` dans CORS_ORIGINS**.

---

## 12. Points d'attention et recommandations

### 🔴 Haute priorité

| # | Problème | Localisation | Recommandation |
|---|---------|-------------|----------------|
| 1 | **Sel PBKDF2 fixe** — attaque dictionnaire possible si `config.json` est exfiltré | `crypto.py:21` | Générer un sel aléatoire par token, le stocker avec le ciphertext |
| 2 | **Pas de timeout de session** — session valide indéfiniment | `auth.py` | `SESSION_COOKIE_AGE = 3600` (1 h) ou via `before_request` |
| 3 | **Regex d'autorisation sans ancre de fin** — risque de contournement | `auth.py:294-296` | Ajouter `$` après le groupe capturant |
| 4 | **Rate limiting en mémoire** — réinitialisé au redémarrage | `dashboard.py:77` | Migrer vers `storage_uri='redis://...'` en production |
| 5 | **`ssl_verify=False` en production** — MITM possible sur tokens AWX/JFrog | `services/pssit.py` | Interdire en production ; utiliser bundle CA à la place |

### 🟡 Priorité moyenne

| # | Problème | Localisation | Recommandation |
|---|---------|-------------|----------------|
| 6 | **Pas de PKCE** pour OAuth2 | `auth.py` | Implémenter RFC 7636 (code_verifier + code_challenge S256) |
| 7 | **Aucune rotation de clé** — changer `secret_key` invalide tous les tokens | `crypto.py` | Préfixer les ciphertexts avec une version de clé |
| 8 | **Pas d'audit des 403** | `auth.py` | Logger chaque refus avec user_id + chemin |
| 9 | **secrets.json non chiffré** — données sensibles lisibles si accès FS | `auth_store.py` | Chiffrement à la clé dérivée d'un secret externe (vault) |
| 10 | **Pas de CSP** — XSS pourrait voler le token CSRF | (nginx/proxy) | Configurer `Content-Security-Policy` au niveau reverse-proxy |

### 🟢 Améliorations souhaitables

| # | Amélioration |
|---|-------------|
| 11 | Ajouter `SameSite=Lax` et `Secure` sur le cookie de session (`SESSION_COOKIE_SAMESITE`, `SESSION_COOKIE_SECURE`) |
| 12 | Implémenter un `nonce` dans le flux ADFS pour prévenir le rejeu de token |
| 13 | Scanner les dépendances régulièrement (`pip-audit` en CI/CD) |
| 14 | Ajouter un hook pre-commit `gitleaks` pour détecter les secrets commités |
| 15 | Passer l'audit log dans un fichier append-only (ou syslog) pour l'immuabilité |
| 16 | Documenter la procédure de rotation de `secret_key` (migration des tokens) |

---

## Références

- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [RFC 6749 — OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [Python cryptography — Fernet](https://cryptography.io/en/latest/fernet/)
- [NIST SP 800-132 — PBKDF](https://csrc.nist.gov/publications/detail/sp/800-132/final)

---

*Ce document est à usage interne. Ne pas publier dans un dépôt public.*
