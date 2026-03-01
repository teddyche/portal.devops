# AppOps

Plateforme multi-modules pour les operations applicatives CA-GIP. Dashboard configurable, scoring automatise, orchestration de workflows, le tout avec authentification ADFS et controle d'acces par equipe.

## Stack technique

| Composant | Technologie |
|---|---|
| Backend | Python 3 / Flask |
| Frontend | HTML + CSS + JS vanilla (pas de framework, pas de build) |
| Persistance | Fichiers JSON (pas de BDD) |
| Auth | OIDC / OAuth2 (ADFS) + login local bcrypt |
| Integrations | AWX (Ansible Tower), JFrog Artifactory |

## Structure du projet

```
appops/
├── dashboard.py            # App Flask principale (~800 lignes, ~55 routes)
├── auth.py                 # Blueprint auth : login, session, before_request, RBAC
├── auth_admin.py           # Blueprint admin auth : CRUD orgs/equipes/users
├── migrate.py              # Migration legacy + configs par defaut
│
├── pages/                  # Pages HTML (17 fichiers, tout est self-contained)
│   ├── home.html               # Accueil multi-modules
│   ├── login.html               # Connexion ADFS + local
│   ├── auth_admin.html          # Admin auth (orgs, equipes, users, config)
│   ├── landing.html             # Landing SRE (liste clusters)
│   ├── admin.html               # Admin SRE (CRUD clusters)
│   ├── dashboard.html           # Dashboard tableau (SRE + CAD, multi-contexte)
│   ├── config.html              # Config colonnes du dashboard (SRE + CAD)
│   ├── board.html               # Vue post-it / kanban (SRE + CAD)
│   ├── autoscore.html           # Questionnaire autoscore
│   ├── autoscore_config.html    # Config categories/criteres autoscore
│   ├── cad_landing.html         # Landing CAD
│   ├── cad_admin.html           # Admin CAD (CRUD workspaces)
│   ├── pssit_landing.html       # Landing PSSIT
│   ├── pssit_admin.html         # Admin PSSIT (CRUD apps)
│   ├── pssit_app.html           # Detail app PSSIT (launch, schedule, history)
│   ├── pssit_config.html        # Config environnements PSSIT
│   └── placeholder.html         # Page placeholder
│
├── img/                    # Assets statiques
│   ├── logo-cagip.jpg
│   ├── alert.png
│   ├── coaching.png
│   ├── comment.png
│   └── reminder.png
│
└── datas/                  # Donnees persistantes (JSON)
    ├── auth/                   # Authentification
    │   ├── config.json             # Config ADFS + mot de passe admin local
    │   ├── users.json              # Utilisateurs (locaux + ADFS)
    │   ├── teams.json              # Equipes (membres + ressources)
    │   └── organizations.json      # Organisations
    ├── clusters.json           # Registre des clusters SRE
    ├── cad_workspaces.json     # Registre des workspaces CAD
    ├── pssit_apps.json         # Registre des apps PSSIT
    ├── <CLUSTER_ID>/           # Donnees par cluster
    │   ├── config.json             # Configuration colonnes
    │   ├── data.json               # Lignes du tableau
    │   ├── autoscore_config.json   # Criteres autoscore
    │   └── autoscore/<CODE>.json   # Scores par application
    ├── cad/<WORKSPACE_ID>/     # Donnees par workspace CAD
    │   ├── config.json
    │   └── data.json
    └── pssit/<APP_ID>/         # Donnees par app PSSIT
        ├── config.json             # Environnements (AWX, JFrog, params)
        ├── history.json            # Historique des executions
        └── schedules.json          # Planifications
```

## Les 3 modules

### SRE (Site Reliability Engineering)

Dashboard tableau configurable par cluster. Chaque cluster a :
- **Tableau** : grille editable avec groupes de colonnes, types de champs (text, toggle, autoscore), couleurs par valeur
- **Board** : vue post-it alternative avec groupement et filtrage
- **Autoscore** : questionnaire de maturite SRE (5 categories, 76 criteres, note A-G sur 660 points)
- **Indicateurs visuels** : alertes (clignotant), coaching (spinner), commentaires, rappels — accessibles via clic droit

**Particularite** : `dashboard.html` et `config.html` sont **multi-contexte**. Ils detectent l'URL (`/cluster/<id>` vs `/cad/workspace/<id>`) pour adapter l'API base, les liens de navigation et les fonctionnalites (ex: autoscore uniquement en SRE).

### CAD (Comite d'Architecture et Design)

Meme moteur que SRE mais avec une config par defaut orientee architecture SI :
- Colonnes : Application, Architecture, Technique, Hebergement, Conformite
- Champs : type d'archi, stack, BDD, PRA/PCA, RGPD, obsolescence...

### PSSIT (Pilotage des Services et Suivi des Interventions Techniques)

Module d'orchestration via AWX (Ansible Tower) et JFrog Artifactory :
- Configuration par app : environnements, workflows AWX, repos JFrog
- Actions : start, stop, deploy, patch, status
- Planification de taches avec creation de schedules AWX
- Historique des executions avec suivi de statut en temps reel
- Selection d'artefact depuis JFrog pour les deploiements

## Authentification et droits

### Architecture

```
before_request (auth.py)
    │
    ├── Route publique ? (/login, /auth/*, /img/*) → passe
    │
    ├── Pas de session ? → redirect /login (pages) ou 401 (API)
    │
    └── Session valide → verifie acces a la ressource
         ├── superadmin → tout
         └── user normal → check resources de ses equipes
```

### Hierarchie

```
Organisation (ex: CLP)
  └── Equipe (ex: sre-cagip)
       ├── Membres : [{user_id, role: admin|member}]
       └── Ressources : [{module: sre|cad|pssit, resource_id: CLP}]
```

- **superadmin** : voit tout, acces a `/auth-admin`, gere les orgs/equipes/config ADFS
- **team admin** : peut modifier les membres de son equipe, acces a `/auth-admin`
- **member** : voit uniquement les ressources de ses equipes

### Deux modes de login

1. **ADFS** (OpenID Connect) : bouton "Se connecter avec le compte entreprise", flow Authorization Code, creation auto du user au premier login
2. **Local** : formulaire username/password, mot de passe hashe bcrypt, reserve au super admin

### Barre auth

Toutes les pages HTML incluent un snippet JS qui appelle `GET /api/auth/me` et affiche une barre fixe en haut avec le nom de l'utilisateur, un lien admin (si admin), et la deconnexion.

## API

### Routes principales (78 total)

| Prefixe | Module | Routes | Description |
|---|---|---|---|
| `/api/clusters` | SRE | 4 | CRUD clusters |
| `/api/cluster/<id>/*` | SRE | 8 | Config, data, autoscore, autoscore-config |
| `/api/cad/workspaces` | CAD | 4 | CRUD workspaces |
| `/api/cad/workspace/<id>/*` | CAD | 4 | Config, data |
| `/api/pssit/apps` | PSSIT | 4 | CRUD apps |
| `/api/pssit/app/<id>/*` | PSSIT | 9 | Config, history, schedules, launch, status, artifacts |
| `/api/auth/*` | Auth | 20 | Me, config, orgs, teams, members, resources, users |
| Pages | - | 19 | HTML rendues via `send_file()` |
| Auth pages | - | 6 | Login, logout, ADFS flow, auth-admin |

### Conventions

- **GET** : lecture (retourne JSON array ou object)
- **POST** : creation ou sauvegarde complete (body JSON)
- **PUT** : modification partielle (body JSON avec champs a modifier)
- **DELETE** : suppression
- Reponse succes : `{"success": true}`
- Reponse erreur : `{"error": "message"}` avec code HTTP 400/401/403/404

## Comment ca marche cote code

### Pas de templating

Les pages HTML sont servies telles quelles via `send_file()`. Tout le rendu est fait cote client en JavaScript :
1. La page se charge avec le HTML/CSS/JS embarque
2. Le JS appelle les API Flask via `fetch()`
3. Le DOM est construit dynamiquement avec les donnees

**Avantage** : zero dependance frontend, pas de build, fichiers autonomes.

### Persistance JSON

Pas de base de donnees. Tout est dans des fichiers JSON dans `datas/` :
- `load_json(path)` : lit un fichier JSON, retourne `None` si absent
- `save_json(path, data)` : ecrit avec `ensure_ascii=False` et `indent=2`
- Les repertoires sont crees automatiquement via `os.makedirs(..., exist_ok=True)`

**Consequence** : pas de concurrence d'ecriture. Si deux users sauvegardent en meme temps, le dernier ecrase. Acceptable pour l'usage interne prevu.

### Multi-contexte (dashboard.html / config.html)

Ces deux pages detectent le contexte depuis l'URL au chargement :

```javascript
const path = location.pathname;
if (path.startsWith('/cad/workspace/')) {
    apiBase = '/api/cad/workspace/' + id;
    // ...mode CAD
} else {
    apiBase = '/api/cluster/' + id;
    // ...mode SRE
}
```

Cela evite de dupliquer ~1500 lignes de HTML/JS.

### Context menu (clic droit)

Le dashboard et le board partagent un systeme de clic droit sur les lignes/cartes avec des actions stockees dans `data.json` via des cles prefixees `_row` :
- `_row_comment` : commentaire texte
- `_row_alert` : alerte visuelle (blink rouge)
- `_row_reminder` : rappel (icone horloge)
- `_row_coaching` : coaching (spinner anime)

## Installation et lancement

### Installation offline (VM RHEL8 sans acces internet)

Les dependances Python sont incluses dans le dossier `vendor/` sous forme de wheels pre-compiles pour Linux x86_64. Aucun acces internet necessaire.

```bash
# Transferer le zip du repo sur la VM
unzip portal.devops-main.zip
cd portal.devops-main

# Creer le virtualenv (Python 3.9+ requis, RHEL8 a Python 3.8/3.9 via dnf)
python3 -m venv .venv
source .venv/bin/activate

# Installer les dependances OFFLINE depuis vendor/
pip install --no-index --find-links=vendor/ -r requirements.txt

# Creer le dossier de donnees initial
mkdir -p datas/auth
cp -n datas_example/auth/* datas/auth/ 2>/dev/null || true

# Lancer
python dashboard.py
# → http://localhost:5000
# Login par defaut : admin / admin
```

> **Note RHEL8** : si Python 3.9+ n'est pas installe, l'installer via :
> ```bash
> sudo dnf install python39
> python3.9 -m venv .venv
> ```

### Installation avec internet

```bash
git clone https://github.com/teddyche/portal.devops.git
cd portal.devops

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python dashboard.py
```

### Lancer en arriere-plan (production)

```bash
# Avec nohup
nohup python dashboard.py > appops.log 2>&1 &

# Ou avec systemd (creer /etc/systemd/system/appops.service)
# [Unit]
# Description=AppOps Dashboard
# After=network.target
#
# [Service]
# Type=simple
# User=appops
# WorkingDirectory=/opt/appops
# ExecStart=/opt/appops/.venv/bin/python dashboard.py
# Restart=always
#
# [Install]
# WantedBy=multi-user.target
```

## Configuration ADFS

1. Se connecter en tant qu'admin local
2. Aller dans **Admin Auth** (lien dans la barre du haut)
3. Onglet **Configuration** :
   - Cocher "ADFS active"
   - Renseigner Client ID, Client Secret, Authority URL, Redirect URI
   - Enregistrer
4. L'ecran de login affichera desormais le bouton "Se connecter avec le compte entreprise"

Le Redirect URI a configurer dans ADFS : `https://<domaine>/auth/adfs/callback`

## Premiere utilisation

1. Se connecter en **admin / admin**
2. Aller dans **Admin Auth** → creer une organisation → creer des equipes → assigner des ressources (clusters, workspaces, apps)
3. Aller dans **Administration** (SRE) → creer un cluster
4. Ouvrir le cluster → **Configurer** les colonnes → ajouter des lignes dans le tableau
5. (Optionnel) **Configurer l'autoscore** pour adapter les criteres de notation
