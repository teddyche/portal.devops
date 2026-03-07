"""
DevOps Tools — Génération ZIP Onboarding / Deboarding (GitLab + AAP).
ZIPs génériques : tout est paramétré via Survey AAP + Credentials AAP au runtime.
"""
import io
import zipfile


# ── Public API ─────────────────────────────────────────────────────────────────

def generate_onboarding_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('onboarding/01_gitlab_setup.yml',  _pb_gitlab_on())
        zf.writestr('onboarding/02_aap_setup.yml',     _pb_aap_on())
        zf.writestr('onboarding/vars/config.yml',      _vars_infra('onboarding'))
        zf.writestr('onboarding/README.md',             _readme_on())
    return buf.getvalue()


def generate_deboarding_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('deboarding/01_aap_cleanup.yml',    _pb_aap_off())
        zf.writestr('deboarding/02_gitlab_cleanup.yml', _pb_gitlab_off())
        zf.writestr('deboarding/vars/config.yml',       _vars_infra('deboarding'))
        zf.writestr('deboarding/README.md',              _readme_off())
    return buf.getvalue()


# ── Variables infra (statiques) ────────────────────────────────────────────────

def _vars_infra(mode: str) -> str:
    return """\
# ═══════════════════════════════════════════════════════════════
#  Variables statiques infra — à adapter à votre environnement
# ═══════════════════════════════════════════════════════════════
#
#  ⚠  TOKENS → CREDENTIALS AAP (jamais dans ce fichier)
#  ──────────────────────────────────────────────────────────────
#  Les tokens sont injectés automatiquement par les Credentials AAP.
#  Associer au job template avant exécution :
#
#    • Credential « GitLab Interne »  → injecte {{ gitlab_internal_token }}
""" + ("""\
#    • Credential « GitLab Premium »  → injecte {{ gitlab_premium_token }}
#                                         et {{ gitlab_premium_mirror_url }}
""" if mode == 'onboarding' else '') + """\
#    • Credential « AAP Controller »  → injecte {{ aap_token }}
#
#  📋  SURVEY AAP → Variables dynamiques par application
#  Voir README.md pour la liste complète des variables Survey.
#
# ═══════════════════════════════════════════════════════════════

# ── URLs infra ────────────────────────────────────────────────────────────────
gitlab_internal_url:  "https://gitlab.internal.fr"   # À adapter
aap_controller_host:  "https://aap.internal.fr"      # À adapter
aap_organization:     "Default"                        # À adapter
aap_validate_certs:   true
git_branch:           "main"
"""


# ── Playbook GitLab Onboarding ─────────────────────────────────────────────────

def _pb_gitlab_on() -> str:
    return """\
---
# ═══════════════════════════════════════════════════════════════
#  [1/2] GitLab Setup — Onboarding
#  Crée groupe/sous-groupe/repo interne + pull mirror ← Premium
#  Variables : Survey AAP + Credential « GitLab Interne » + « GitLab Premium »
#  Prérequis : community.general >= 7.0
# ═══════════════════════════════════════════════════════════════

- name: "GitLab Setup — Onboarding"
  hosts: localhost
  gather_facts: false
  vars_files:
    - vars/config.yml

  tasks:

    # ── Calcul du full path ───────────────────────────────────────────────────
    - name: "Set gitlab_full_path (avec sous-groupe)"
      ansible.builtin.set_fact:
        gitlab_full_path: "{{ gitlab_group }}/{{ gitlab_subgroup | trim }}"
      when: gitlab_subgroup | default('') | trim | length > 0

    - name: "Set gitlab_full_path (sans sous-groupe)"
      ansible.builtin.set_fact:
        gitlab_full_path: "{{ gitlab_group }}"
      when: gitlab_subgroup | default('') | trim | length == 0

    # ── 1. Groupe principal ───────────────────────────────────────────────────
    - name: "Créer le groupe '{{ gitlab_group }}'"
      community.general.gitlab_group:
        name:       "{{ gitlab_group }}"
        path:       "{{ gitlab_group | lower | replace(' ', '-') }}"
        visibility: private
        state:      present
        api_url:    "{{ gitlab_internal_url }}"
        api_token:  "{{ gitlab_internal_token }}"

    # ── 2. Sous-groupe (optionnel) ────────────────────────────────────────────
    - name: "Créer le sous-groupe '{{ gitlab_subgroup }}'"
      community.general.gitlab_group:
        name:        "{{ gitlab_subgroup }}"
        path:        "{{ gitlab_subgroup | lower | replace(' ', '-') }}"
        parent_path: "{{ gitlab_group | lower | replace(' ', '-') }}"
        visibility:  private
        state:       present
        api_url:     "{{ gitlab_internal_url }}"
        api_token:   "{{ gitlab_internal_token }}"
      when: gitlab_subgroup | default('') | trim | length > 0

    # ── 3. Repo interne ───────────────────────────────────────────────────────
    - name: "Créer le repo '{{ code_app }}_deploy'"
      community.general.gitlab_project:
        name:                   "{{ code_app }}_deploy"
        description:            "{{ nom_app }} — Déploiement Ansible (CLP Builder)"
        group:                  "{{ gitlab_full_path }}"
        visibility:             private
        initialize_with_readme: false
        state:                  present
        api_url:                "{{ gitlab_internal_url }}"
        api_token:              "{{ gitlab_internal_token }}"

    # ── 4. Pull mirror Interne ← Premium ─────────────────────────────────────
    #  gitlab_premium_mirror_url est injecté par le Credential « GitLab Premium »
    #  Format : https://oauth2:TOKEN@gitlab-premium.example.com/team/repo.git
    - name: "Configurer le pull mirror depuis GitLab Premium"
      ansible.builtin.uri:
        url:    "{{ gitlab_internal_url }}/api/v4/projects/{{ (gitlab_full_path + '/' + code_app + '_deploy') | urlencode }}/remote_mirrors"
        method: POST
        headers:
          PRIVATE-TOKEN: "{{ gitlab_internal_token }}"
        body_format: json
        body:
          url:                     "{{ gitlab_premium_mirror_url }}"
          enabled:                 true
          only_protected_branches: false
          keep_divergent_refs:     false
        status_code: [200, 201]

    - name: "Résultat"
      ansible.builtin.debug:
        msg: "Repo interne : {{ gitlab_internal_url }}/{{ gitlab_full_path }}/{{ code_app }}_deploy"
"""


# ── Playbook AAP Onboarding ────────────────────────────────────────────────────

def _pb_aap_on() -> str:
    return """\
---
# ═══════════════════════════════════════════════════════════════
#  [2/2] AAP Setup — Onboarding
#  Crée credential, project, inventaires, job templates, workflows
#  Variables : Survey AAP + Credential « GitLab Interne » + « AAP Controller »
#  Prérequis : ansible-galaxy collection install awx.awx
# ═══════════════════════════════════════════════════════════════

- name: "AAP Setup — Onboarding"
  hosts: localhost
  gather_facts: false
  vars_files:
    - vars/config.yml

  tasks:

    # ── Préparation ───────────────────────────────────────────────────────────
    - name: "Construire les listes dynamiques"
      ansible.builtin.set_fact:
        env_list: "{{ (environments | default('prod')).split(',') | map('trim') | select | list }}"
        mw_list:  "{{ (middlewares  | default('')).split(',') | map('trim') | select | list }}"
        _mode:    "{{ deploy_mode | default('job') }}"

    - name: "Set gitlab_full_path (avec sous-groupe)"
      ansible.builtin.set_fact:
        gitlab_full_path: "{{ gitlab_group }}/{{ gitlab_subgroup | trim }}"
      when: gitlab_subgroup | default('') | trim | length > 0

    - name: "Set gitlab_full_path (sans sous-groupe)"
      ansible.builtin.set_fact:
        gitlab_full_path: "{{ gitlab_group }}"
      when: gitlab_subgroup | default('') | trim | length == 0

    # ── 1. Credential Source Control ─────────────────────────────────────────
    - name: "Créer le credential '{{ code_app }}_gitlab_cred'"
      awx.awx.credential:
        name:             "{{ code_app }}_gitlab_cred"
        organization:     "{{ aap_organization }}"
        credential_type:  "Source Control"
        inputs:
          username: "oauth2"
          password: "{{ gitlab_internal_token }}"
        state:                 present
        controller_host:       "{{ aap_controller_host }}"
        controller_oauthtoken: "{{ aap_token }}"
        validate_certs:        "{{ aap_validate_certs }}"

    # ── 2. Projet AAP ─────────────────────────────────────────────────────────
    - name: "Créer le projet '{{ code_app }}_deploy'"
      awx.awx.project:
        name:                 "{{ code_app }}_deploy"
        organization:         "{{ aap_organization }}"
        scm_type:             git
        scm_url:              "{{ gitlab_internal_url }}/{{ gitlab_full_path }}/{{ code_app }}_deploy.git"
        scm_branch:           "{{ git_branch }}"
        scm_update_on_launch: true
        credential:           "{{ code_app }}_gitlab_cred"
        state:                present
        controller_host:       "{{ aap_controller_host }}"
        controller_oauthtoken: "{{ aap_token }}"
        validate_certs:        "{{ aap_validate_certs }}"

    - name: "Synchroniser le projet"
      awx.awx.project_update:
        name:                  "{{ code_app }}_deploy"
        wait:                  true
        controller_host:       "{{ aap_controller_host }}"
        controller_oauthtoken: "{{ aap_token }}"
        validate_certs:        "{{ aap_validate_certs }}"

    # ── 3. Inventaires ────────────────────────────────────────────────────────
    - name: "Créer l'inventaire '{{ code_app }}_inv_{{ item }}'"
      awx.awx.inventory:
        name:          "{{ code_app }}_inv_{{ item }}"
        organization:  "{{ aap_organization }}"
        state:         present
        controller_host:       "{{ aap_controller_host }}"
        controller_oauthtoken: "{{ aap_token }}"
        validate_certs:        "{{ aap_validate_certs }}"
      loop: "{{ env_list }}"

    # ── 4a. Job Templates — mode job (4 actions × N envs) ────────────────────
    - name: "Créer JT '{{ code_app }}_{{ item.1 }}_{{ item.0 }}' (job)"
      awx.awx.job_template:
        name:                    "{{ code_app }}_{{ item.1 }}_{{ item.0 }}"
        project:                 "{{ code_app }}_deploy"
        playbook:                "playbooks/{{ item.1 }}.yml"
        inventory:               "{{ code_app }}_inv_{{ item.0 }}"
        organization:            "{{ aap_organization }}"
        ask_variables_on_launch: true
        state:                   present
        controller_host:         "{{ aap_controller_host }}"
        controller_oauthtoken:   "{{ aap_token }}"
        validate_certs:          "{{ aap_validate_certs }}"
      loop: "{{ env_list | product(['deploy', 'stop_middleware', 'start_middleware', 'status_middleware']) | list }}"
      loop_control:
        label: "{{ item.1 }}_{{ item.0 }}"
      when: _mode == 'job'

    # ── 4b. Job Templates — mode workflow ─────────────────────────────────────
    - name: "Créer JT deploy '{{ code_app }}_deploy_{{ item }}' (workflow)"
      awx.awx.job_template:
        name:                    "{{ code_app }}_deploy_{{ item }}"
        project:                 "{{ code_app }}_deploy"
        playbook:                "playbooks/deploy.yml"
        inventory:               "{{ code_app }}_inv_{{ item }}"
        organization:            "{{ aap_organization }}"
        ask_variables_on_launch: true
        state:                   present
        controller_host:         "{{ aap_controller_host }}"
        controller_oauthtoken:   "{{ aap_token }}"
        validate_certs:          "{{ aap_validate_certs }}"
      loop: "{{ env_list }}"
      when: _mode == 'workflow'

    - name: "Créer JTs MW '{{ code_app }}_{{ item.2 }}_{{ item.1 }}_{{ item.0 }}' (workflow)"
      awx.awx.job_template:
        name:                    "{{ code_app }}_{{ item.2 }}_{{ item.1 }}_{{ item.0 }}"
        project:                 "{{ code_app }}_deploy"
        playbook:                "playbooks/{{ item.2 }}_{{ item.1 }}.yml"
        inventory:               "{{ code_app }}_inv_{{ item.0 }}"
        organization:            "{{ aap_organization }}"
        ask_variables_on_launch: true
        state:                   present
        controller_host:         "{{ aap_controller_host }}"
        controller_oauthtoken:   "{{ aap_token }}"
        validate_certs:          "{{ aap_validate_certs }}"
      loop: "{{ env_list | product(mw_list) | product(['stop', 'start', 'status']) | map('flatten') | list }}"
      loop_control:
        label: "{{ item.2 }}_{{ item.1 }}_{{ item.0 }}"
      when: _mode == 'workflow' and mw_list | length > 0

    # ── 5. Workflow Templates ─────────────────────────────────────────────────
    - name: "Créer Workflow Template '{{ code_app }}_lifecycle_{{ item }}'"
      awx.awx.workflow_job_template:
        name:                    "{{ code_app }}_lifecycle_{{ item }}"
        organization:            "{{ aap_organization }}"
        ask_variables_on_launch: true
        state:                   present
        controller_host:         "{{ aap_controller_host }}"
        controller_oauthtoken:   "{{ aap_token }}"
        validate_certs:          "{{ aap_validate_certs }}"
      loop: "{{ env_list }}"
      when: _mode == 'workflow'
"""


# ── Playbook AAP Deboarding ────────────────────────────────────────────────────

def _pb_aap_off() -> str:
    return """\
---
# ═══════════════════════════════════════════════════════════════
#  [1/2] AAP Cleanup — Deboarding
#  ⚠  Supprime définitivement les objets AAP
#  Variables : Survey AAP + Credential « AAP Controller »
# ═══════════════════════════════════════════════════════════════

- name: "AAP Cleanup — Deboarding"
  hosts: localhost
  gather_facts: false
  vars_files:
    - vars/config.yml

  tasks:

    - name: "Construire les listes dynamiques"
      ansible.builtin.set_fact:
        env_list: "{{ (environments | default('prod')).split(',') | map('trim') | select | list }}"
        mw_list:  "{{ (middlewares  | default('')).split(',') | map('trim') | select | list }}"
        _mode:    "{{ deploy_mode | default('job') }}"

    # Ordre inverse : WF → JT → Inventaires → Project → Credential

    - name: "Supprimer Workflow Templates"
      awx.awx.workflow_job_template:
        name:          "{{ code_app }}_lifecycle_{{ item }}"
        organization:  "{{ aap_organization }}"
        state:         absent
        controller_host:       "{{ aap_controller_host }}"
        controller_oauthtoken: "{{ aap_token }}"
        validate_certs:        "{{ aap_validate_certs }}"
      loop: "{{ env_list }}"
      when: _mode == 'workflow'

    - name: "Supprimer JTs (mode job)"
      awx.awx.job_template:
        name:          "{{ code_app }}_{{ item.1 }}_{{ item.0 }}"
        organization:  "{{ aap_organization }}"
        state:         absent
        controller_host:       "{{ aap_controller_host }}"
        controller_oauthtoken: "{{ aap_token }}"
        validate_certs:        "{{ aap_validate_certs }}"
      loop: "{{ env_list | product(['deploy', 'stop_middleware', 'start_middleware', 'status_middleware']) | list }}"
      loop_control:
        label: "{{ item.1 }}_{{ item.0 }}"
      when: _mode == 'job'

    - name: "Supprimer JT deploy (mode workflow)"
      awx.awx.job_template:
        name:          "{{ code_app }}_deploy_{{ item }}"
        organization:  "{{ aap_organization }}"
        state:         absent
        controller_host:       "{{ aap_controller_host }}"
        controller_oauthtoken: "{{ aap_token }}"
        validate_certs:        "{{ aap_validate_certs }}"
      loop: "{{ env_list }}"
      when: _mode == 'workflow'

    - name: "Supprimer JTs MW (mode workflow)"
      awx.awx.job_template:
        name:          "{{ code_app }}_{{ item.2 }}_{{ item.1 }}_{{ item.0 }}"
        organization:  "{{ aap_organization }}"
        state:         absent
        controller_host:       "{{ aap_controller_host }}"
        controller_oauthtoken: "{{ aap_token }}"
        validate_certs:        "{{ aap_validate_certs }}"
      loop: "{{ env_list | product(mw_list) | product(['stop', 'start', 'status']) | map('flatten') | list }}"
      loop_control:
        label: "{{ item.2 }}_{{ item.1 }}_{{ item.0 }}"
      when: _mode == 'workflow' and mw_list | length > 0

    - name: "Supprimer les inventaires"
      awx.awx.inventory:
        name:          "{{ code_app }}_inv_{{ item }}"
        organization:  "{{ aap_organization }}"
        state:         absent
        controller_host:       "{{ aap_controller_host }}"
        controller_oauthtoken: "{{ aap_token }}"
        validate_certs:        "{{ aap_validate_certs }}"
      loop: "{{ env_list }}"

    - name: "Supprimer le projet '{{ code_app }}_deploy'"
      awx.awx.project:
        name:          "{{ code_app }}_deploy"
        organization:  "{{ aap_organization }}"
        state:         absent
        controller_host:       "{{ aap_controller_host }}"
        controller_oauthtoken: "{{ aap_token }}"
        validate_certs:        "{{ aap_validate_certs }}"

    - name: "Supprimer le credential '{{ code_app }}_gitlab_cred'"
      awx.awx.credential:
        name:          "{{ code_app }}_gitlab_cred"
        organization:  "{{ aap_organization }}"
        state:         absent
        controller_host:       "{{ aap_controller_host }}"
        controller_oauthtoken: "{{ aap_token }}"
        validate_certs:        "{{ aap_validate_certs }}"
"""


# ── Playbook GitLab Deboarding ─────────────────────────────────────────────────

def _pb_gitlab_off() -> str:
    return """\
---
# ═══════════════════════════════════════════════════════════════
#  [2/2] GitLab Cleanup — Deboarding
#  Archive le repo interne (suppression manuelle si nécessaire)
#  Variables : Survey AAP + Credential « GitLab Interne »
# ═══════════════════════════════════════════════════════════════

- name: "GitLab Cleanup — Deboarding"
  hosts: localhost
  gather_facts: false
  vars_files:
    - vars/config.yml

  tasks:

    - name: "Set gitlab_full_path (avec sous-groupe)"
      ansible.builtin.set_fact:
        gitlab_full_path: "{{ gitlab_group }}/{{ gitlab_subgroup | trim }}"
      when: gitlab_subgroup | default('') | trim | length > 0

    - name: "Set gitlab_full_path (sans sous-groupe)"
      ansible.builtin.set_fact:
        gitlab_full_path: "{{ gitlab_group }}"
      when: gitlab_subgroup | default('') | trim | length == 0

    - name: "Archiver le repo '{{ code_app }}_deploy'"
      ansible.builtin.uri:
        url:    "{{ gitlab_internal_url }}/api/v4/projects/{{ (gitlab_full_path + '/' + code_app + '_deploy') | urlencode }}/archive"
        method: POST
        headers:
          PRIVATE-TOKEN: "{{ gitlab_internal_token }}"
        status_code: [200, 201]

    - name: "Résultat"
      ansible.builtin.debug:
        msg: "Repo archivé — suppression manuelle si nécessaire : {{ gitlab_internal_url }}/{{ gitlab_full_path }}/{{ code_app }}_deploy"
"""


# ── README ─────────────────────────────────────────────────────────────────────

def _readme_on() -> str:
    return """\
# Onboarding AAP — README

Projet Ansible générique pour bootstrapper une application CLP Builder
sur l'infrastructure AppOps (GitLab Interne + AAP).

**Déployer ce projet une fois → créer les Job Templates → chaque onboarding
se lance via Survey AAP, aucun fichier à modifier.**

## Contenu

```
onboarding/
├── 01_gitlab_setup.yml    Crée groupe/repo GitLab interne + pull mirror ← Premium
├── 02_aap_setup.yml       Crée credential, project, inventaires, JTs, WFs AAP
├── vars/config.yml        Variables statiques infra (URLs uniquement)
└── README.md              Ce fichier
```

## 1. Adapter vars/config.yml

Mettre à jour les URLs de votre infrastructure :

| Variable | Description |
|---|---|
| `gitlab_internal_url` | URL de votre GitLab interne |
| `aap_controller_host` | URL de votre AAP Controller |
| `aap_organization` | Organisation AAP cible |

## 2. Credentials AAP à associer aux job templates

| Credential | Variables injectées | Droits requis |
|---|---|---|
| GitLab Interne | `gitlab_internal_token` | API read+write |
| GitLab Premium | `gitlab_premium_token`, `gitlab_premium_mirror_url` | read+write (mirror) |
| AAP Controller | `aap_token` | Admin |

> ⚠ Les tokens ne doivent **jamais** apparaître dans les fichiers du projet.

`gitlab_premium_mirror_url` doit être au format :
`https://oauth2:TOKEN@gitlab-premium.example.com/team/repo.git`

## 3. Survey AAP à créer sur les job templates

### 01_gitlab_setup.yml

| Variable | Label | Type | Req | Exemple |
|---|---|---|---|---|
| `code_app` | Code application | text | ✓ | `myap` |
| `nom_app` | Nom application | text | ✓ | `My Application` |
| `premium_url` | URL repo GitLab Premium (.git) | text | ✓ | `https://...` |
| `gitlab_group` | Groupe GitLab interne | text | ✓ | `mon-equipe` |
| `gitlab_subgroup` | Sous-groupe (optionnel) | text | | `applis-clp` |

### 02_aap_setup.yml

| Variable | Label | Type | Req | Exemple |
|---|---|---|---|---|
| `code_app` | Code application | text | ✓ | `myap` |
| `nom_app` | Nom application | text | ✓ | `My Application` |
| `gitlab_group` | Groupe GitLab interne | text | ✓ | `mon-equipe` |
| `gitlab_subgroup` | Sous-groupe (optionnel) | text | | |
| `environments` | Environnements (virgule) | text | ✓ | `low,mid,prod` |
| `middlewares` | Middlewares (virgule) | text | | `apache,tomcat` |
| `deploy_mode` | Mode déploiement | multiple choice | ✓ | `job` / `workflow` |
"""


def _readme_off() -> str:
    return """\
# Deboarding AAP — README

Projet Ansible générique pour retirer proprement une application décommissionnée
de l'infrastructure AppOps (AAP + GitLab Interne).

> ⚠ **Actions irréversibles** — Supprime définitivement les objets AAP
> et archive le repo GitLab interne.

## Contenu

```
deboarding/
├── 01_aap_cleanup.yml     Supprime WF → JT → Inventaires → Project → Credential
├── 02_gitlab_cleanup.yml  Archive le repo GitLab interne
├── vars/config.yml        Variables statiques infra (URLs uniquement)
└── README.md              Ce fichier
```

## 1. Adapter vars/config.yml

| Variable | Description |
|---|---|
| `gitlab_internal_url` | URL de votre GitLab interne |
| `aap_controller_host` | URL de votre AAP Controller |
| `aap_organization` | Organisation AAP cible |

## 2. Credentials AAP à associer aux job templates

| Credential | Variables injectées |
|---|---|
| GitLab Interne | `gitlab_internal_token` |
| AAP Controller | `aap_token` |

## 3. Survey AAP à créer sur les job templates

| Variable | Label | Type | Req | Exemple |
|---|---|---|---|---|
| `code_app` | Code application | text | ✓ | `myap` |
| `gitlab_group` | Groupe GitLab interne | text | ✓ | `mon-equipe` |
| `gitlab_subgroup` | Sous-groupe (optionnel) | text | | |
| `environments` | Environnements (virgule) | text | ✓ | `low,mid,prod` |
| `middlewares` | Middlewares (virgule) | text | | `apache,tomcat` |
| `deploy_mode` | Mode déploiement | multiple choice | ✓ | `job` / `workflow` |
"""
