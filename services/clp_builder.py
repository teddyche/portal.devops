"""
Service CLP Ansible Builder — génération de packages Ansible en mémoire.
"""
import io
import zipfile

# ── Constantes ──────────────────────────────────────────────────────────────

ENV_LETTERS = {
    'dev': 'd', 'rec': 'r', 'qua': 'q', 'int': 'i',
    'hom': 'h', 'pre': 'o', 'prd': 'p',
    'int2': 'i', 'int3': 'i',
}

ENV_ARTIFACTORY = {
    'dev':  ('community', 'scratch'),
    'rec':  ('community', 'scratch'),
    'qua':  ('community', 'scratch'),
    'int':  ('community', 'scratch'),
    'int2': ('community', 'scratch'),
    'int3': ('community', 'scratch'),
    'hom':  ('3PG_HP',    'stable'),
    'pre':  ('3PG_HP',    'stable'),
    'prd':  ('3PG',       'stable'),
}

# ── SSH args par type d'OS ───────────────────────────────────────────────────

# AIX : paramiko obligatoire, GSSAPIAuthentication, tmp custom, world-readable temp
# (ansible_command_warnings est déprécié en Ansible >= 2.12, mais inoffensif)
_SSH_ARGS_AIX = (
    'ansible_ssh_args="-o GSSAPIAuthentication=yes '
    '-o UserKnownHostsFile=/home/ldap/ansible_tmp/known_hosts" '
    'ansible_shell_allow_world_readable_temp=true '   # AIX : /tmp est world-readable
    'ansible_host_key_checking=false '
    'ansible_retry_files_enabled=false '
    'ansible_deprecation_warnings=false '
    'ansible_display_skipped_hosts=false '
    'ansible_transport=paramiko '                     # AIX ne supporte pas OpenSSH natif
    'ansible_scp_if_ssh=true '                        # SCP via paramiko
    'ansible_pipelining=true '
    'ansible_become_ask_pass=false '
    'ansible_local_tmp=/home/ldap/ansible_tmp '
    'ansible_remote_tmp=/home/ldap/ansible_tmp'
)

# Linux : SSH natif OpenSSH, variables minimales
_SSH_ARGS_LINUX = (
    'ansible_host_key_checking=false '
    'ansible_become_ask_pass=false'
)

# Windows : connexion WinRM (NTLM ou Kerberos selon env)
_SSH_ARGS_WINDOWS = (
    'ansible_connection=winrm '
    'ansible_winrm_transport=ntlm '
    'ansible_port=5985 '
    'ansible_winrm_server_cert_validation=ignore'
)

_OS_SSH_ARGS = {
    'linux':   _SSH_ARGS_LINUX,
    'aix':     _SSH_ARGS_AIX,
    'windows': _SSH_ARGS_WINDOWS,
}

_OS_PREFIX = {'linux': 'VM', 'aix': 'AIX', 'windows': 'WIN'}
_OS_PARENT = {'linux': 'VM_LINUX', 'aix': 'VM_AIX', 'windows': 'WIN_WINDOWS'}
_OS_ORDER  = ['linux', 'aix', 'windows']

# Mapping rôle (groupe hôte) → nom de middleware
# Permet de construire les groupes cross-OS {ca}_{mw} dans le fichier hosts
_ROLE_TO_MW = {
    'APACHE':    'apache',
    'TOMCAT':    'tomcat',
    'MQ':        'mq',
    'WEBSPHERE': 'websphere',
    'PHP':       'php',
    'JBOSS':     'jboss',
    'CFT':       'cft',
}


def _j(var: str) -> str:
    """Retourne une expression Jinja2 {{ var }}."""
    return '{{ ' + var + ' }}'


# ── group_vars ────────────────────────────────────────────────────────────────

def _root_group_vars(code_app: str, nom_app: str, entite: str) -> str:
    ca = code_app.lower()
    return '\n'.join([
        '# Variables communes à tous les environnements',
        f'entite: "{entite}"',
        f'code_app: "{ca}"',
        f'nom_app: "{nom_app}"',
        '',
        'user:',
        '  app: "dsadm117"',
        '',
        f'working_dir: "/app/{_j("code_app")}/{_j("nom_app")}"',
        f'livrable_path: "/app/{_j("code_app")}/{_j("nom_app")}/livrable"',
        '',
        'assembly:',
        f'  groupId: "{_j("prj_name")}"',
        f'  artifactId: "{_j("app_name")}"',
        f'  version: "{_j("tag_version")}.zip"',
        '',
    ])


def _env_group_vars(env: str) -> str:
    letter = ENV_LETTERS.get(env, env[0])
    area, maturity = ENV_ARTIFACTORY.get(env, ('community', 'scratch'))
    return '\n'.join([
        f"# Variables pour l'environnement {env}",
        '---',
        f'env: "{env}"',
        f'env_letter: "{letter}"',
        '',
        'artifactory:',
        f'  area: {area}',
        f'  maturity: {maturity}',
        f'  login: "{_j("arti_id")}"',
        f'  password: "{_j("arti_password")}"',
        '',
    ])


# ── Inventaire hosts ──────────────────────────────────────────────────────────

def _hosts_content(code_app: str, hosts: list, fqdn: str, middlewares: list | None = None) -> str:
    """
    Génère le fichier hosts Ansible avec une hiérarchie OS-based :

      {ca}_platform
        ├── VM_LINUX          (tous les hôtes Linux)
        │     ├── VM_APP      (Linux + rôle APP)
        │     └── VM_APACHE   (Linux + rôle APACHE, si MW sélectionné)
        └── VM_AIX            (tous les hôtes AIX)
              ├── AIX_APP
              └── AIX_DB

    Nommage des groupes : {OS_PREFIX}_{ROLE_UPPER}
      - Linux   → VM_APP, VM_DB, VM_APACHE ...
      - AIX     → AIX_APP, AIX_DB ...
      - Windows → WIN_APP, WIN_DB ...
    """
    ca = code_app.lower()

    # (os_type, role) → [hostname]
    groups: dict[tuple, list[str]] = {}
    for h in hosts:
        os_type = h.get('os', 'linux').lower()
        role    = h.get('group', 'APP').strip().upper().replace(' ', '_')
        hn      = h.get('hostname', '').strip()
        if hn:
            groups.setdefault((os_type, role), []).append(hn)

    if not groups:
        eg = fqdn or 'fqdn.exemple'
        return '\n'.join([
            f'[{ca}_platform:vars]',
            'callbacks_enabled=timer,profile_tasks,profile_roles',
            '',
            f'[{ca}_platform:children]',
            'VM_LINUX',
            'VM_AIX',
            '',
            '[VM_LINUX:children]',
            '# TODO: ex: VM_APP, VM_DB, VM_APACHE',
            '',
            '[VM_AIX:children]',
            '# TODO: ex: AIX_APP, AIX_DB',
            '',
            '# [VM_APP]',
            f'# server01.{eg} {_SSH_ARGS_LINUX}',
            '',
            '# [AIX_APP]',
            f'# aix01.{eg} {_SSH_ARGS_AIX}',
            '',
        ])

    # OS présents, dans un ordre logique
    os_present = [o for o in _OS_ORDER if o in {k[0] for k in groups}]

    # os_type → [group_names] (triés)
    os_to_groups: dict[str, list[str]] = {}
    for (os_type, role) in groups:
        g = f'{_OS_PREFIX.get(os_type, "VM")}_{role}'
        os_to_groups.setdefault(os_type, []).append(g)
    for k in os_to_groups:
        os_to_groups[k] = sorted(set(os_to_groups[k]))

    # MW présents : mw_name → [group_names cross-OS]
    # ex: 'apache' → ['AIX_APACHE', 'VM_APACHE']
    mw_to_groups: dict[str, list[str]] = {}
    for (os_type, role) in groups:
        mw = _ROLE_TO_MW.get(role)
        if mw and mw in (middlewares or []):
            g = f'{_OS_PREFIX.get(os_type, "VM")}_{role}'
            mw_to_groups.setdefault(mw, []).append(g)
    for k in mw_to_groups:
        mw_to_groups[k] = sorted(set(mw_to_groups[k]))

    lines = [
        '# Inventaire généré par CLP Ansible Builder',
        '',
        f'[{ca}_platform:vars]',
        'callbacks_enabled=timer,profile_tasks,profile_roles',
        '',
        f'# ── {ca}_platform — hiérarchie complète ────────────────────────────────',
        f'[{ca}_platform:children]',
    ]

    # Enfants OS
    if os_present:
        lines.append('# Groupes OS → ciblage patch management')
    for os_type in os_present:
        lines.append(_OS_PARENT[os_type])

    # Enfants MW cross-OS
    if mw_to_groups:
        lines.append('# Groupes Middleware → ciblage applicatif')
    for mw in mw_to_groups:
        lines.append(f'{ca}_{mw}')

    lines.append('')

    # Groupes OS → sous-groupes par rôle
    for os_type in os_present:
        parent   = _OS_PARENT[os_type]
        children = os_to_groups.get(os_type, [])
        lines.append(f'# ── {parent} ─────────────────────────────────────────────────────────')
        lines.append(f'[{parent}:children]')
        lines += children
        lines.append('')

    # Groupes Middleware cross-OS (contiennent VM_APACHE, AIX_APACHE, etc.)
    for mw, children in mw_to_groups.items():
        lines.append(f'# ── {ca}_{mw} — tous les serveurs {mw.upper()} (Linux + AIX + ...) ──')
        lines.append(f'[{ca}_{mw}:children]')
        lines += children
        lines.append('')

    # Groupes individuels avec hôtes + SSH args
    lines.append('# ── Serveurs ─────────────────────────────────────────────────────────────')
    lines.append('')
    for (os_type, role), hostnames in groups.items():
        group_name = f'{_OS_PREFIX.get(os_type, "VM")}_{role}'
        ssh_args   = _OS_SSH_ARGS.get(os_type, _SSH_ARGS_LINUX)
        lines.append(f'[{group_name}]')
        for hn in hostnames:
            host = f'{hn}.{fqdn}' if fqdn and '.' not in hn else hn
            lines.append(f'{host} {ssh_args}')
        lines.append('')

    return '\n'.join(lines)


# ── Rôle : get-from-artifactory ───────────────────────────────────────────────

def _get_from_artifactory_defaults(repo_type: str = 'generic') -> str:
    return f"""\
# =============================================================================
# Rôle : get-from-artifactory — Variables par défaut
#
# Ces valeurs sont des DÉFAUTS et peuvent être surchargées depuis :
#   - les group_vars/all.yml de chaque environnement
#   - les vars du playbook appelant
# =============================================================================

# ── Répertoire de travail temporaire ─────────────────────────────────────────
# Chemin local sur le nœud Ansible où l'artefact sera téléchargé avant copie.
tmp_dir: "{{{{ hostvars[inventory_hostname]['ansible_remote_tmp'] | default('/tmp') }}}}"

# ── Type de dépôt Artifactory ─────────────────────────────────────────────────
#   generic → chemin libre  : GroupId/ArtifactId/fichier.ext
#             (le GroupId est utilisé TEL QUEL, pas de conversion points → slashes)
#   maven   → arborescence Maven : com/example/app/1.0/app-1.0.jar
#             (les points du GroupId sont convertis en slashes)
artifactory_repo_type: {repo_type}

# ── Zone d'exposition ─────────────────────────────────────────────────────────
#   intranet → réseau privé d'entreprise (cas standard)
#   internet → accès public (rare, nécessite autorisation)
zone: intranet

# ── Maturité du dépôt ─────────────────────────────────────────────────────────
#   scratch  → Dev, Intégration, Recette usine (binaires bruts non validés)
#   staging  → Qualification, Recette (en cours de validation)
#   stable   → Homologation, Pré-PROD, PROD (binaires validés et promus)
maturity: stable

# ── Zone d'infrastructure Artifactory ────────────────────────────────────────
#   community → Environnements Cloud / usine logicielle
#   3PG_HP    → Pré-production et Homologation (pre-registry-pda)
#   3PG       → Production (registry-pda)
artifactory_area: community

# ── Nom du dépôt construit automatiquement ───────────────────────────────────
# Format : {{entite}}-{{code_app}}-{{type}}-{{maturity}}-{{zone}}
# Exemple : caps-ya-generic-scratch-intranet
artifactory_repo_name: "{{{{ entite }}}}-{{{{ code_app }}}}-{{{{ artifactory_repo_type }}}}-{{{{ maturity }}}}-{{{{ zone }}}}"

# ── Titre affiché dans les logs Ansible ──────────────────────────────────────
artifact_title: "[{{{{ artifactory_repo_name }}}}] {{{{ maven.groupId }}}}:{{{{ maven.artifactId }}}}:{{{{ maven.version }}}}"

# ── URLs Artifactory par zone d'infrastructure ────────────────────────────────
artifactory_url_target:
  community: "https://registry.saas.cagip.group.gca:443/artifactory"
  3PG_HP:    "https://pre-registry-pda.ca-cedicam.fr:443/artifactory"
  3PG:       "https://registry-pda.sec-prod1.lan:443/artifactory"

# URL résolue automatiquement selon la zone choisie
artifactory_url: "{{{{ artifactory_url_target[artifactory_area] }}}}"

# ── Validation des certificats SSL ────────────────────────────────────────────
# Mettre à false uniquement si l'environnement utilise des certificats auto-signés.
# Ne JAMAIS désactiver en production.
validate_certs: true
"""


def _get_from_artifactory_tasks(repo_type: str = 'generic') -> str:
    # Jinja2 ternaire pour le chemin selon le type de repo
    group_path = (
        "{{ (artifactory_repo_type == 'maven') "
        "| ternary(maven.groupId | replace('.', '/'), maven.groupId) }}"
    )
    return f"""\
---
# =============================================================================
# Rôle : get-from-artifactory
#
# Télécharge un artefact depuis Artifactory et le dépose localement.
# Vérifie l'intégrité via checksum SHA256 avant de considérer le téléchargement
# comme réussi.
#
# Variables requises (à passer depuis le playbook appelant) :
#   login            : identifiant de service Artifactory
#   password         : mot de passe / token Artifactory
#   artifactory_area : zone infra  (community | 3PG_HP | 3PG)
#   maturity         : maturité    (scratch | staging | stable)
#   maven            : dict avec :
#     groupId        : groupe de l'artefact
#                      → generic : chemin tel quel      ex: DCA
#                      → maven   : notation pointée     ex: com.example.app
#     artifactId     : nom de l'artefact                ex: mon-app
#     version        : version + extension              ex: 1.2.3.zip
#
# Variable de sortie :
#   artifact_dest    : chemin absolu du fichier téléchargé localement
# =============================================================================

# ── Calcul du chemin dans le dépôt ───────────────────────────────────────────
# Pour les dépôts Maven  : les points du groupId sont convertis en slashes
#                          ex: com.example.app → com/example/app
# Pour les dépôts Generic: le groupId est utilisé tel quel
#                          ex: DCA → DCA
- name: "{{{{ artifact_title }}}} — Calcul du chemin de l'artefact"
  ansible.builtin.set_fact:
    _artifact_group_path: "{group_path}"

# ── Récupération des métadonnées de version ───────────────────────────────────
# L'API de stockage Artifactory retourne les informations sur le fichier
# (chemin réel, checksums, dates...) avant le téléchargement effectif.
- name: "{{{{ artifact_title }}}} — Récupération des métadonnées"
  ansible.builtin.uri:
    url:              "{{{{ artifactory_url }}}}/api/storage/{{{{ artifactory_repo_name }}}}/{{{{ _artifact_group_path }}}}/{{{{ maven.artifactId }}}}/{{{{ maven.version }}}}"
    return_content:   true
    force_basic_auth: true
    url_username:     "{{{{ login }}}}"
    url_password:     "{{{{ password }}}}"
    validate_certs:   "{{{{ validate_certs }}}}"
  register: artifact_info

# ── Extraction du nom de fichier réel ─────────────────────────────────────────
# Le chemin retourné par l'API peut différer de la version demandée
# (ex: snapshot avec timestamp). On extrait le basename pour la suite.
- name: "{{{{ artifact_title }}}} — Extraction du nom de fichier"
  ansible.builtin.set_fact:
    _artifact_filename: "{{{{ artifact_info.json.path | basename }}}}"

# ── Récupération du checksum SHA256 ───────────────────────────────────────────
# Le checksum sera utilisé pour vérifier l'intégrité après téléchargement.
# Ansible rejette automatiquement le fichier si le checksum ne correspond pas.
- name: "{{{{ artifact_title }}}} — Récupération du checksum SHA256"
  ansible.builtin.uri:
    url:              "{{{{ artifactory_url }}}}/api/storage/{{{{ artifactory_repo_name }}}}/{{{{ _artifact_group_path }}}}/{{{{ maven.artifactId }}}}/{{{{ _artifact_filename }}}}"
    return_content:   true
    force_basic_auth: true
    url_username:     "{{{{ login }}}}"
    url_password:     "{{{{ password }}}}"
    validate_certs:   "{{{{ validate_certs }}}}"
  register: artifact_meta

- name: "{{{{ artifact_title }}}} — Définition du checksum"
  ansible.builtin.set_fact:
    _artifact_checksum: "sha256:{{{{ artifact_meta.json.checksums.sha256 }}}}"

# ── Chemin de destination local ───────────────────────────────────────────────
# Par défaut dans tmp_dir (ansible_remote_tmp). Peut être surchargé
# en passant la variable 'dest' depuis le playbook appelant.
- name: "{{{{ artifact_title }}}} — Définition du chemin de destination"
  ansible.builtin.set_fact:
    artifact_dest: "{{{{ dest | default(tmp_dir + '/' + _artifact_filename) }}}}"

# ── Création du répertoire de destination ────────────────────────────────────
- name: "{{{{ artifact_title }}}} — Création du répertoire de destination"
  ansible.builtin.file:
    path:  "{{{{ artifact_dest | dirname }}}}"
    state: directory
    mode:  '0755'

# ── Téléchargement de l'artefact ─────────────────────────────────────────────
# Le module get_url vérifie automatiquement le checksum après téléchargement.
# Si le fichier existe déjà avec le bon checksum, il n'est pas retéléchargé
# (idempotence).
- name: "{{{{ artifact_title }}}} — Téléchargement vers {{{{ artifact_dest }}}}"
  ansible.builtin.get_url:
    url:           "{{{{ artifactory_url }}}}/{{{{ artifactory_repo_name }}}}/{{{{ _artifact_group_path }}}}/{{{{ maven.artifactId }}}}/{{{{ _artifact_filename }}}}"
    dest:          "{{{{ artifact_dest }}}}"
    url_username:  "{{{{ login }}}}"
    url_password:  "{{{{ password }}}}"
    checksum:      "{{{{ _artifact_checksum }}}}"
    validate_certs: "{{{{ validate_certs }}}}"
    force:         false
  register: download_result

# ── Vérification finale ────────────────────────────────────────────────────────
- name: "{{{{ artifact_title }}}} — Vérification du fichier téléchargé"
  ansible.builtin.stat:
    path: "{{{{ artifact_dest }}}}"
  register: artifact_stat

- name: "{{{{ artifact_title }}}} — Résumé du téléchargement"
  ansible.builtin.debug:
    msg: >-
      Artefact disponible : {{{{ artifact_dest }}}}
      ({{{{ (artifact_stat.stat.size / 1024 / 1024) | round(2) }}}} Mo)
  when: artifact_stat.stat.exists
"""


# ── Rôle : apache ─────────────────────────────────────────────────────────────

def _apache_defaults() -> str:
    return """\
# =============================================================================
# Rôle : apache — Variables par défaut
# =============================================================================

# Nom du service systemd Apache (httpd sur RHEL/CentOS, apache2 sur Debian/Ubuntu)
apache_service: httpd

# Port HTTP d'écoute
apache_port: 80

# Port HTTPS d'écoute
apache_port_ssl: 443

# Répertoire principal de configuration Apache
apache_conf_dir: /etc/httpd/conf

# Répertoire des virtual hosts et configurations complémentaires
apache_vhosts_dir: /etc/httpd/conf.d

# Racine web par défaut
apache_webroot: /var/www/html

# Timeout maximum d'attente pour le démarrage du service (secondes)
apache_start_timeout: 30
"""


def _apache_tasks() -> str:
    return """\
---
# =============================================================================
# Rôle : apache
#
# Gestion du service Apache HTTP Server (httpd) sur RHEL/CentOS.
# Vérifie le statut, démarre si nécessaire et valide la configuration.
#
# Variables configurables (voir defaults/main.yml) :
#   apache_service  : nom du service systemd      (défaut: httpd)
#   apache_port     : port HTTP                   (défaut: 80)
#   apache_port_ssl : port HTTPS                  (défaut: 443)
#   apache_webroot  : racine web                  (défaut: /var/www/html)
# =============================================================================

# ── Vérification du statut actuel ────────────────────────────────────────────
- name: "Apache — Vérification du statut du service {{ apache_service }}"
  ansible.builtin.systemd:
    name: "{{ apache_service }}"
  register: apache_status
  become: true

- name: "Apache — Statut : {{ apache_status.status.ActiveState }}"
  ansible.builtin.debug:
    msg: "Le service {{ apache_service }} est {{ apache_status.status.ActiveState }}"

# ── Démarrage du service si arrêté ───────────────────────────────────────────
# Active également le démarrage automatique au boot (enabled: true).
- name: "Apache — Démarrage du service (si arrêté)"
  ansible.builtin.systemd:
    name:    "{{ apache_service }}"
    state:   started
    enabled: true
  become: true
  when: apache_status.status.ActiveState != 'active'

# ── Validation de la configuration ───────────────────────────────────────────
# Équivalent de `httpd -t` — vérifie la syntaxe avant tout rechargement.
# La tâche échoue si la configuration est invalide (rc != 0).
- name: "Apache — Validation de la configuration (httpd -t)"
  ansible.builtin.command: httpd -t
  changed_when: false
  become: true
  register: apache_config_test
  failed_when: apache_config_test.rc != 0

- name: "Apache — Résultat de la validation"
  ansible.builtin.debug:
    msg: "{{ apache_config_test.stderr_lines }}"

# ── Vérification de la disponibilité du port ─────────────────────────────────
# Attend que le port HTTP soit ouvert avant de continuer.
- name: "Apache — Vérification de la disponibilité du port {{ apache_port }}"
  ansible.builtin.wait_for:
    port:    "{{ apache_port }}"
    timeout: "{{ apache_start_timeout }}"
    state:   started
"""


def _apache_handlers() -> str:
    return """\
---
# =============================================================================
# Rôle : apache — Handlers
#
# Déclenchés via `notify: restart apache` ou `notify: reload apache`
# depuis les tâches du rôle ou d'un playbook dépendant.
# =============================================================================

# Redémarrage complet du service (à utiliser après changement de configuration
# qui nécessite un rechargement complet du processus, ex: modules).
- name: restart apache
  ansible.builtin.systemd:
    name:  "{{ apache_service }}"
    state: restarted
  become: true

# Rechargement à chaud (graceful) — les connexions en cours ne sont pas coupées.
# Préférer reload pour les changements de virtual hosts ou de configuration mineurs.
- name: reload apache
  ansible.builtin.systemd:
    name:  "{{ apache_service }}"
    state: reloaded
  become: true
"""


# ── Rôle : tomcat ─────────────────────────────────────────────────────────────

def _tomcat_defaults() -> str:
    return """\
# =============================================================================
# Rôle : tomcat — Variables par défaut
# =============================================================================

# Nom du service systemd Tomcat
tomcat_service: tomcat

# Port HTTP d'écoute de Tomcat (connecteur HTTP/1.1)
tomcat_port: 8080

# Port AJP (si utilisé avec Apache en frontal, sinon laisser commenté)
# tomcat_port_ajp: 8009

# Répertoire d'installation de Tomcat
tomcat_home: /opt/tomcat

# Répertoire de déploiement des applications (WAR/répertoires)
tomcat_webapps: "{{ tomcat_home }}/webapps"

# Répertoire des journaux Tomcat
tomcat_logs: "{{ tomcat_home }}/logs"

# Utilisateur système sous lequel tourne Tomcat
tomcat_user: tomcat

# Timeout maximum d'attente pour le démarrage du service (secondes)
tomcat_start_timeout: 60
"""


def _tomcat_tasks() -> str:
    return """\
---
# =============================================================================
# Rôle : tomcat
#
# Gestion du service Tomcat sur RHEL/CentOS.
# Vérifie le statut, démarre si nécessaire et attend la disponibilité du port.
#
# Variables configurables (voir defaults/main.yml) :
#   tomcat_service       : nom du service systemd   (défaut: tomcat)
#   tomcat_port          : port HTTP Tomcat          (défaut: 8080)
#   tomcat_home          : répertoire d'installation (défaut: /opt/tomcat)
#   tomcat_webapps       : répertoire des webapps    (défaut: {{ tomcat_home }}/webapps)
#   tomcat_user          : utilisateur système       (défaut: tomcat)
#   tomcat_start_timeout : timeout de démarrage (s)  (défaut: 60)
# =============================================================================

# ── Vérification du statut actuel ────────────────────────────────────────────
- name: "Tomcat — Vérification du statut du service {{ tomcat_service }}"
  ansible.builtin.systemd:
    name: "{{ tomcat_service }}"
  register: tomcat_status
  become: true

- name: "Tomcat — Statut : {{ tomcat_status.status.ActiveState }}"
  ansible.builtin.debug:
    msg: "Le service {{ tomcat_service }} est {{ tomcat_status.status.ActiveState }}"

# ── Démarrage du service si arrêté ───────────────────────────────────────────
# Active également le démarrage automatique au boot (enabled: true).
- name: "Tomcat — Démarrage du service (si arrêté)"
  ansible.builtin.systemd:
    name:    "{{ tomcat_service }}"
    state:   started
    enabled: true
  become: true
  when: tomcat_status.status.ActiveState != 'active'

# ── Vérification de la disponibilité du port ─────────────────────────────────
# Attend que Tomcat soit prêt à accepter des connexions sur son port HTTP.
# Échoue si le port n'est pas disponible après tomcat_start_timeout secondes.
- name: "Tomcat — Attente de la disponibilité du port {{ tomcat_port }}"
  ansible.builtin.wait_for:
    port:    "{{ tomcat_port }}"
    timeout: "{{ tomcat_start_timeout }}"
    state:   started

# ── Affichage des derniers logs au démarrage ─────────────────────────────────
# Utile pour diagnostiquer un démarrage lent ou une erreur d'initialisation.
- name: "Tomcat — Lecture des dernières lignes de catalina.out"
  ansible.builtin.command:
    cmd: "tail -n 20 {{ tomcat_logs }}/catalina.out"
  changed_when: false
  become: true
  become_user: "{{ tomcat_user }}"
  register: tomcat_log_tail
  failed_when: false

- name: "Tomcat — Derniers logs de démarrage"
  ansible.builtin.debug:
    msg: "{{ tomcat_log_tail.stdout_lines }}"
  when: tomcat_log_tail.stdout_lines is defined
"""


def _tomcat_handlers() -> str:
    return """\
---
# =============================================================================
# Rôle : tomcat — Handlers
#
# Déclenchés via `notify: restart tomcat` ou `notify: stop tomcat`
# depuis les tâches du rôle ou d'un playbook dépendant.
# =============================================================================

# Redémarrage complet de Tomcat (à utiliser après déploiement d'une webapp
# ou modification de la configuration server.xml / context.xml).
- name: restart tomcat
  ansible.builtin.systemd:
    name:  "{{ tomcat_service }}"
    state: restarted
  become: true

# Arrêt propre du service Tomcat.
- name: stop tomcat
  ansible.builtin.systemd:
    name:  "{{ tomcat_service }}"
    state: stopped
  become: true
"""


# ── Rôle : mq (IBM MQ) ───────────────────────────────────────────────────────

def _mq_defaults() -> str:
    return """\
# =============================================================================
# Rôle : mq — Variables par défaut (IBM MQ)
# =============================================================================

# Nom du Queue Manager à gérer
mq_qmgr: QMGR1

# Utilisateur système IBM MQ
mq_user: mqm

# Répertoire d'installation IBM MQ
mq_install_dir: /opt/mqm

# Port d'écoute du listener MQ
mq_port: 1414

# Timeout d'attente du démarrage (secondes)
mq_start_timeout: 60
"""


def _mq_tasks() -> str:
    return """\
---
# =============================================================================
# Rôle : mq
#
# Gestion du Queue Manager IBM MQ.
#
# Variables configurables (voir defaults/main.yml) :
#   mq_qmgr        : nom du Queue Manager         (défaut: QMGR1)
#   mq_user        : utilisateur système MQ        (défaut: mqm)
#   mq_install_dir : répertoire d'installation     (défaut: /opt/mqm)
#   mq_port        : port du listener              (défaut: 1414)
# =============================================================================

# ── Vérification du statut du Queue Manager ───────────────────────────────────
# dspmq affiche l'état de tous les Queue Managers ou d'un en particulier.
- name: "MQ — Statut du Queue Manager {{ mq_qmgr }}"
  ansible.builtin.command:
    cmd: "{{ mq_install_dir }}/bin/dspmq -m {{ mq_qmgr }}"
  register: mq_status
  become: true
  become_user: "{{ mq_user }}"
  changed_when: false
  failed_when: false

- name: "MQ — Affichage du statut"
  ansible.builtin.debug:
    msg: "{{ mq_status.stdout }}"

# ── Démarrage du Queue Manager si arrêté ─────────────────────────────────────
# strmqm démarre le QM. Si déjà démarré, la commande retourne un avertissement
# mais ne provoque pas d'erreur (idempotent en pratique).
- name: "MQ — Démarrage du Queue Manager {{ mq_qmgr }} (si arrêté)"
  ansible.builtin.command:
    cmd: "{{ mq_install_dir }}/bin/strmqm {{ mq_qmgr }}"
  become: true
  become_user: "{{ mq_user }}"
  when: "'Running' not in mq_status.stdout"
  register: mq_start
  changed_when: mq_start.rc == 0

# ── Vérification de la disponibilité du port listener ────────────────────────
- name: "MQ — Attente de la disponibilité du port {{ mq_port }}"
  ansible.builtin.wait_for:
    port:    "{{ mq_port }}"
    timeout: "{{ mq_start_timeout }}"
    state:   started
  when: "'Running' not in mq_status.stdout"

# ── Vérification finale ────────────────────────────────────────────────────────
- name: "MQ — Statut final du Queue Manager"
  ansible.builtin.command:
    cmd: "{{ mq_install_dir }}/bin/dspmq -m {{ mq_qmgr }}"
  register: mq_final
  become: true
  become_user: "{{ mq_user }}"
  changed_when: false

- name: "MQ — Résultat"
  ansible.builtin.debug:
    msg: "{{ mq_final.stdout }}"
"""


def _mq_handlers() -> str:
    return """\
---
# =============================================================================
# Rôle : mq — Handlers
# =============================================================================

# Arrêt propre du Queue Manager (attente des connexions en cours).
- name: stop mq
  ansible.builtin.command:
    cmd: "{{ mq_install_dir }}/bin/endmqm {{ mq_qmgr }}"
  become: true
  become_user: "{{ mq_user }}"

# Redémarrage : arrêt puis démarrage du Queue Manager.
- name: restart mq
  ansible.builtin.command:
    cmd: "{{ mq_install_dir }}/bin/endmqm {{ mq_qmgr }}"
  become: true
  become_user: "{{ mq_user }}"
  notify: start mq after stop

- name: start mq after stop
  ansible.builtin.command:
    cmd: "{{ mq_install_dir }}/bin/strmqm {{ mq_qmgr }}"
  become: true
  become_user: "{{ mq_user }}"
"""


# ── Rôle : websphere (IBM WebSphere Application Server) ──────────────────────

def _websphere_defaults() -> str:
    return """\
# =============================================================================
# Rôle : websphere — Variables par défaut (IBM WebSphere Application Server)
# =============================================================================

# Répertoire d'installation de WebSphere Application Server
was_install_dir: /opt/IBM/WebSphere/AppServer

# Nom du profil WebSphere à gérer
was_profile: AppSrv01

# Nom du serveur d'application dans le profil
was_server: server1

# Utilisateur système WebSphere
was_user: wasadm

# Port HTTP de l'application (pour vérification de disponibilité)
was_port: 9080

# Timeout de démarrage (secondes)
was_start_timeout: 120
"""


def _websphere_tasks() -> str:
    return """\
---
# =============================================================================
# Rôle : websphere
#
# Gestion d'un serveur IBM WebSphere Application Server.
#
# Variables configurables (voir defaults/main.yml) :
#   was_install_dir : répertoire d'installation WAS   (défaut: /opt/IBM/WebSphere/AppServer)
#   was_profile     : nom du profil WAS               (défaut: AppSrv01)
#   was_server      : nom du serveur dans le profil   (défaut: server1)
#   was_user        : utilisateur système             (défaut: wasadm)
#   was_port        : port HTTP applicatif            (défaut: 9080)
# =============================================================================

# ── Vérification du statut du serveur ─────────────────────────────────────────
# serverStatus.sh retourne l'état du serveur (STARTED / STOPPED).
- name: "WebSphere — Statut du serveur {{ was_server }} (profil {{ was_profile }})"
  ansible.builtin.command:
    cmd: >
      {{ was_install_dir }}/profiles/{{ was_profile }}/bin/serverStatus.sh
      {{ was_server }}
      -profileName {{ was_profile }}
  register: was_status
  become: true
  become_user: "{{ was_user }}"
  changed_when: false
  failed_when: false

- name: "WebSphere — Affichage du statut"
  ansible.builtin.debug:
    msg: "{{ was_status.stdout_lines }}"

# ── Démarrage du serveur si arrêté ───────────────────────────────────────────
- name: "WebSphere — Démarrage de {{ was_server }} (si arrêté)"
  ansible.builtin.command:
    cmd: >
      {{ was_install_dir }}/profiles/{{ was_profile }}/bin/startServer.sh
      {{ was_server }}
      -profileName {{ was_profile }}
  become: true
  become_user: "{{ was_user }}"
  when: "'STARTED' not in was_status.stdout"
  register: was_start
  changed_when: was_start.rc == 0

# ── Attente de la disponibilité HTTP ──────────────────────────────────────────
- name: "WebSphere — Attente de la disponibilité du port {{ was_port }}"
  ansible.builtin.wait_for:
    port:    "{{ was_port }}"
    timeout: "{{ was_start_timeout }}"
    state:   started
  when: "'STARTED' not in was_status.stdout"
"""


def _websphere_handlers() -> str:
    return """\
---
# =============================================================================
# Rôle : websphere — Handlers
# =============================================================================

# Arrêt propre du serveur WebSphere.
- name: stop websphere
  ansible.builtin.command:
    cmd: >
      {{ was_install_dir }}/profiles/{{ was_profile }}/bin/stopServer.sh
      {{ was_server }}
      -profileName {{ was_profile }}
  become: true
  become_user: "{{ was_user }}"

# Redémarrage du serveur WebSphere.
- name: restart websphere
  ansible.builtin.command:
    cmd: >
      {{ was_install_dir }}/profiles/{{ was_profile }}/bin/stopServer.sh
      {{ was_server }}
      -profileName {{ was_profile }}
  become: true
  become_user: "{{ was_user }}"
  notify: start websphere after stop

- name: start websphere after stop
  ansible.builtin.command:
    cmd: >
      {{ was_install_dir }}/profiles/{{ was_profile }}/bin/startServer.sh
      {{ was_server }}
      -profileName {{ was_profile }}
  become: true
  become_user: "{{ was_user }}"
"""


# ── Rôle : php ────────────────────────────────────────────────────────────────

def _php_defaults() -> str:
    return """\
# =============================================================================
# Rôle : php — Variables par défaut (PHP-FPM)
# =============================================================================

# Nom du service PHP-FPM (adapter selon la version installée)
# Exemples : php-fpm, php7.4-fpm, php8.1-fpm
php_fpm_service: php-fpm

# Port d'écoute de PHP-FPM (si configuré en mode TCP, sinon Unix socket)
php_fpm_port: 9000

# Répertoire des pools PHP-FPM
php_fpm_pool_dir: /etc/php-fpm.d

# Timeout de démarrage (secondes)
php_start_timeout: 30
"""


def _php_tasks() -> str:
    return """\
---
# =============================================================================
# Rôle : php
#
# Gestion du service PHP-FPM.
# PHP-FPM (FastCGI Process Manager) est généralement associé à un serveur
# web (Apache avec mod_proxy_fcgi ou Nginx) pour servir les applications PHP.
#
# Variables configurables (voir defaults/main.yml) :
#   php_fpm_service  : nom du service systemd     (défaut: php-fpm)
#   php_fpm_port     : port TCP de PHP-FPM        (défaut: 9000)
#   php_start_timeout: timeout démarrage (s)      (défaut: 30)
# =============================================================================

# ── Vérification du statut ────────────────────────────────────────────────────
- name: "PHP-FPM — Vérification du statut du service {{ php_fpm_service }}"
  ansible.builtin.systemd:
    name: "{{ php_fpm_service }}"
  register: phpfpm_status
  become: true

- name: "PHP-FPM — Statut : {{ phpfpm_status.status.ActiveState }}"
  ansible.builtin.debug:
    msg: "Le service {{ php_fpm_service }} est {{ phpfpm_status.status.ActiveState }}"

# ── Démarrage si arrêté ───────────────────────────────────────────────────────
- name: "PHP-FPM — Démarrage du service (si arrêté)"
  ansible.builtin.systemd:
    name:    "{{ php_fpm_service }}"
    state:   started
    enabled: true
  become: true
  when: phpfpm_status.status.ActiveState != 'active'

# ── Vérification de la disponibilité du port ──────────────────────────────────
# Applicable uniquement si PHP-FPM est configuré en mode TCP (pas Unix socket).
- name: "PHP-FPM — Attente de la disponibilité du port {{ php_fpm_port }}"
  ansible.builtin.wait_for:
    port:    "{{ php_fpm_port }}"
    timeout: "{{ php_start_timeout }}"
    state:   started
  # Commenter si PHP-FPM utilise un Unix socket plutôt qu'un port TCP
"""


def _php_handlers() -> str:
    return """\
---
# =============================================================================
# Rôle : php — Handlers
# =============================================================================

# Redémarrage complet de PHP-FPM (après changement de configuration).
- name: restart php-fpm
  ansible.builtin.systemd:
    name:  "{{ php_fpm_service }}"
    state: restarted
  become: true

# Rechargement à chaud de PHP-FPM (après ajout/modification de pool).
- name: reload php-fpm
  ansible.builtin.systemd:
    name:  "{{ php_fpm_service }}"
    state: reloaded
  become: true
"""


# ── Rôle : jboss (WildFly / JBoss EAP) ──────────────────────────────────────

def _jboss_defaults() -> str:
    return """\
# =============================================================================
# Rôle : jboss — Variables par défaut (WildFly / JBoss EAP)
# =============================================================================

# Nom du service systemd WildFly/JBoss
jboss_service: wildfly

# Répertoire d'installation de WildFly/JBoss
jboss_home: /opt/wildfly

# Port HTTP de l'application (pour vérification de disponibilité)
jboss_port: 8080

# Port de la console d'administration (HTTP)
jboss_admin_port: 9990

# Utilisateur système WildFly/JBoss
jboss_user: wildfly

# Timeout de démarrage (secondes)
jboss_start_timeout: 120
"""


def _jboss_tasks() -> str:
    return """\
---
# =============================================================================
# Rôle : jboss
#
# Gestion du serveur d'application WildFly / JBoss EAP.
#
# Variables configurables (voir defaults/main.yml) :
#   jboss_service      : nom du service systemd        (défaut: wildfly)
#   jboss_home         : répertoire d'installation     (défaut: /opt/wildfly)
#   jboss_port         : port HTTP applicatif          (défaut: 8080)
#   jboss_admin_port   : port console d'admin          (défaut: 9990)
#   jboss_user         : utilisateur système           (défaut: wildfly)
#   jboss_start_timeout: timeout démarrage (s)         (défaut: 120)
# =============================================================================

# ── Vérification du statut ────────────────────────────────────────────────────
- name: "JBoss — Vérification du statut du service {{ jboss_service }}"
  ansible.builtin.systemd:
    name: "{{ jboss_service }}"
  register: jboss_status
  become: true

- name: "JBoss — Statut : {{ jboss_status.status.ActiveState }}"
  ansible.builtin.debug:
    msg: "Le service {{ jboss_service }} est {{ jboss_status.status.ActiveState }}"

# ── Démarrage si arrêté ───────────────────────────────────────────────────────
- name: "JBoss — Démarrage du service (si arrêté)"
  ansible.builtin.systemd:
    name:    "{{ jboss_service }}"
    state:   started
    enabled: true
  become: true
  when: jboss_status.status.ActiveState != 'active'

# ── Attente de la disponibilité HTTP ──────────────────────────────────────────
# WildFly peut prendre du temps à démarrer (chargement des déploiements).
- name: "JBoss — Attente de la disponibilité du port {{ jboss_port }}"
  ansible.builtin.wait_for:
    port:    "{{ jboss_port }}"
    timeout: "{{ jboss_start_timeout }}"
    state:   started

# ── Vérification de la console d'administration ────────────────────────────────
- name: "JBoss — Vérification de la disponibilité de la console d'admin (port {{ jboss_admin_port }})"
  ansible.builtin.wait_for:
    port:    "{{ jboss_admin_port }}"
    timeout: 30
    state:   started
  failed_when: false   # Non bloquant : la console peut être désactivée
"""


def _jboss_handlers() -> str:
    return """\
---
# =============================================================================
# Rôle : jboss — Handlers
# =============================================================================

# Redémarrage complet de WildFly/JBoss (après déploiement ou changement de config).
- name: restart jboss
  ansible.builtin.systemd:
    name:  "{{ jboss_service }}"
    state: restarted
  become: true

# Arrêt propre du service.
- name: stop jboss
  ansible.builtin.systemd:
    name:  "{{ jboss_service }}"
    state: stopped
  become: true
"""


# ── Rôle : cft (Axway Transfer CFT) ──────────────────────────────────────────

def _cft_defaults() -> str:
    return """\
# =============================================================================
# Rôle : cft — Variables par défaut (Axway Transfer CFT)
# =============================================================================

# Répertoire d'installation de Transfer CFT
cft_install_dir: /opt/cft

# Utilisateur système CFT
cft_user: cftuser

# Nom de l'instance CFT (CFTENV ou équivalent)
cft_instance: CFTPROD

# Timeout de démarrage (secondes)
cft_start_timeout: 60

# Port de supervision CFT (si activé)
# cft_port: 1761
"""


def _cft_tasks() -> str:
    return """\
---
# =============================================================================
# Rôle : cft
#
# Gestion du transfert de fichiers Axway Transfer CFT.
#
# Variables configurables (voir defaults/main.yml) :
#   cft_install_dir : répertoire d'installation    (défaut: /opt/cft)
#   cft_user        : utilisateur système CFT      (défaut: cftuser)
#   cft_instance    : nom de l'instance CFT        (défaut: CFTPROD)
#   cft_start_timeout: timeout démarrage (s)       (défaut: 60)
# =============================================================================

# ── Vérification du statut via cftping ────────────────────────────────────────
# cftping retourne 0 si CFT est actif, non-zero sinon.
- name: "CFT — Vérification du statut (cftping)"
  ansible.builtin.command:
    cmd:  "{{ cft_install_dir }}/bin/cftping"
    chdir: "{{ cft_install_dir }}"
  register: cft_status
  become: true
  become_user: "{{ cft_user }}"
  changed_when: false
  failed_when: false
  environment:
    CFTENV: "{{ cft_instance }}"

- name: "CFT — Statut : {{ 'actif' if cft_status.rc == 0 else 'inactif' }}"
  ansible.builtin.debug:
    msg: "CFT {{ cft_instance }} : {{ cft_status.stdout | default('pas de réponse') }}"

# ── Démarrage si inactif ──────────────────────────────────────────────────────
# cftstart initialise et démarre le moteur de transfert.
- name: "CFT — Démarrage de l'instance {{ cft_instance }} (si inactif)"
  ansible.builtin.command:
    cmd:  "{{ cft_install_dir }}/bin/cftstart"
    chdir: "{{ cft_install_dir }}"
  become: true
  become_user: "{{ cft_user }}"
  when: cft_status.rc != 0
  environment:
    CFTENV: "{{ cft_instance }}"
  register: cft_start
  changed_when: cft_start.rc == 0

# ── Vérification post-démarrage ───────────────────────────────────────────────
- name: "CFT — Attente de la disponibilité après démarrage"
  ansible.builtin.command:
    cmd:  "{{ cft_install_dir }}/bin/cftping"
    chdir: "{{ cft_install_dir }}"
  register: cft_ready
  become: true
  become_user: "{{ cft_user }}"
  changed_when: false
  retries: 6
  delay: 10
  until: cft_ready.rc == 0
  when: cft_status.rc != 0
  environment:
    CFTENV: "{{ cft_instance }}"
"""


def _cft_handlers() -> str:
    return """\
---
# =============================================================================
# Rôle : cft — Handlers
# =============================================================================

# Arrêt propre de Transfer CFT (attend la fin des transferts en cours).
- name: stop cft
  ansible.builtin.command:
    cmd:  "{{ cft_install_dir }}/bin/cftstop"
    chdir: "{{ cft_install_dir }}"
  become: true
  become_user: "{{ cft_user }}"
  environment:
    CFTENV: "{{ cft_instance }}"

# Redémarrage : arrêt puis démarrage de Transfer CFT.
- name: restart cft
  ansible.builtin.command:
    cmd:  "{{ cft_install_dir }}/bin/cftstop"
    chdir: "{{ cft_install_dir }}"
  become: true
  become_user: "{{ cft_user }}"
  environment:
    CFTENV: "{{ cft_instance }}"
  notify: start cft after stop

- name: start cft after stop
  ansible.builtin.command:
    cmd:  "{{ cft_install_dir }}/bin/cftstart"
    chdir: "{{ cft_install_dir }}"
  become: true
  become_user: "{{ cft_user }}"
  environment:
    CFTENV: "{{ cft_instance }}"
"""


# ── Point d'entrée ────────────────────────────────────────────────────────────

def generate_ansible_zip(
    code_app: str,
    nom_app: str,
    entite: str,
    envs: list,
    repo_type: str = 'generic',
    middlewares: list | None = None,
) -> bytes:
    """
    Génère un package Ansible (ZIP) en mémoire.

    envs = [
        {
            "name": "dev",
            "fqdn": "ca-cedicam.fr",
            "hosts": [{"hostname": "server01", "group": "AIX_APP"}]
        },
        ...
    ]
    middlewares = ["apache", "tomcat"]  # optionnel
    """
    ca = code_app.lower()
    base = f'{ca}_deploy/'
    mw = [m.lower() for m in (middlewares or [])]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:

        # group_vars racine
        zf.writestr(base + 'group_vars/all.yml',
                    _root_group_vars(code_app, nom_app, entite))

        # Inventaires par env
        for env_cfg in envs:
            env   = env_cfg.get('name', '')
            fqdn  = env_cfg.get('fqdn', '')
            hosts = env_cfg.get('hosts', [])
            if not env:
                continue
            inv = base + f'inventories/{env}/'
            zf.writestr(inv + 'hosts',              _hosts_content(code_app, hosts, fqdn, mw))
            zf.writestr(inv + 'group_vars/all.yml', _env_group_vars(env))

        # Rôle get-from-artifactory
        role = base + 'playbooks/roles/get-from-artifactory/'
        zf.writestr(role + 'defaults/main.yml', _get_from_artifactory_defaults(repo_type))
        zf.writestr(role + 'tasks/main.yml',    _get_from_artifactory_tasks(repo_type))

        # Rôles middleware optionnels
        _MW_ROLES = {
            'apache':    (_apache_defaults,    _apache_tasks,    _apache_handlers),
            'tomcat':    (_tomcat_defaults,    _tomcat_tasks,    _tomcat_handlers),
            'mq':        (_mq_defaults,        _mq_tasks,        _mq_handlers),
            'websphere': (_websphere_defaults, _websphere_tasks, _websphere_handlers),
            'php':       (_php_defaults,       _php_tasks,       _php_handlers),
            'jboss':     (_jboss_defaults,     _jboss_tasks,     _jboss_handlers),
            'cft':       (_cft_defaults,       _cft_tasks,       _cft_handlers),
        }
        for mw_name, (fn_def, fn_tasks, fn_handlers) in _MW_ROLES.items():
            if mw_name in mw:
                r = base + f'playbooks/roles/{mw_name}/'
                zf.writestr(r + 'defaults/main.yml',  fn_def())
                zf.writestr(r + 'tasks/main.yml',     fn_tasks())
                zf.writestr(r + 'handlers/main.yml',  fn_handlers())

    return buf.getvalue()
