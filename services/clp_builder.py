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

PROD_ENVS = {'prd'}

_SSH_ARGS = (
    'ansible_ssh_args="-o GSSAPIAuthentication=yes '
    '-o UserKnownHostsFile=/home/ldap/ansible_tmp/known_hosts" '
    'ansible_shell_allow_world_readable_temp=true '
    'ansible_host_key_checking=false '
    'ansible_retry_files_enabled=false '
    'ansible_deprecation_warnings=false '
    'ansible_display_skipped_hosts=false '
    'ansible_command_warnings=false '
    'ansible_transport=paramiko '
    'ansible_scp_if_ssh=true '
    'ansible_pipelining=true '
    'ansible_become_ask_pass=false '
    'ansible_local_tmp=/home/ldap/ansible_tmp '
    'ansible_remote_tmp=/home/ldap/ansible_tmp'
)


def _j(var: str) -> str:
    """Retourne une expression Jinja2 {{ var }}."""
    return '{{ ' + var + ' }}'


# ── Générateurs de contenu ───────────────────────────────────────────────────

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
        f'# Variables pour l\'environnement {env}',
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


def _hosts_content(code_app: str, hosts: list, fqdn: str) -> str:
    ca = code_app.lower()

    # Collect groups: group_name → [hostname]
    groups: dict[str, list[str]] = {}
    for h in hosts:
        g = h.get('group', f'{code_app.upper()}_APP').strip().upper().replace(' ', '_')
        hn = h.get('hostname', '').strip()
        if hn:
            groups.setdefault(g, []).append(hn)

    if not groups:
        # Fichier vide avec commentaire guide
        return '\n'.join([
            f'[{ca}_platform:vars]',
            'callbacks_enabled=timer,profile_tasks,profile_roles',
            '',
            f'[{ca}_platform:children]',
            f'{ca}_app',
            '',
            f'[{ca}_app:children]',
            f'# TODO: définir les groupes de serveurs',
            '',
            f'# [NOM_GROUPE]',
            f'# hostname.{fqdn or "fqdn.exemple"} {_SSH_ARGS}',
            '',
        ])

    # Séparer app / db
    app_groups = [g for g in groups if not any(k in g for k in ('DB', 'BDD', 'BASE'))]
    db_groups  = [g for g in groups if any(k in g for k in ('DB', 'BDD', 'BASE'))]

    lines = [
        f'[{ca}_platform:vars]',
        'callbacks_enabled=timer,profile_tasks,profile_roles',
        '',
        f'[{ca}_platform:children]',
    ]
    if app_groups:
        lines.append(f'{ca}_app')
    if db_groups:
        lines.append(f'{ca}_db')
    lines.append('')

    if app_groups:
        lines.append(f'[{ca}_app:children]')
        for g in app_groups:
            lines.append(g)
        lines.append('')

    if db_groups:
        lines.append(f'[{ca}_db:children]')
        for g in db_groups:
            lines.append(g)
        lines.append('')

    for g, hostnames in groups.items():
        lines.append(f'[{g}]')
        for hn in hostnames:
            host = f'{hn}.{fqdn}' if fqdn and '.' not in hn else hn
            lines.append(f'{host} {_SSH_ARGS}')
        lines.append('')

    return '\n'.join(lines)


def _get_from_artifactory_defaults() -> str:
    return """\
# Répertoire temporaire
tmp_dir: "{{ hostvars[inventory_hostname]['ansible_remote_tmp'] | default('/tmp') }}"

# Code entité
entity: caps

# Type de repo : maven, generic, docker
artifactory_repo_type: generic

# Maturité : scratch (dev/int/rec), staging (qua/rec), stable (hom/pre/prd)
maturity: stable

# Zone d'exposition : intranet ou internet
zone: intranet

# Zone infrastructure : community, 3PG_HP ou 3PG
artifactory_area: community

artifactory_repo_name: "{{ entite }}-{{ code_app }}-{{ artifactory_repo_type }}-{{ maturity }}-{{ zone }}"

artifact_title: "[{{ artifactory_repo_name }}] maven:{{ maven.groupId }}:{{ maven.artifactId }}:{{ maven.version }}"

artifactory_url_target:
  community: "https://registry.saas.cagip.group.gca:443/artifactory"
  3PG_HP: "https://pre-registry-pda.ca-cedicam.fr:443/artifactory"
  3PG: "https://registry-pda.sec-prod1.lan:443/artifactory"

artifactory_url: "{{ artifactory_url_target[artifactory_area] }}"
"""


def _get_from_artifactory_tasks() -> str:
    return """\
---
# Rôle : get-from-artifactory
# Récupère un artefact depuis Artifactory et le place localement

- name: "{{ artifact_title }} - Récupération des informations sur la version"
  ansible.builtin.uri:
    url: "{{ artifactory_url }}/api/storage/{{ artifactory_repo_name }}/{{ maven.groupId | replace('.', '/') }}/{{ maven.artifactId }}/{{ maven.version }}"
    return_content: yes
    force_basic_auth: true
    url_username: "{{ login }}"
    url_password: "{{ password }}"
  register: artifact_info

- name: "{{ artifact_title }} - Détermination du nom de fichier"
  ansible.builtin.set_fact:
    filename: "{{ artifact_info.json.path | basename }}"

- name: "{{ artifact_title }} - Récupération des informations sur le livrable"
  ansible.builtin.uri:
    url: "{{ artifactory_url }}/api/storage/{{ artifactory_repo_name }}/{{ maven.groupId | replace('.', '/') }}/{{ maven.artifactId }}/{{ filename }}"
    return_content: yes
    force_basic_auth: true
    url_username: "{{ login }}"
    url_password: "{{ password }}"
  register: artifact_info

- name: "{{ artifact_title }} - Détermination de la somme de contrôle SHA256"
  ansible.builtin.set_fact:
    artifact_checksum: "sha256:{{ artifact_info.json.checksums.sha256 }}"

- name: "{{ artifact_title }} - Détermination du chemin de destination"
  ansible.builtin.set_fact:
    artifact_dest: "{{ dest | default(tmp_dir + '/' + filename) }}"

- name: "{{ artifact_title }} - Création du répertoire de destination si nécessaire"
  ansible.builtin.file:
    path: "{{ artifact_dest | dirname }}"
    state: directory

- name: "{{ artifact_title }} - Téléchargement de l'artefact dans {{ artifact_dest }}"
  ansible.builtin.get_url:
    url: "{{ artifactory_url }}/{{ artifactory_repo_name }}/{{ maven.groupId | replace('.', '/') }}/{{ maven.artifactId }}/{{ filename }}"
    dest: "{{ artifact_dest }}"
    url_username: "{{ login }}"
    url_password: "{{ password }}"
    checksum: "{{ artifact_checksum }}"
"""


# ── Point d'entrée ───────────────────────────────────────────────────────────

def generate_ansible_zip(
    code_app: str,
    nom_app: str,
    entite: str,
    envs: list,
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
    """
    ca = code_app.lower()
    project_name = f'{ca}_deploy'

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        base = project_name + '/'

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
            zf.writestr(inv + 'hosts', _hosts_content(code_app, hosts, fqdn))
            zf.writestr(inv + 'group_vars/all.yml', _env_group_vars(env))

        # Rôle get-from-artifactory
        role = base + 'playbooks/roles/get-from-artifactory/'
        zf.writestr(role + 'defaults/main.yml', _get_from_artifactory_defaults())
        zf.writestr(role + 'tasks/main.yml',    _get_from_artifactory_tasks())

    return buf.getvalue()
