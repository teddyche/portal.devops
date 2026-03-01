"""
Utilitaires CRUD partagés entre les services SRE, PSSIT et CAD.
Élimine la duplication des patterns exists/filter/remove présents dans les trois modules.
"""
from typing import Optional

from services import store
from services.store import ServiceError


def entity_exists(entities_file: str, entity_id: str) -> bool:
    """Vérifie qu'une entité avec cet id est présente dans le fichier JSON de liste."""
    entities: list[dict] = store.load_json(entities_file) or []
    return any(e['id'] == entity_id for e in entities)


def filter_by_resources(
    entities: list[dict],
    user_resources: Optional[list[dict]],
    module: str,
) -> list[dict]:
    """Filtre une liste d'entités selon les droits de l'utilisateur.
    user_resources=None signifie superadmin (accès total).
    """
    if user_resources is None:
        return entities
    allowed = {r['resource_id'] for r in user_resources if r['module'] == module}
    return [e for e in entities if e['id'] in allowed]


def remove_from_list(entities_file: str, entity_id: str, not_found_msg: str = 'Entité non trouvée') -> None:
    """Retire une entité par id de la liste JSON et sauvegarde le fichier.
    Lève ServiceError(404) si l'entité n'existe pas.
    """
    entities: list[dict] = store.load_json(entities_file) or []
    if not any(e['id'] == entity_id for e in entities):
        raise ServiceError(not_found_msg, 404)
    store.save_json(entities_file, [e for e in entities if e['id'] != entity_id])
