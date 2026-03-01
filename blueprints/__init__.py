from flask import abort, request


def _require_json() -> dict:
    """Retourne le corps JSON de la requête ou lève 400 si absent/invalide."""
    body = request.get_json(force=True, silent=True)
    if body is None:
        abort(400)
    return body
