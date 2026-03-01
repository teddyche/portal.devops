from flask import abort, jsonify, request


def _require_json() -> dict:
    """Retourne le corps JSON de la requête ou lève 400 si absent/invalide."""
    body = request.get_json(force=True, silent=True)
    if body is None:
        abort(400)
    return body


def api_error(message: str, status: int = 400):
    """Retourne une réponse d'erreur JSON unifiée {'error': message, 'status': status}."""
    return jsonify({'error': message, 'status': status}), status
