"""
Blueprint Kubi IHM : génération de tokens Kubernetes via le serveur Kubi.

Routes :
  GET  /api/kubi/config        → config clusters + proxy (admin)
  POST /api/kubi/config        → sauvegarde config (admin)
  POST /api/kubi/generate      → génère token + kubeconfig + k8s_url
  POST /api/kubi/explain       → décode un token JWT
  POST /api/kubi/quotas        → ResourceQuotas d'un namespace (via token Bearer)

Le mot de passe n'est jamais stocké — transit uniquement pour l'appel Kubi.
"""
import logging

from flask import Blueprint, current_app, jsonify, session

import services.kubi as kubi_service
from blueprints import _require_json, api_error
from services.store import ServiceError

kubi_bp = Blueprint('kubi', __name__)
logger = logging.getLogger(__name__)
_audit = logging.getLogger('audit')


def _dd() -> str:
    return current_app.config['DATAS_DIR']


def _uid() -> str:
    return session.get('user_id', 'anonymous')


# === Config (clusters + proxy) ===

@kubi_bp.route('/api/kubi/config', methods=['GET'])
def api_get_kubi_config():
    """
    Retourne la configuration Kubi (clusters et proxy).
    ---
    tags: [Kubi]
    responses:
      200:
        description: Configuration Kubi
    """
    return jsonify(kubi_service.get_kubi_config(_dd()))


@kubi_bp.route('/api/kubi/config', methods=['POST'])
def api_save_kubi_config():
    """
    Sauvegarde la configuration Kubi.
    ---
    tags: [Kubi]
    responses:
      200:
        description: Config sauvegardée
    """
    try:
        body = _require_json()
        kubi_service.save_kubi_config(_dd(), body)
        _audit.info('kubi_config_saved user=%s', _uid())
        return jsonify({'success': True})
    except ServiceError as e:
        return api_error(e.message, e.status)


# === Génération de token ===

@kubi_bp.route('/api/kubi/generate', methods=['POST'])
def api_kubi_generate():
    """
    Génère un token Kubi et le kubeconfig associé.

    Le mot de passe n'est jamais stocké — utilisé uniquement pour l'appel Kubi.
    ---
    tags: [Kubi]
    parameters:
      - in: body
        schema:
          properties:
            cluster_id: {type: string}
            username:   {type: string}
            password:   {type: string}
            scopes:     {type: string}
    responses:
      200:
        description: Token généré
      401:
        description: Identifiants incorrects
      502:
        description: Serveur Kubi injoignable
    """
    try:
        body = _require_json()
        cluster_id = body.get('cluster_id', '').strip()
        username = body.get('username', '').strip()
        password = body.get('password', '')
        scopes = body.get('scopes', '').strip()

        if not cluster_id:
            return api_error('cluster_id requis', 400)
        if not username:
            return api_error('username requis', 400)
        if not password:
            return api_error('password requis', 400)

        cfg = kubi_service.get_kubi_config(_dd())
        cluster = next((c for c in cfg.get('clusters', []) if c['id'] == cluster_id), None)
        if not cluster:
            return api_error(f'Cluster "{cluster_id}" non trouvé dans la configuration', 404)

        result = kubi_service.generate_kubi_token(
            cluster_url=cluster['url'],
            username=username,
            password=password,
            insecure=cluster.get('insecure', True),
            proxy_url=cfg.get('proxy_url', ''),
            use_proxy=cluster.get('use_proxy', False),
            scopes=scopes,
        )

        _audit.info('kubi_token_generated user=%s cluster=%s subject=%s',
                    _uid(), cluster_id, result.get('body', {}).get('sub', '?'))
        return jsonify(result)

    except ServiceError as e:
        return api_error(e.message, e.status)


# === Quotas K8s ===

@kubi_bp.route('/api/kubi/quotas', methods=['POST'])
def api_kubi_quotas():
    """
    Retourne les ResourceQuotas d'un namespace via l'API K8s.

    Utilise le token Bearer (JWT kubi) — aucun mot de passe requis.
    ---
    tags: [Kubi]
    parameters:
      - in: body
        schema:
          properties:
            k8s_url:    {type: string, description: "URL API K8s (depuis kubeconfig)"}
            token:      {type: string, description: "Token JWT kubi"}
            namespace:  {type: string, description: "Namespace K8s"}
            cluster_id: {type: string, description: "ID cluster (pour paramètres SSL)"}
    responses:
      200:
        description: Liste des ResourceQuotas normalisés
      401:
        description: Token invalide ou expiré
      403:
        description: Accès refusé au namespace
      404:
        description: Namespace introuvable
    """
    try:
        body = _require_json()
        k8s_url = body.get('k8s_url', '').strip()
        token = body.get('token', '').strip()
        namespace = body.get('namespace', '').strip()
        cluster_id = body.get('cluster_id', '').strip()

        if not k8s_url:
            return api_error('k8s_url requis', 400)
        if not token:
            return api_error('token requis', 400)
        if not namespace:
            return api_error('namespace requis', 400)

        # Récupère insecure + proxy depuis la config cluster
        cfg = kubi_service.get_kubi_config(_dd())
        cluster = next((c for c in cfg.get('clusters', []) if c['id'] == cluster_id), None)
        insecure = cluster.get('insecure', True) if cluster else True
        use_proxy = cluster.get('use_proxy', False) if cluster else False
        proxy_url = cfg.get('proxy_url', '')

        quotas = kubi_service.get_kubi_quotas(k8s_url, token, namespace, insecure, proxy_url, use_proxy)
        return jsonify({'quotas': quotas, 'namespace': namespace})

    except ServiceError as e:
        return api_error(e.message, e.status)


@kubi_bp.route('/api/kubi/quotas/all', methods=['POST'])
def api_kubi_quotas_all():
    """
    Liste tous les namespaces accessibles et retourne leurs ResourceQuotas.

    Découverte automatique via GET /api/v1/namespaces — les namespaces en 403/404
    sont ignorés silencieusement. Seuls les namespaces ayant des quotas sont retournés.
    ---
    tags: [Kubi]
    parameters:
      - in: body
        schema:
          properties:
            k8s_url:    {type: string}
            token:      {type: string}
            cluster_id: {type: string}
    responses:
      200:
        description: Liste [{namespace, quotas}] pour les namespaces avec quotas
      401:
        description: Token invalide ou expiré
      502:
        description: API K8s injoignable
    """
    try:
        body = _require_json()
        k8s_url = body.get('k8s_url', '').strip()
        token = body.get('token', '').strip()
        cluster_id = body.get('cluster_id', '').strip()

        if not k8s_url:
            return api_error('k8s_url requis', 400)
        if not token:
            return api_error('token requis', 400)

        cfg = kubi_service.get_kubi_config(_dd())
        cluster = next((c for c in cfg.get('clusters', []) if c['id'] == cluster_id), None)
        insecure = cluster.get('insecure', True) if cluster else True
        use_proxy = cluster.get('use_proxy', False) if cluster else False
        proxy_url = cfg.get('proxy_url', '')

        results = kubi_service.get_all_kubi_quotas(k8s_url, token, insecure, proxy_url, use_proxy)
        _audit.info('kubi_quotas_all user=%s cluster=%s namespaces=%d',
                    _uid(), cluster_id, len(results))
        return jsonify({'results': results})

    except ServiceError as e:
        return api_error(e.message, e.status)


# === Pods K8s ===

def _pod_proxy_params(cluster_id: str) -> tuple:
    """Retourne (insecure, proxy_url, use_proxy) depuis la config cluster."""
    cfg = kubi_service.get_kubi_config(_dd())
    cluster = next((c for c in cfg.get('clusters', []) if c['id'] == cluster_id), None)
    return (
        cluster.get('insecure', True) if cluster else True,
        cfg.get('proxy_url', ''),
        cluster.get('use_proxy', False) if cluster else False,
    )


@kubi_bp.route('/api/kubi/pods', methods=['POST'])
def api_kubi_pods():
    """Liste les pods d'un namespace avec statut, ready, restarts et age."""
    try:
        body = _require_json()
        k8s_url   = body.get('k8s_url', '').strip()
        token     = body.get('token', '').strip()
        namespace = body.get('namespace', '').strip()
        cluster_id = body.get('cluster_id', '').strip()

        if not k8s_url:   return api_error('k8s_url requis', 400)
        if not token:     return api_error('token requis', 400)
        if not namespace: return api_error('namespace requis', 400)

        insecure, proxy_url, use_proxy = _pod_proxy_params(cluster_id)
        pods = kubi_service.get_kubi_pods(k8s_url, token, namespace, insecure, proxy_url, use_proxy)
        return jsonify({'pods': pods, 'namespace': namespace})

    except ServiceError as e:
        return api_error(e.message, e.status)


@kubi_bp.route('/api/kubi/pods/delete', methods=['POST'])
def api_kubi_pods_delete():
    """Supprime un pod (force restart via son contrôleur Deployment/StatefulSet)."""
    try:
        body = _require_json()
        k8s_url   = body.get('k8s_url', '').strip()
        token     = body.get('token', '').strip()
        namespace = body.get('namespace', '').strip()
        pod_name  = body.get('pod_name', '').strip()
        cluster_id = body.get('cluster_id', '').strip()

        if not k8s_url:   return api_error('k8s_url requis', 400)
        if not token:     return api_error('token requis', 400)
        if not namespace: return api_error('namespace requis', 400)
        if not pod_name:  return api_error('pod_name requis', 400)

        insecure, proxy_url, use_proxy = _pod_proxy_params(cluster_id)
        result = kubi_service.delete_kubi_pod(k8s_url, token, namespace, pod_name,
                                               insecure, proxy_url, use_proxy)
        _audit.warning('kubi_pod_delete user=%s cluster=%s ns=%s pod=%s',
                       _uid(), cluster_id, namespace, pod_name)
        return jsonify(result)

    except ServiceError as e:
        return api_error(e.message, e.status)


@kubi_bp.route('/api/kubi/namespace/describe', methods=['POST'])
def api_kubi_namespace_describe():
    """Décrit un namespace : métadonnées, labels, annotations, LimitRanges."""
    try:
        body = _require_json()
        k8s_url   = body.get('k8s_url', '').strip()
        token     = body.get('token', '').strip()
        namespace = body.get('namespace', '').strip()
        cluster_id = body.get('cluster_id', '').strip()

        if not k8s_url:   return api_error('k8s_url requis', 400)
        if not token:     return api_error('token requis', 400)
        if not namespace: return api_error('namespace requis', 400)

        insecure, proxy_url, use_proxy = _pod_proxy_params(cluster_id)
        result = kubi_service.get_kubi_namespace_describe(
            k8s_url, token, namespace, insecure, proxy_url, use_proxy
        )
        return jsonify(result)

    except ServiceError as e:
        return api_error(e.message, e.status)


# === Quota PATCH ===

@kubi_bp.route('/api/kubi/quota/patch', methods=['POST'])
def api_kubi_quota_patch():
    """Met à jour les limites hard d'un ResourceQuota (merge-patch)."""
    try:
        body = _require_json()
        k8s_url    = body.get('k8s_url', '').strip()
        token      = body.get('token', '').strip()
        namespace  = body.get('namespace', '').strip()
        quota_name = body.get('quota_name', '').strip()
        hard       = body.get('hard', {})
        cluster_id = body.get('cluster_id', '').strip()

        if not k8s_url:    return api_error('k8s_url requis', 400)
        if not token:      return api_error('token requis', 400)
        if not namespace:  return api_error('namespace requis', 400)
        if not quota_name: return api_error('quota_name requis', 400)
        if not hard:       return api_error('hard (dict ressources→valeurs) requis', 400)

        insecure, proxy_url, use_proxy = _pod_proxy_params(cluster_id)
        result = kubi_service.patch_namespace_quota(
            k8s_url, token, namespace, quota_name, hard, insecure, proxy_url, use_proxy
        )
        _audit.warning('kubi_quota_patch user=%s cluster=%s ns=%s quota=%s hard=%s',
                       _uid(), cluster_id, namespace, quota_name, hard)
        return jsonify(result)

    except ServiceError as e:
        return api_error(e.message, e.status)


# === Logs pod ===

@kubi_bp.route('/api/kubi/logs', methods=['POST'])
def api_kubi_logs():
    """Récupère les logs d'un container de pod (dernier N lignes)."""
    try:
        body = _require_json()
        k8s_url    = body.get('k8s_url', '').strip()
        token      = body.get('token', '').strip()
        namespace  = body.get('namespace', '').strip()
        pod_name   = body.get('pod_name', '').strip()
        container  = body.get('container', '').strip()
        cluster_id = body.get('cluster_id', '').strip()
        try:
            tail = int(body.get('tail', 200))
        except (ValueError, TypeError):
            return api_error('tail doit être un entier', 400)

        if not k8s_url:   return api_error('k8s_url requis', 400)
        if not token:     return api_error('token requis', 400)
        if not namespace: return api_error('namespace requis', 400)
        if not pod_name:  return api_error('pod_name requis', 400)

        insecure, proxy_url, use_proxy = _pod_proxy_params(cluster_id)
        result = kubi_service.get_pod_logs(
            k8s_url, token, namespace, pod_name, container, tail, insecure, proxy_url, use_proxy
        )
        return jsonify(result)

    except ServiceError as e:
        return api_error(e.message, e.status)


@kubi_bp.route('/api/kubi/pods/containers', methods=['POST'])
def api_kubi_pod_containers():
    """Liste les containers (et initContainers) d'un pod."""
    try:
        body = _require_json()
        k8s_url    = body.get('k8s_url', '').strip()
        token      = body.get('token', '').strip()
        namespace  = body.get('namespace', '').strip()
        pod_name   = body.get('pod_name', '').strip()
        cluster_id = body.get('cluster_id', '').strip()

        if not k8s_url:   return api_error('k8s_url requis', 400)
        if not token:     return api_error('token requis', 400)
        if not namespace: return api_error('namespace requis', 400)
        if not pod_name:  return api_error('pod_name requis', 400)

        insecure, proxy_url, use_proxy = _pod_proxy_params(cluster_id)
        containers = kubi_service.get_pod_containers(
            k8s_url, token, namespace, pod_name, insecure, proxy_url, use_proxy
        )
        return jsonify({'containers': containers})

    except ServiceError as e:
        return api_error(e.message, e.status)


# === Métriques (metrics-server) ===

@kubi_bp.route('/api/kubi/metrics/pods', methods=['POST'])
def api_kubi_metrics_pods():
    """Métriques CPU/mémoire temps réel des pods d'un namespace (via metrics-server)."""
    try:
        body = _require_json()
        k8s_url   = body.get('k8s_url', '').strip()
        token     = body.get('token', '').strip()
        namespace = body.get('namespace', '').strip()
        cluster_id = body.get('cluster_id', '').strip()

        if not k8s_url:   return api_error('k8s_url requis', 400)
        if not token:     return api_error('token requis', 400)
        if not namespace: return api_error('namespace requis', 400)

        insecure, proxy_url, use_proxy = _pod_proxy_params(cluster_id)
        metrics = kubi_service.get_pod_metrics(
            k8s_url, token, namespace, insecure, proxy_url, use_proxy
        )
        return jsonify({'metrics': metrics})

    except ServiceError as e:
        return api_error(e.message, e.status)


@kubi_bp.route('/api/kubi/metrics/nodes', methods=['POST'])
def api_kubi_metrics_nodes():
    """Métriques CPU/mémoire temps réel des nœuds du cluster (via metrics-server)."""
    try:
        body = _require_json()
        k8s_url   = body.get('k8s_url', '').strip()
        token     = body.get('token', '').strip()
        cluster_id = body.get('cluster_id', '').strip()

        if not k8s_url: return api_error('k8s_url requis', 400)
        if not token:   return api_error('token requis', 400)

        insecure, proxy_url, use_proxy = _pod_proxy_params(cluster_id)
        nodes = kubi_service.get_node_metrics(k8s_url, token, insecure, proxy_url, use_proxy)
        return jsonify({'nodes': nodes})

    except ServiceError as e:
        return api_error(e.message, e.status)


# === Explain (décode un JWT) ===

@kubi_bp.route('/api/kubi/explain', methods=['POST'])
def api_kubi_explain():
    """
    Décode un token JWT (sans authentification).
    ---
    tags: [Kubi]
    parameters:
      - in: body
        schema:
          properties:
            token: {type: string}
    responses:
      200:
        description: Token décodé
    """
    try:
        body = _require_json()
        token = body.get('token', '').strip()
        if not token:
            return api_error('token requis', 400)
        result = kubi_service.decode_token(token)
        return jsonify(result)
    except ServiceError as e:
        return api_error(e.message, e.status)
