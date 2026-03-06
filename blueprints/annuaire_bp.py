from flask import Blueprint, g, request, jsonify, current_app
from auth import get_user_teams, is_admin as auth_is_admin
from services.store import ServiceError
import services.annuaire as svc

annuaire_bp = Blueprint('annuaire', __name__)

def _dd():     return current_app.config['DATAS_DIR']
def _user():   return g.current_user
def _uid():    return _user()['id']
def _tids():   return [t['id'] for t in get_user_teams(_uid())]
def _admin():  return auth_is_admin(_uid())
def _err(msg, s=400): return jsonify({'error': msg}), s

def _require_json():
    if not request.json: return _err('JSON requis')

# ── Categories ────────────────────────────────────────────────

@annuaire_bp.route('/api/annuaire/categories', methods=['GET'])
def api_get_cats():
    return jsonify({'categories': svc.list_categories(_dd())})

@annuaire_bp.route('/api/annuaire/categories', methods=['POST'])
def api_create_cat():
    if not _admin(): return _err('Admin requis', 403)
    b = request.json or {}
    name = (b.get('name') or '').strip()
    if not name: return _err('Nom requis')
    cat = svc.create_category(_dd(), name, b.get('icon', '🔗'), b.get('color', '#607d8b'), b.get('order', 99))
    return jsonify(cat), 201

@annuaire_bp.route('/api/annuaire/categories/<cid>', methods=['PUT'])
def api_update_cat(cid):
    if not _admin(): return _err('Admin requis', 403)
    b = request.json or {}
    try:
        return jsonify(svc.update_category(_dd(), cid, **{k: b.get(k) for k in ('name','icon','color','order')}))
    except ServiceError as e: return _err(e.message, e.status)

@annuaire_bp.route('/api/annuaire/categories/<cid>', methods=['DELETE'])
def api_delete_cat(cid):
    if not _admin(): return _err('Admin requis', 403)
    try:
        svc.delete_category(_dd(), cid)
        return jsonify({'ok': True})
    except ServiceError as e: return _err(e.message, e.status)

# ── Links ─────────────────────────────────────────────────────

@annuaire_bp.route('/api/annuaire/links', methods=['GET'])
def api_get_links():
    links = svc.list_links(_dd(), _uid(), _tids(), _admin())
    favs  = svc.get_favorites(_dd(), _uid())
    for l in links: l['is_favorite'] = l['id'] in favs
    return jsonify({'links': links})

@annuaire_bp.route('/api/annuaire/links', methods=['POST'])
def api_create_link():
    b = request.json or {}
    name = (b.get('name') or '').strip()
    url  = (b.get('url')  or '').strip()
    if not name: return _err('Nom requis')
    if not url:  return _err('URL requise')
    link = svc.create_link(
        _dd(), name, url,
        description=b.get('description', ''),
        category_id=b.get('category_id', ''),
        tags=b.get('tags', []),
        team_id=b.get('team_id', ''),
        is_public=b.get('is_public', True),
        created_by=_uid(),
    )
    return jsonify(link), 201

@annuaire_bp.route('/api/annuaire/links/<lid>', methods=['PUT'])
def api_update_link(lid):
    link = svc.get_link(_dd(), lid)
    if not link: return _err('Lien introuvable', 404)
    if link['created_by'] != _uid() and not _admin(): return _err('Non autorisé', 403)
    b = request.json or {}
    try:
        updated = svc.update_link(_dd(), lid,
            name=b.get('name'), url=b.get('url'),
            description=b.get('description'), category_id=b.get('category_id'),
            tags=b.get('tags'), team_id=b.get('team_id'), is_public=b.get('is_public'))
        return jsonify(updated)
    except ServiceError as e: return _err(e.message, e.status)

@annuaire_bp.route('/api/annuaire/links/<lid>', methods=['DELETE'])
def api_delete_link(lid):
    link = svc.get_link(_dd(), lid)
    if not link: return _err('Lien introuvable', 404)
    if link['created_by'] != _uid() and not _admin(): return _err('Non autorisé', 403)
    svc.delete_link(_dd(), lid)
    return jsonify({'ok': True})

# ── Favorites ─────────────────────────────────────────────────

@annuaire_bp.route('/api/annuaire/links/<lid>/favorite', methods=['POST'])
def api_toggle_fav(lid):
    added = svc.toggle_favorite(_dd(), _uid(), lid)
    return jsonify({'ok': True, 'added': added})
