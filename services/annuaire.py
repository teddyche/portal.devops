import os
import re
from datetime import datetime
from services.store import load_json, save_json, ServiceError


def _make_id(name: str, existing: list) -> str:
    slug = re.sub(r'[^a-z0-9]+', '_', name.lower().strip())[:40].strip('_') or 'item'
    cid, i = slug, 2
    while cid in existing:
        cid = f'{slug}_{i}'; i += 1
    return cid

def _links_path(d): return os.path.join(d, 'annuaire', 'links.json')
def _cats_path(d):  return os.path.join(d, 'annuaire', 'categories.json')
def _favs_path(d):  return os.path.join(d, 'annuaire', 'favorites.json')

_DEFAULT_CATS = [
    {'id': 'outils',        'name': 'Outils',        'icon': '🛠️', 'color': '#1565c0', 'order': 1},
    {'id': 'documentation', 'name': 'Documentation', 'icon': '📖', 'color': '#2e7d32', 'order': 2},
    {'id': 'monitoring',    'name': 'Monitoring',    'icon': '📊', 'color': '#e65100', 'order': 3},
    {'id': 'cloud_infra',   'name': 'Cloud / Infra', 'icon': '☁️', 'color': '#326ce5', 'order': 4},
    {'id': 'securite',      'name': 'Sécurité',      'icon': '🔐', 'color': '#6a1b9a', 'order': 5},
    {'id': 'portails',      'name': 'Portails',      'icon': '🌐', 'color': '#00838f', 'order': 6},
    {'id': 'autre',         'name': 'Autre',         'icon': '🔗', 'color': '#607d8b', 'order': 99},
]

# ── Categories ────────────────────────────────────────────────

def list_categories(datas_dir):
    cats = load_json(_cats_path(datas_dir))
    if cats is None:
        save_json(_cats_path(datas_dir), _DEFAULT_CATS)
        return list(_DEFAULT_CATS)
    return sorted(cats, key=lambda c: (c.get('order', 99), c.get('name', '')))

def create_category(datas_dir, name, icon='🔗', color='#607d8b', order=99):
    cats = load_json(_cats_path(datas_dir)) or []
    cid = _make_id(name, [c['id'] for c in cats])
    cat = {'id': cid, 'name': name, 'icon': icon, 'color': color, 'order': int(order)}
    cats.append(cat)
    save_json(_cats_path(datas_dir), cats)
    return cat

def update_category(datas_dir, cid, **kw):
    cats = load_json(_cats_path(datas_dir)) or []
    cat = next((c for c in cats if c['id'] == cid), None)
    if not cat: raise ServiceError('Catégorie introuvable', 404)
    for k, v in kw.items():
        if v is not None: cat[k] = v
    save_json(_cats_path(datas_dir), cats)
    return cat

def delete_category(datas_dir, cid):
    cats = load_json(_cats_path(datas_dir)) or []
    save_json(_cats_path(datas_dir), [c for c in cats if c['id'] != cid])
    links = load_json(_links_path(datas_dir)) or []
    for l in links:
        if l.get('category_id') == cid: l['category_id'] = 'autre'
    save_json(_links_path(datas_dir), links)

# ── Links ─────────────────────────────────────────────────────

def list_links(datas_dir, user_id, team_ids, is_admin=False):
    links = load_json(_links_path(datas_dir)) or []
    if is_admin:
        return links
    return [l for l in links if l.get('is_public', True) or not l.get('team_id') or l.get('team_id') in team_ids]

def create_link(datas_dir, name, url, description='', category_id='', tags=None,
                team_id='', is_public=True, created_by=''):
    links = load_json(_links_path(datas_dir)) or []
    lid = _make_id(name, [l['id'] for l in links])
    link = {
        'id': lid, 'name': name, 'url': url,
        'description': description or '', 'category_id': category_id or '',
        'tags': tags or [], 'team_id': team_id or '',
        'is_public': bool(is_public), 'created_by': created_by,
        'created_at': datetime.utcnow().isoformat(),
    }
    links.append(link)
    save_json(_links_path(datas_dir), links)
    return link

def update_link(datas_dir, lid, **kw):
    links = load_json(_links_path(datas_dir)) or []
    link = next((l for l in links if l['id'] == lid), None)
    if not link: raise ServiceError('Lien introuvable', 404)
    for k, v in kw.items():
        if v is not None: link[k] = v
    save_json(_links_path(datas_dir), links)
    return link

def delete_link(datas_dir, lid):
    links = load_json(_links_path(datas_dir)) or []
    save_json(_links_path(datas_dir), [l for l in links if l['id'] != lid])
    # clean from all favorites
    favs = load_json(_favs_path(datas_dir)) or {}
    for uid in favs:
        if lid in favs[uid]: favs[uid].remove(lid)
    save_json(_favs_path(datas_dir), favs)

def get_link(datas_dir, lid):
    links = load_json(_links_path(datas_dir)) or []
    return next((l for l in links if l['id'] == lid), None)

# ── Favorites ─────────────────────────────────────────────────

def get_favorites(datas_dir, user_id):
    return (load_json(_favs_path(datas_dir)) or {}).get(user_id, [])

def toggle_favorite(datas_dir, user_id, lid):
    favs = load_json(_favs_path(datas_dir)) or {}
    lst = favs.get(user_id, [])
    if lid in lst:
        lst.remove(lid); added = False
    else:
        lst.append(lid); added = True
    favs[user_id] = lst
    save_json(_favs_path(datas_dir), favs)
    return added
