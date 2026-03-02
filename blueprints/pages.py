"""
Routes pages statiques : retournent les fichiers HTML du dossier pages/.
"""
import os

from flask import Blueprint, abort, current_app, send_file

import services.cad as cad_service
import services.sre as sre_service
import services.pssit as pssit_service
import services.kubi as kubi_service

pages_bp = Blueprint('pages', __name__)


def _pages_dir() -> str:
    return current_app.config['PAGES_DIR']


def _datas_dir() -> str:
    return current_app.config['DATAS_DIR']


def _page(filename: str):
    return send_file(os.path.join(_pages_dir(), filename))


# === Routes générales ===

@pages_bp.route('/')
def home():
    return _page('home.html')


@pages_bp.route('/sre')
def landing():
    return _page('landing.html')


@pages_bp.route('/ldap-checker')
def ldap_checker():
    return _page('ldap_checker.html')


@pages_bp.route('/admin')
def admin():
    return _page('admin.html')


@pages_bp.route('/auth-admin')
def auth_admin_page():
    return _page('auth_admin.html')


# === Routes SRE Clusters ===

@pages_bp.route('/cluster/<cluster_id>')
def cluster_dashboard(cluster_id: str):
    if not sre_service.cluster_exists(_datas_dir(), cluster_id):
        abort(404)
    return _page('dashboard.html')


@pages_bp.route('/cluster/<cluster_id>/config')
def cluster_config_page(cluster_id: str):
    if not sre_service.cluster_exists(_datas_dir(), cluster_id):
        abort(404)
    return _page('config.html')


@pages_bp.route('/cluster/<cluster_id>/autoscore')
def cluster_autoscore(cluster_id: str):
    if not sre_service.cluster_exists(_datas_dir(), cluster_id):
        abort(404)
    return _page('autoscore.html')


@pages_bp.route('/cluster/<cluster_id>/autoscore-config')
def cluster_autoscore_config(cluster_id: str):
    if not sre_service.cluster_exists(_datas_dir(), cluster_id):
        abort(404)
    return _page('autoscore_config.html')


@pages_bp.route('/cluster/<cluster_id>/board')
def cluster_board(cluster_id: str):
    if not sre_service.cluster_exists(_datas_dir(), cluster_id):
        abort(404)
    return _page('board.html')


# === Routes CAD ===

@pages_bp.route('/cad')
def cad_landing():
    return _page('cad_landing.html')


@pages_bp.route('/cad/admin')
def cad_admin():
    return _page('cad_admin.html')


@pages_bp.route('/cad/workspace/<ws_id>')
def cad_dashboard(ws_id: str):
    if not cad_service.cad_ws_exists(_datas_dir(), ws_id):
        abort(404)
    return _page('dashboard.html')


@pages_bp.route('/cad/workspace/<ws_id>/config')
def cad_config_page(ws_id: str):
    if not cad_service.cad_ws_exists(_datas_dir(), ws_id):
        abort(404)
    return _page('config.html')


@pages_bp.route('/cad/workspace/<ws_id>/board')
def cad_board(ws_id: str):
    if not cad_service.cad_ws_exists(_datas_dir(), ws_id):
        abort(404)
    return _page('board.html')


# === Routes PSSIT ===

@pages_bp.route('/pssit')
def pssit_landing():
    return _page('pssit_landing.html')


@pages_bp.route('/pssit/admin')
def pssit_admin():
    return _page('pssit_admin.html')


@pages_bp.route('/pssit/app/<app_id>')
def pssit_app_detail(app_id: str):
    if not pssit_service.pssit_app_exists(_datas_dir(), app_id):
        abort(404)
    return _page('pssit_app.html')


@pages_bp.route('/pssit/app/<app_id>/config')
def pssit_app_config(app_id: str):
    if not pssit_service.pssit_app_exists(_datas_dir(), app_id):
        abort(404)
    return _page('pssit_config.html')


# === Routes Kubi ===

@pages_bp.route('/kubi')
def kubi_page():
    return _page('kubi.html')


@pages_bp.route('/kubi/config')
def kubi_config_page():
    return _page('kubi_config.html')
