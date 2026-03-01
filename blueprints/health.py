"""
Blueprint monitoring : health check et métriques Prometheus.
"""
import os
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify

health_bp = Blueprint('health', __name__)


@health_bp.route('/api/health')
def api_health():
    """
    Health check de l'application.
    ---
    tags:
      - Monitoring
    responses:
      200:
        description: Service opérationnel
        schema:
          properties:
            status:
              type: string
              example: ok
            version:
              type: string
              example: "1.0.0"
            timestamp:
              type: string
              format: date-time
            datas_dir_ok:
              type: boolean
    """
    datas_dir = current_app.config.get('DATAS_DIR', '')
    return jsonify({
        'status': 'ok',
        'version': '1.0.0',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'datas_dir_ok': os.path.isdir(datas_dir),
    })
