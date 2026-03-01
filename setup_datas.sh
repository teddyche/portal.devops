#!/usr/bin/env bash
# ==============================================================================
# setup_datas.sh — Initialisation du dossier datas/ depuis datas_exemple/
# Usage : bash setup_datas.sh
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SCRIPT_DIR/datas_exemple"
DST="$SCRIPT_DIR/datas"

if [ -d "$DST" ]; then
    echo "⚠️  Le dossier datas/ existe déjà."
    read -rp "   Écraser ? (o/N) : " confirm
    if [[ "$confirm" != "o" && "$confirm" != "O" ]]; then
        echo "Annulé."
        exit 0
    fi
fi

cp -r "$SRC/." "$DST"
echo "✅  datas/ initialisé depuis datas_exemple/"
echo ""
echo "📝  À personnaliser dans datas/auth/config.json :"
echo "    - secret_key       → générer avec : python -c \"import secrets; print(secrets.token_hex(32))\""
echo "    - local_admin      → changer le password_hash (mdp par défaut : 'admin')"
echo "    - adfs             → renseigner client_id / client_secret si ADFS activé"
echo "    - ldap             → renseigner host / base_dn / bind_dn_template"
echo ""
echo "🔐  Générer un nouveau hash de mot de passe :"
echo "    python -c \"import bcrypt; print(bcrypt.hashpw(b'MONMOTDEPASSE', bcrypt.gensalt(12)).decode())\""
