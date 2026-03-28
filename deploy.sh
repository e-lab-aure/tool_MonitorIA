#!/bin/bash
# deploy.sh - Construit et lance le container MonitorIA

set -e

IMAGE="monitoria:latest"
CONTAINER="monitoria"
CONFIG_DIR="/opt/tool_MonitorIA/config"

# Creation du repertoire de configuration si absent
mkdir -p "$CONFIG_DIR"

# Arret et suppression du container existant si necessaire
if podman container exists "$CONTAINER" 2>/dev/null; then
    echo "[INFO] Arret du container existant..."
    podman stop "$CONTAINER" 2>/dev/null || true
    podman rm "$CONTAINER" 2>/dev/null || true
fi

# Construction de l'image
echo "[INFO] Construction de l'image $IMAGE..."
podman build -t "$IMAGE" -f Containerfile .

# Lancement du container avec acces aux logs du systeme hote
#
# Volumes montes :
#   /var/log              - fichiers de logs (fail2ban, kern, etc.)
#   /run/systemd/journal  - socket journald pour journalctl dans le container
#   $CONFIG_DIR           - persistance de la configuration email
#
# --group-add keep-groups : le container herite des groupes supplementaires de
#   l'utilisateur hote (ex: adm), ce qui permet de lire fail2ban.log (root:adm 640)
# L'option :z applique le bon label SELinux si necessaire

echo "[INFO] Demarrage du container $CONTAINER sur le port 8080..."

podman run -d \
    --name "$CONTAINER" \
    -p 8080:8080 \
    -v /var/log:/var/log:ro,z \
    -v /run/systemd/journal:/run/systemd/journal:ro,z \
    -v "$CONFIG_DIR":/app/config:z \
    --group-add keep-groups \
    --restart unless-stopped \
    "$IMAGE"

echo "[OK] MonitorIA demarre - http://localhost:8080"
echo "[INFO] Logs du container : podman logs -f $CONTAINER"
