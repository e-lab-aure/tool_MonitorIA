#!/bin/bash
# run.sh - Construit et lance le container MonitorIA

set -e

IMAGE="monitoria:latest"
CONTAINER="monitoria"
CONFIG_DIR="$(pwd)/config"

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
#   /var/log          - fichiers de logs systemd, fail2ban, auth.log
#   /run/systemd/...  - socket journald pour journalctl dans le container
#   ./config          - persistance de la configuration email
#
# L'option :z applique le bon label SELinux si necessaire (systemes avec SELinux actif)

echo "[INFO] Demarrage du container $CONTAINER sur le port 8080..."

podman run -d \
    --name "$CONTAINER" \
    -p 8080:8080 \
    -v /var/log:/var/log:ro,z \
    -v /run/systemd/journal:/run/systemd/journal:ro,z \
    -v "$CONFIG_DIR":/app/config:z \
    --restart unless-stopped \
    "$IMAGE"

echo "[OK] MonitorIA demarre - http://localhost:8080"
echo "[INFO] Logs du container : podman logs -f $CONTAINER"
