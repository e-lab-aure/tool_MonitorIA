# Image de base minimaliste Python 3.12
FROM python:3.12-slim

# Metadonnees
LABEL maintainer="MonitorIA" \
      description="Dashboard de monitoring SSH/WireGuard/fail2ban"

WORKDIR /app

# Installation de systemd (binaire journalctl) et curl (HEALTHCHECK).
# systemd ne tourne pas comme PID 1 - seul le binaire journalctl est utilise.
# curl sert uniquement a la sonde de sante du container.
RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd \
        curl \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

# Fuseau horaire : herite de TZ si defini au lancement (podman run -e TZ=Europe/Paris),
# sinon Europe/Paris par defaut.
ENV TZ=Europe/Paris
RUN ln -snf /usr/share/zoneinfo/${TZ} /etc/localtime && echo ${TZ} > /etc/timezone

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code applicatif
COPY app/ .

# Repertoire de persistance de la configuration email
RUN mkdir -p /app/config

EXPOSE 8080

# Sonde de sante : interroge /health toutes les 30s.
# Si 3 echecs consecutifs (timeout 5s chacun), le container passe en "unhealthy".
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Lancement du serveur Flask en mode multithreade
CMD ["python", "app.py"]
