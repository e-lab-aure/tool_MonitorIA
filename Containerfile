# Image de base minimaliste Python 3.12
FROM python:3.12-slim

# Metadonnees
LABEL maintainer="MonitorIA" \
      description="Dashboard de monitoring SSH/WireGuard/fail2ban"

WORKDIR /app

# Installation de systemd pour disposer du binaire journalctl.
# Necessaire sur les systemes sans auth.log (journald pur, sans rsyslog).
# systemd ne tourne pas comme PID 1 - seul le binaire journalctl est utilise.
RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd \
    && rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code applicatif
COPY app/ .

# Repertoire de persistance de la configuration email
RUN mkdir -p /app/config

EXPOSE 8080

# Lancement du serveur Flask en mode multithreade
CMD ["python", "app.py"]
