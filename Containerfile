# Image de base minimaliste Python 3.12
FROM python:3.12-slim

# Metadonnees
LABEL maintainer="MonitorIA" \
      description="Dashboard de monitoring SSH/WireGuard/fail2ban"

WORKDIR /app

# Dependances Python uniquement - pas de systemd dans le container.
# L'acces aux logs se fait par lecture directe de /var/log monte depuis l'hote,
# avec fallback sur journalctl si le socket journal est monte.
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code applicatif
COPY app/ .

# Repertoire de persistance de la configuration email
RUN mkdir -p /app/config

EXPOSE 8080

# Lancement du serveur Flask en mode multithreade
CMD ["python", "app.py"]
