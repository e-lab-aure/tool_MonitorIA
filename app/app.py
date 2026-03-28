"""
MonitorIA - Dashboard de monitoring en temps reel.
Surveille les logs SSH, WireGuard, fail2ban et nftables via SSE.
"""

import os
import re
import json
import queue
import smtplib
import threading
import subprocess
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, Response, jsonify, request, stream_with_context

app = Flask(__name__)

# --- Configuration ---

CONFIG_PATH = os.environ.get("CONFIG_PATH", "/app/config/config.json")

DEFAULT_CONFIG = {
    "enabled": False,
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_user": "",
    "smtp_pass": "",
    "recipient": "",
    "alert_on": ["success"]
}

email_config = DEFAULT_CONFIG.copy()

# --- Clients SSE connectes ---

clients: list[queue.Queue] = []
clients_lock = threading.Lock()

# --- Patterns de classification des logs ---

LOG_PATTERNS = [
    {
        "id": "ssh_failure",
        "regex": re.compile(
            r"(Failed password|Invalid user|authentication failure|"
            r"Connection closed by invalid user|BREAK-IN ATTEMPT|"
            r"maximum authentication attempts exceeded|no supported authentication)",
            re.IGNORECASE
        ),
        "type": "failure",
        "service": "SSH"
    },
    {
        "id": "ssh_success",
        "regex": re.compile(
            r"(Accepted password for|Accepted publickey for|session opened for user)",
            re.IGNORECASE
        ),
        "type": "success",
        "service": "SSH"
    },
    {
        "id": "wireguard",
        "regex": re.compile(
            r"(wireguard|wg-quick|wg0).*(handshake|peer|session|allowed ip|interface)",
            re.IGNORECASE
        ),
        "type": "wireguard",
        "service": "WireGuard"
    },
    {
        "id": "fail2ban_ban",
        "regex": re.compile(r"fail2ban.*\sBan\s+[\d\.]+", re.IGNORECASE),
        "type": "ban",
        "service": "fail2ban"
    },
    {
        "id": "fail2ban_unban",
        "regex": re.compile(r"fail2ban.*\sUnban\s+[\d\.]+", re.IGNORECASE),
        "type": "unban",
        "service": "fail2ban"
    },
    {
        "id": "nftables",
        "regex": re.compile(r"(nft\s|nftables|IN=\S+\s+OUT=)", re.IGNORECASE),
        "type": "nftables",
        "service": "nftables"
    }
]


def classify_line(line: str) -> tuple[str, str]:
    """
    Identifie le type et le service associe a une ligne de log.
    Retourne (type, service) parmi les patterns definis.
    """
    for pattern in LOG_PATTERNS:
        if pattern["regex"].search(line):
            return pattern["type"], pattern["service"]
    return "normal", "system"


def broadcast(entry: dict) -> None:
    """
    Diffuse un evenement de log a tous les clients SSE actifs.
    Supprime les queues des clients deconnectes (queue pleine).
    """
    with clients_lock:
        dead = []
        for q in clients:
            try:
                q.put_nowait(entry)
            except queue.Full:
                dead.append(q)
        for q in dead:
            clients.remove(q)


def send_alert(entry: dict) -> None:
    """
    Envoie une alerte mail si l'evenement correspond aux criteres configures.
    L'envoi est effectue dans un thread separe pour ne pas bloquer le flux de logs.
    """
    if not email_config.get("enabled"):
        return
    alert_on = email_config.get("alert_on", ["success"])
    if entry["type"] not in alert_on:
        return

    def _send() -> None:
        try:
            msg = MIMEMultipart()
            msg["From"] = email_config["smtp_user"]
            msg["To"] = email_config["recipient"]
            msg["Subject"] = f"[MonitorIA] {entry['service']} - {entry['type'].upper()}"
            body = (
                f"Evenement detecte sur votre serveur :\n\n"
                f"Service : {entry['service']}\n"
                f"Type    : {entry['type']}\n"
                f"Heure   : {entry['timestamp']}\n\n"
                f"Ligne   : {entry['line']}"
            )
            msg.attach(MIMEText(body, "plain"))
            with smtplib.SMTP(email_config["smtp_host"], int(email_config["smtp_port"])) as server:
                server.starttls()
                server.login(email_config["smtp_user"], email_config["smtp_pass"])
                server.sendmail(email_config["smtp_user"], email_config["recipient"], msg.as_string())
            app.logger.info(f"[INFO] Alerte mail envoyee pour {entry['service']} - {entry['type']}")
        except smtplib.SMTPException as exc:
            app.logger.error(f"[ERROR] Envoi mail SMTP echoue : {exc}")
        except Exception as exc:
            app.logger.error(f"[ERROR] Envoi mail echoue : {exc}")

    threading.Thread(target=_send, daemon=True).start()


def process_line(line: str, fallback_service: str = None) -> None:
    """
    Traite une ligne de log brute : classification, diffusion SSE et alerte mail.
    fallback_service est utilise si la classification retourne 'system'.
    """
    line = line.strip()
    if not line:
        return

    log_type, service = classify_line(line)
    if fallback_service and service == "system":
        service = fallback_service

    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "line": line,
        "type": log_type,
        "service": service
    }
    broadcast(entry)
    send_alert(entry)


def tail_journald() -> None:
    """
    Surveille les journaux systemd des services cibles via journalctl.
    Redemarre automatiquement en cas de crash du processus.
    """
    units = ["-u", "ssh", "-u", "sshd", "-u", "wg-quick@wg0", "-u", "fail2ban"]
    cmd = ["journalctl", "-f", "-n", "100", "--no-pager", "--output=short-iso"] + units

    app.logger.info(f"[INFO] Demarrage surveillance journalctl")

    while True:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            for line in proc.stdout:
                process_line(line)
            proc.wait()
            app.logger.warning("[WARNING] journalctl s'est arrete, redemarrage dans 5s")
        except FileNotFoundError:
            app.logger.warning("[WARNING] journalctl non disponible - passage aux fichiers de logs")
            break
        except Exception as exc:
            app.logger.error(f"[ERROR] journalctl : {exc}")
        time.sleep(5)


def tail_file(filepath: str, service: str) -> None:
    """
    Surveille un fichier de log en continu (lecture de fin de fichier).
    Utilise comme fallback si journalctl est indisponible.
    """
    app.logger.info(f"[INFO] Surveillance fichier : {filepath}")

    while True:
        try:
            with open(filepath, "r", errors="replace") as f:
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if line:
                        process_line(line, fallback_service=service)
                    else:
                        time.sleep(0.1)
        except FileNotFoundError:
            app.logger.warning(f"[WARNING] Fichier introuvable : {filepath} - nouvelle tentative dans 30s")
            time.sleep(30)
        except PermissionError:
            app.logger.error(f"[ERROR] Permission refusee pour lire : {filepath}")
            break
        except Exception as exc:
            app.logger.error(f"[ERROR] Lecture {filepath} : {exc}")
            time.sleep(5)


def start_log_watchers() -> None:
    """
    Demarre tous les threads de surveillance des logs.
    Tente journalctl en priorite, puis les fichiers de logs en parallele.
    """
    threading.Thread(target=tail_journald, daemon=True).start()

    # Fichiers surveilles en complement (couvrent fail2ban, nftables, acces SSH)
    log_files = [
        ("/var/log/fail2ban.log", "fail2ban"),
        ("/var/log/auth.log", "SSH"),
        ("/var/log/secure", "SSH"),
        ("/var/log/kern.log", "nftables"),
        ("/var/log/syslog", "system"),
    ]
    for filepath, service in log_files:
        if os.path.exists(filepath):
            threading.Thread(target=tail_file, args=(filepath, service), daemon=True).start()


def load_config() -> None:
    """Charge la configuration email depuis le fichier JSON persistant."""
    global email_config
    try:
        with open(CONFIG_PATH, "r") as f:
            saved = json.load(f)
            email_config.update(saved)
        app.logger.info("[INFO] Configuration email chargee")
    except FileNotFoundError:
        app.logger.info("[INFO] Aucune configuration existante - valeurs par defaut appliquees")
    except (json.JSONDecodeError, IOError) as exc:
        app.logger.error(f"[ERROR] Chargement configuration : {exc}")


def save_config() -> None:
    """Sauvegarde la configuration email dans le fichier JSON persistant."""
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(email_config, f, indent=2)
        app.logger.info("[INFO] Configuration email sauvegardee")
    except IOError as exc:
        app.logger.error(f"[ERROR] Sauvegarde configuration : {exc}")


# --- Routes Flask ---

@app.route("/")
def index():
    """Page principale du dashboard."""
    return render_template("index.html")


@app.route("/stream")
def stream():
    """
    Endpoint SSE : diffuse les evenements de logs en temps reel.
    Chaque client recoit sa propre queue pour eviter les pertes d'evenements.
    """
    client_queue: queue.Queue = queue.Queue(maxsize=200)

    with clients_lock:
        clients.append(client_queue)

    active = len(clients)
    app.logger.info(f"[INFO] Nouveau client SSE connecte ({active} actif(s))")

    def event_stream():
        try:
            while True:
                try:
                    entry = client_queue.get(timeout=30)
                    yield f"data: {json.dumps(entry)}\n\n"
                except queue.Empty:
                    # Keepalive pour maintenir la connexion ouverte
                    yield 'data: {"type":"ping"}\n\n'
        finally:
            with clients_lock:
                if client_queue in clients:
                    clients.remove(client_queue)
            app.logger.info(f"[INFO] Client SSE deconnecte ({len(clients)} actif(s))")

    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive"
        }
    )


@app.route("/api/config", methods=["GET"])
def get_config():
    """
    Retourne la configuration email actuelle.
    Le mot de passe n'est jamais expose : remplace par un indicateur booleen.
    """
    safe = {k: v for k, v in email_config.items() if k != "smtp_pass"}
    safe["smtp_pass_set"] = bool(email_config.get("smtp_pass"))
    return jsonify(safe)


@app.route("/api/config", methods=["POST"])
def set_config():
    """
    Met a jour et persiste la configuration email.
    Si smtp_pass est absent ou vide, le mot de passe existant est conserve.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Corps JSON invalide"}), 400

    # Preservation du mot de passe si non fourni dans la requete
    if not data.get("smtp_pass") and email_config.get("smtp_pass"):
        data["smtp_pass"] = email_config["smtp_pass"]

    email_config.update(data)
    save_config()
    return jsonify({"status": "ok"})


@app.route("/api/test-email", methods=["POST"])
def test_email():
    """Envoie un email de test pour valider la configuration SMTP."""
    if not email_config.get("smtp_host") or not email_config.get("recipient"):
        return jsonify({"error": "Configuration SMTP incomplete"}), 400

    try:
        msg = MIMEText("Ceci est un email de test envoye par MonitorIA. La configuration est correcte.")
        msg["From"] = email_config["smtp_user"]
        msg["To"] = email_config["recipient"]
        msg["Subject"] = "[MonitorIA] Test de configuration"

        with smtplib.SMTP(email_config["smtp_host"], int(email_config["smtp_port"])) as server:
            server.starttls()
            server.login(email_config["smtp_user"], email_config["smtp_pass"])
            server.sendmail(email_config["smtp_user"], email_config["recipient"], msg.as_string())

        app.logger.info("[INFO] Email de test envoye avec succes")
        return jsonify({"status": "ok"})
    except smtplib.SMTPAuthenticationError:
        return jsonify({"error": "Authentification SMTP echouee - verifiez les identifiants"}), 500
    except smtplib.SMTPException as exc:
        app.logger.error(f"[ERROR] Test email SMTP : {exc}")
        return jsonify({"error": f"Erreur SMTP : {exc}"}), 500
    except Exception as exc:
        app.logger.error(f"[ERROR] Test email : {exc}")
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    load_config()
    start_log_watchers()
    app.logger.info("[INFO] MonitorIA demarre sur le port 8080")
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
