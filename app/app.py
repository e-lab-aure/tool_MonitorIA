"""
MonitorIA - Dashboard de monitoring en temps reel.
Surveille les logs SSH, WireGuard, fail2ban et nftables via SSE.
"""

import atexit
import copy
import csv
import io
import ipaddress
import os
import re
import json
import queue
import signal
import smtplib
import sys
import threading
import subprocess
import time
import logging
from collections import deque
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, Response, jsonify, request, stream_with_context

app = Flask(__name__)

# Flask passe le logger en WARNING par defaut - forcer INFO pour voir les
# messages de demarrage des threads de surveillance dans podman logs.
logging.basicConfig(level=logging.INFO, format="%(message)s")
app.logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CONFIG_PATH    = os.environ.get("CONFIG_PATH",    "/app/config/config.json")
IP_STATS_PATH  = os.environ.get("IP_STATS_PATH",  "/app/config/ip_stats.json")
BLOCKLIST_PATH = os.environ.get("BLOCKLIST_PATH", "/app/config/blocklist.json")
IP_LOGS_DIR    = os.environ.get("IP_LOGS_DIR",    "/app/config/ip_logs")

# Table nftables geree par MonitorIA (creee automatiquement si absente)
NFT_TABLE = "monitoria"
NFT_SET   = "blocklist"

# Taille maximale du dossier de logs IP (1 Go)
IP_LOGS_MAX_BYTES = 1 * 1024 * 1024 * 1024

# Duree de retention des stats IP : buckets plus vieux purges a la sauvegarde
RETENTION_DAYS = 7

# Seuils de classification des menaces par IP
BRUTE_FORCE_MIN_COUNT = 20  # Tentatives sur un seul service -> brute force
SCAN_MIN_SERVICES     = 2   # Services distincts cibles     -> scan

# Delai minimum entre deux alertes mail du meme type (evite le flood)
ALERT_COOLDOWN_SECONDS = 300  # 5 minutes

# Nombre maximum d'evenements conserves en memoire pour l'export CSV
EVENT_BUFFER_MAXLEN = 1000

# Nombre de lignes de log brutes conservees par IP pour le contexte des attaques
CONTEXT_LINES_MAX = 10

# Port UDP WireGuard (51820 par defaut, surchargeable via variable d'environnement)
WG_PORT = re.escape(os.environ.get("WG_PORT", "51820"))

DEFAULT_CONFIG = {
    "enabled":       False,
    "smtp_host":     "",
    "smtp_port":     587,
    "smtp_security": "starttls",
    "smtp_user":     "",
    "smtp_pass":     "",
    "recipient":     "",
    "alert_on":      ["success"],
    "whitelist": {
        "cidrs":    ["127.0.0.0/8", "::1", "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"],
        "ips":      [],
        "patterns": []
    },
    "exception_rules": []
}

email_config: dict = DEFAULT_CONFIG.copy()

# Heure de demarrage de l'application (pour l'endpoint /health)
_start_time = datetime.now(timezone.utc)

# ---------------------------------------------------------------------------
# Clients SSE connectes
# ---------------------------------------------------------------------------

clients: list[queue.Queue] = []
clients_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Buffer circulaire des evenements recents (export CSV)
# ---------------------------------------------------------------------------

_event_buffer: deque = deque(maxlen=EVENT_BUFFER_MAXLEN)
_buffer_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Whitelist IP : IPs/CIDRs/patterns exclus du suivi des menaces
# ---------------------------------------------------------------------------

_whitelist_cidrs:    list = []
_whitelist_ips:      set  = set()
_whitelist_patterns: list = []
_whitelist_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Patterns de classification des logs
# ---------------------------------------------------------------------------

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
        # Connexion WireGuard aboutie :
        # "Sending handshake response" = serveur a authentifie le pair et repond.
        # "Keypair created"            = tunnel chiffre operationnel.
        # "Sending handshake initiation" = reconnexion / keepalive sortant.
        # NB : "Receiving handshake initiation" est le DEBUT du handshake (pas encore etabli)
        #      -> tombe dans le pattern generique ci-dessous.
        "id": "wireguard_success",
        "regex": re.compile(
            r"(wireguard|wg\d+).*(Sending handshake response to peer|"
            r"Sending handshake initiation to peer|Keypair \d+ created for peer)",
            re.IGNORECASE
        ),
        "type": "wireguard_success",
        "service": "WireGuard"
    },
    {
        # Tentative invalide ou paquet rejete :
        # "Invalid handshake initiation from"         = source inconnue (aucun pair correspondant).
        # "Invalid MAC of handshake, dropping packet" = MAC incorrecte (paquet corrompu ou usurpe).
        # "unallowed src IP"                          = paquet depuis une IP non declaree pour ce pair.
        # "replay attack"                             = paquet rejoue detecte.
        "id": "wireguard_failure",
        "regex": re.compile(
            r"(wireguard|wg\d+).*(Invalid handshake initiation|Invalid MAC of handshake|"
            r"unallowed src IP|replay attack|too many sessions)",
            re.IGNORECASE
        ),
        "type": "wireguard_failure",
        "service": "WireGuard"
    },
    {
        # Paquets UDP vers le port WireGuard loggues par nftables.
        # Correspond au prefixe recommande [wireguard-*] ou a DPT=<port> PROTO=UDP.
        "id": "wireguard_nftables",
        "regex": re.compile(
            rf"\[wireguard[^\]]*\]|(?:PROTO=UDP.*\bDPT={WG_PORT}\b|\bDPT={WG_PORT}\b.*PROTO=UDP)",
            re.IGNORECASE
        ),
        "type": "wireguard",
        "service": "WireGuard"
    },
    {
        # Autres evenements generiques du module WireGuard ou du service wg-quick.
        # wg-quick\S* matche le nom de processus tel que journald le formate (ex: wg-quick[1234]:),
        # ce qui couvre les commandes emises par wg-quick sans mot-cle supplementaire.
        "id": "wireguard",
        "regex": re.compile(
            r"wg-quick\S*|"
            r"(wireguard|wg\d+).*(handshake|peer|session|allowed ip|interface|"
            r"keypair|endpoint|roaming|destroying|cookie|no route)",
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
    Retourne (type, service) parmi les patterns definis, ou ('normal', 'system').
    """
    for pattern in LOG_PATTERNS:
        if pattern["regex"].search(line):
            return pattern["type"], pattern["service"]
    return "normal", "system"


def broadcast(entry: dict) -> None:
    """
    Diffuse un evenement de log a tous les clients SSE actifs et l'enregistre
    dans le buffer circulaire (utilise pour l'export CSV).
    Supprime les queues des clients deconnectes (queue pleine = client lent ou parti).
    """
    with _buffer_lock:
        _event_buffer.appendleft(entry)

    with clients_lock:
        dead = []
        for q in clients:
            try:
                q.put_nowait(entry)
            except queue.Full:
                dead.append(q)
        for q in dead:
            clients.remove(q)


# ---------------------------------------------------------------------------
# Alertes mail
# ---------------------------------------------------------------------------

_alert_lock     = threading.Lock()
# Derniere alerte envoyee par type d'evenement - evite le flood pendant une attaque
_alert_cooldown: dict[str, datetime] = {}

# Historique des alertes mail envoyees (100 dernieres)
ALERT_LOG_MAXLEN = 100
_alert_log: deque = deque(maxlen=ALERT_LOG_MAXLEN)
_alert_log_lock = threading.Lock()


def _compile_whitelist() -> None:
    """
    Parse la section whitelist de email_config en structures de recherche rapide.
    Appele apres chaque chargement ou sauvegarde de la configuration.
    """
    global _whitelist_cidrs, _whitelist_ips, _whitelist_patterns
    wl = email_config.get("whitelist", {})
    cidrs = []
    for cidr in wl.get("cidrs", []):
        try:
            cidrs.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            app.logger.warning(f"[WARNING] Whitelist CIDR invalide ignore : {cidr}")
    ips = set(wl.get("ips", []))
    patterns = []
    for pat in wl.get("patterns", []):
        try:
            patterns.append(re.compile(pat))
        except re.error:
            app.logger.warning(f"[WARNING] Whitelist pattern regex invalide ignore : {pat}")
    with _whitelist_lock:
        _whitelist_cidrs    = cidrs
        _whitelist_ips      = ips
        _whitelist_patterns = patterns


def is_whitelisted(ip: str) -> bool:
    """
    Retourne True si l'IP correspond a une entree de la whitelist.
    Thread-safe via _whitelist_lock.
    """
    with _whitelist_lock:
        if ip in _whitelist_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            for net in _whitelist_cidrs:
                if addr in net:
                    return True
        except ValueError:
            pass
        for pat in _whitelist_patterns:
            if pat.search(ip):
                return True
    return False


_RE_SSH_USER = re.compile(r'\bfor\s+(\S+)\s+from\b', re.IGNORECASE)


def _extract_user(line: str) -> str | None:
    """Extrait le nom d'utilisateur d'une ligne de log SSH."""
    m = _RE_SSH_USER.search(line)
    return m.group(1) if m else None


def matches_exception_rule(log_type: str, ip: str | None, line: str) -> bool:
    """
    Retourne True si l'evenement correspond a une regle d'exception configuree.
    Chaque regle est un dict avec les cles optionnelles : type, user_pattern, src_pattern.
    Toutes les cles presentes dans une regle doivent correspondre (ET).
    Plusieurs regles sont evaluees en OU.
    Exemple de regle pour filtrer les connexions root locales des crons :
      {"type": "success", "user_pattern": "root", "src_pattern": "127\\."}
    """
    rules = email_config.get("exception_rules", [])
    if not rules:
        return False
    user = _extract_user(line)
    for rule in rules:
        rule_type = rule.get("type")
        if rule_type and rule_type != log_type:
            continue
        user_pat = rule.get("user_pattern")
        if user_pat:
            if not user or not re.search(user_pat, user):
                continue
        src_pat = rule.get("src_pattern")
        if src_pat:
            if not ip or not re.search(src_pat, ip):
                continue
        return True
    return False


def smtp_send(msg: MIMEMultipart) -> None:
    """
    Envoie un message SMTP en respectant le mode de securite configure.
    - ssl      : connexion directement chiffree via SMTP_SSL (port 465)
    - starttls : connexion en clair puis upgrade TLS (port 587)
    - none     : connexion en clair sans chiffrement (deconseille)
    """
    host     = email_config["smtp_host"]
    port     = int(email_config["smtp_port"])
    user     = email_config["smtp_user"]
    password = email_config["smtp_pass"]
    security = email_config.get("smtp_security", "starttls")

    if security == "ssl":
        with smtplib.SMTP_SSL(host, port) as server:
            server.login(user, password)
            server.sendmail(msg["From"], msg["To"], msg.as_string())
    elif security == "starttls":
        with smtplib.SMTP(host, port) as server:
            server.starttls()
            server.login(user, password)
            server.sendmail(msg["From"], msg["To"], msg.as_string())
    else:
        with smtplib.SMTP(host, port) as server:
            server.login(user, password)
            server.sendmail(msg["From"], msg["To"], msg.as_string())


def send_alert(entry: dict) -> None:
    """
    Envoie une alerte mail si l'evenement correspond aux criteres configures.
    Un cooldown de ALERT_COOLDOWN_SECONDS evite le flood d'emails pour un meme
    type d'evenement (ex: attaque par brute force SSH generant des centaines
    d'echecs). L'envoi est effectue dans un thread separe pour ne pas bloquer
    le flux de logs.
    Les evenements en whitelist ou correspondant a une regle d'exception sont ignores.
    """
    if not email_config.get("enabled"):
        return
    alert_on = email_config.get("alert_on", ["success"])
    if entry["type"] not in alert_on:
        return

    # Ne pas alerter pour les IPs en liste blanche ou matchant une regle d'exception
    line = entry.get("line", "")
    ip   = extract_ip(line)
    if ip and is_whitelisted(ip):
        return
    if matches_exception_rule(entry["type"], ip, line):
        return

    # Deduplication : une alerte par type d'evenement max toutes les 5 minutes
    now = datetime.now(timezone.utc)
    with _alert_lock:
        last = _alert_cooldown.get(entry["type"])
        if last and (now - last).total_seconds() < ALERT_COOLDOWN_SECONDS:
            return
        _alert_cooldown[entry["type"]] = now

    def _send() -> None:
        try:
            msg = MIMEMultipart()
            msg["From"]    = email_config["smtp_user"]
            msg["To"]      = email_config["recipient"]
            msg["Subject"] = f"[MonitorIA] {entry['service']} - {entry['type'].upper()}"
            body = (
                f"Evenement detecte sur votre serveur :\n\n"
                f"Service : {entry['service']}\n"
                f"Type    : {entry['type']}\n"
                f"Heure   : {entry['timestamp']}\n\n"
                f"Ligne   : {entry['line']}"
            )
            msg.attach(MIMEText(body, "plain"))
            smtp_send(msg)
            app.logger.info(f"[INFO] Alerte mail envoyee pour {entry['service']} - {entry['type']}")
            # Enregistrement dans l'historique des alertes envoyees
            record = {
                "sent_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "type":    entry["type"],
                "service": entry["service"],
                "ip":      extract_ip(entry.get("line", "")),
                "line":    entry["line"]
            }
            with _alert_log_lock:
                _alert_log.appendleft(record)
        except smtplib.SMTPException as exc:
            app.logger.error(f"[ERROR] Envoi mail SMTP echoue : {exc}")
        except Exception as exc:
            app.logger.error(f"[ERROR] Envoi mail echoue : {exc}")

    threading.Thread(target=_send, daemon=True).start()


# ---------------------------------------------------------------------------
# Statistiques par IP : suivi des tentatives hostiles
# ---------------------------------------------------------------------------

# Verrou pour l'acces concurrent depuis les threads de surveillance
_ip_lock = threading.Lock()

# Structure a fenetre glissante :
# { "1.2.3.4": { "buckets": { "YYYY-MM-DD": { count, first_seen, last_seen, services, types } } } }
# Chaque jour constitue un bucket independant ; les buckets expires (> RETENTION_DAYS) sont purges.
_ip_stats: dict = {}

# Types d'evenements consideres comme hostiles pour le suivi IP
_HOSTILE_TYPES = frozenset({"failure", "wireguard_failure", "ban", "nftables"})

# Patterns d'extraction de l'IP source selon le format de la ligne.
# Ordre de priorite decroissante : "from X port" > "from X:port" > SRC=X > Ban/Unban X
_RE_IP_FROM_PORT = re.compile(r'\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port\b', re.IGNORECASE)
_RE_IP_FROM      = re.compile(r'\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\b', re.IGNORECASE)
_RE_IP_SRC       = re.compile(r'\bSRC=(\d{1,3}(?:\.\d{1,3}){3})\b')
_RE_IP_BAN       = re.compile(r'\b(?:Ban|Unban)\s+(\d{1,3}(?:\.\d{1,3}){3})\b', re.IGNORECASE)

# Patterns d'extraction du port de destination
_RE_PORT_DPT  = re.compile(r'\bDPT=(\d+)\b')
_RE_PORT_PORT = re.compile(r'\bport\s+(\d+)\b', re.IGNORECASE)
_RE_PORT_ON   = re.compile(r'\bon\s+port\s+(\d+)\b', re.IGNORECASE)

# Port par defaut par service (quand aucun port explicite dans la ligne)
_SERVICE_DEFAULT_PORTS: dict[str, int | None] = {
    "SSH":       22,
    "WireGuard": 51820,
    "fail2ban":  None,
    "nftables":  None,
}

# Constantes de validation nftables (protection injection commande)
_VALID_NFT_FAMILIES = frozenset({"ip", "ip6", "inet", "arp", "bridge", "netdev"})
_VALID_NFT_ACTIONS  = frozenset({"drop", "accept", "reject"})
_VALID_NFT_PROTOS   = frozenset({"tcp", "udp", "any"})
_RE_NFT_NAME        = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')


def extract_ip(line: str) -> str | None:
    """
    Extrait l'adresse IP source d'une ligne de log.
    Essaie plusieurs patterns dans l'ordre de specificite decroissante.
    """
    for pattern in (_RE_IP_FROM_PORT, _RE_IP_FROM, _RE_IP_SRC, _RE_IP_BAN):
        m = pattern.search(line)
        if m:
            return m.group(1)
    return None


def extract_port(line: str, service: str | None = None) -> int | None:
    """
    Extrait le port de destination d'une ligne de log.
    Priorite : DPT= (nftables) > 'on port N' > 'port N' > port par defaut du service.
    """
    for pattern in (_RE_PORT_DPT, _RE_PORT_ON, _RE_PORT_PORT):
        m = pattern.search(line)
        if m:
            p = int(m.group(1))
            if 1 <= p <= 65535:
                return p
    if service:
        return _SERVICE_DEFAULT_PORTS.get(service)
    return None


# Poids par type d'evenement pour le calcul du score de menace.
# Un ban fail2ban (confirmation externe) pese 3x une tentative brute.
THREAT_WEIGHTS = {
    "failure":           1.0,
    "wireguard_failure": 0.8,
    "ban":               3.0,
    "nftables":          0.5,
}


def classify_threat(data: dict) -> str:
    """
    Classe le niveau de menace d'une IP selon ses tentatives :
    - scan        : plusieurs services cibles (reconnaissance du systeme)
    - brute_force : score pondere suffisamment eleve sur un seul service
    - probe       : tentatives isolees ou peu nombreuses
    Le score pondere donne plus de poids aux bans fail2ban qu'aux tentatives brutes.
    """
    nb_svc = sum(1 for v in data["services"].values() if v > 0)
    if nb_svc >= SCAN_MIN_SERVICES:
        return "scan"
    score = sum(
        data["types"].get(t, 0) * w
        for t, w in THREAT_WEIGHTS.items()
    )
    if score >= BRUTE_FORCE_MIN_COUNT:
        return "brute_force"
    return "probe"


def _aggregate_buckets(buckets: dict) -> dict | None:
    """
    Calcule les stats agregees depuis les buckets actifs de l'IP.
    Un bucket est actif si sa date est dans la fenetre de retention.
    Doit etre appele sous _ip_lock (pas de verrou interne).
    Retourne None si aucun evenement actif n'existe.
    Inclut les dernieres lignes de log brutes (contexte des attaques) et le taux horaire.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).date().isoformat()
    total_count = 0
    first_seen: str | None = None
    last_seen:  str | None = None
    services: dict = {}
    types:    dict = {}
    log_lines: list = []

    for day, bucket in buckets.items():
        if day < cutoff:
            continue
        total_count += bucket["count"]
        if first_seen is None or bucket["first_seen"] < first_seen:
            first_seen = bucket["first_seen"]
        if last_seen is None or bucket["last_seen"] > last_seen:
            last_seen = bucket["last_seen"]
        for svc, n in bucket["services"].items():
            services[svc] = services.get(svc, 0) + n
        for t, n in bucket["types"].items():
            types[t] = types.get(t, 0) + n
        log_lines.extend(bucket.get("log_lines", []))

    if total_count == 0:
        return None

    # Garder uniquement les CONTEXT_LINES_MAX dernieres lignes
    log_lines = log_lines[-CONTEXT_LINES_MAX:]

    # Calcul du taux d'evenements par heure sur la plage observee
    rate_per_hour = 0.0
    try:
        span_s = max(
            1,
            (datetime.fromisoformat(last_seen) - datetime.fromisoformat(first_seen)).total_seconds()
        )
        rate_per_hour = round(total_count / span_s * 3600, 1)
    except Exception:
        pass

    return {
        "count":         total_count,
        "first_seen":    first_seen,
        "last_seen":     last_seen,
        "services":      services,
        "types":         types,
        "log_lines":     log_lines,
        "rate_per_hour": rate_per_hour
    }


def record_ip_event(ip: str, service: str, log_type: str, line: str = "") -> None:
    """
    Enregistre une tentative hostile associee a une IP dans le bucket du jour.
    Cree le bucket du jour s'il n'existe pas encore.
    Stocke les dernieres lignes de log brutes pour le contexte des attaques.
    """
    now     = datetime.now(timezone.utc)
    today   = now.date().isoformat()
    now_iso = now.isoformat(timespec="seconds")
    with _ip_lock:
        if ip not in _ip_stats:
            _ip_stats[ip] = {"buckets": {}}
        buckets = _ip_stats[ip]["buckets"]
        if today not in buckets:
            buckets[today] = {
                "count":      0,
                "first_seen": now_iso,
                "last_seen":  now_iso,
                "services":   {},
                "types":      {},
                "log_lines":  []
            }
        bucket = buckets[today]
        bucket["count"] += 1
        bucket["last_seen"] = now_iso
        bucket["services"][service] = bucket["services"].get(service, 0) + 1
        bucket["types"][log_type]   = bucket["types"].get(log_type, 0) + 1
        if line:
            if "log_lines" not in bucket:
                bucket["log_lines"] = []
            bucket["log_lines"].append(line)
            if len(bucket["log_lines"]) > CONTEXT_LINES_MAX:
                bucket["log_lines"] = bucket["log_lines"][-CONTEXT_LINES_MAX:]


def load_ip_stats() -> None:
    """Charge les stats IP depuis le fichier JSON persistant au demarrage."""
    global _ip_stats
    try:
        with open(IP_STATS_PATH, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            _ip_stats = data
            app.logger.info(f"[INFO] Stats IP chargees : {len(_ip_stats)} IP(s)")
    except FileNotFoundError:
        app.logger.info("[INFO] Aucun historique IP existant")
    except (json.JSONDecodeError, IOError) as exc:
        app.logger.error(f"[ERROR] Chargement ip_stats : {exc}")


def save_ip_stats() -> None:
    """
    Persiste les stats IP dans le fichier JSON et purge les buckets expires.
    Les IPs sans aucun bucket actif sont egalement supprimees.
    Utilise une ecriture atomique (fichier temporaire + rename) pour eviter
    toute corruption du fichier en cas d'arret brutal en cours d'ecriture.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).date().isoformat()
    with _ip_lock:
        for ip in list(_ip_stats.keys()):
            buckets = _ip_stats[ip]["buckets"]
            for day in [d for d in buckets if d < cutoff]:
                del buckets[day]
            if not buckets:
                del _ip_stats[ip]
        snapshot = {ip: {"buckets": copy.deepcopy(e["buckets"])} for ip, e in _ip_stats.items()}

    tmp_path = IP_STATS_PATH + ".tmp"
    try:
        dirpath = os.path.dirname(IP_STATS_PATH)
        if dirpath:
            os.makedirs(dirpath, exist_ok=True)
        with open(tmp_path, "w") as f:
            json.dump(snapshot, f)
        # Remplacement atomique : jamais de fichier partiellement ecrit visible
        os.replace(tmp_path, IP_STATS_PATH)
    except IOError as exc:
        app.logger.error(f"[ERROR] Sauvegarde ip_stats : {exc}")
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def ip_stats_saver() -> None:
    """Thread de sauvegarde periodique des stats IP (toutes les 5 minutes)."""
    while True:
        time.sleep(300)
        save_ip_stats()


# ---------------------------------------------------------------------------
# Archive de logs par IP (rotation automatique a 1 Go)
# ---------------------------------------------------------------------------

_ip_logs_lock = threading.Lock()


def _ip_log_path(ip: str) -> str:
    """Retourne le chemin du fichier de log pour une IP donnee."""
    # Sanitize IP pour nom de fichier (remplace les points par des underscores)
    safe = ip.replace(".", "_").replace(":", "_")
    return os.path.join(IP_LOGS_DIR, f"{safe}.jsonl")


def _ip_logs_total_size() -> int:
    """Calcule la taille totale du repertoire de logs IP en octets."""
    total = 0
    try:
        for fname in os.listdir(IP_LOGS_DIR):
            if fname.endswith(".jsonl"):
                try:
                    total += os.path.getsize(os.path.join(IP_LOGS_DIR, fname))
                except OSError:
                    pass
    except OSError:
        pass
    return total


def _rotate_ip_logs() -> None:
    """
    Supprime les fichiers de logs IP les plus anciens jusqu'a repasser sous IP_LOGS_MAX_BYTES.
    Strategie : supprimer d'abord les fichiers dont le dernier evenement est le plus ancien.
    """
    try:
        files = []
        for fname in os.listdir(IP_LOGS_DIR):
            if not fname.endswith(".jsonl"):
                continue
            fpath = os.path.join(IP_LOGS_DIR, fname)
            try:
                mtime = os.path.getmtime(fpath)
                size  = os.path.getsize(fpath)
                files.append((mtime, size, fpath))
            except OSError:
                pass
        # Trier par date de modification croissante (plus anciens en premier)
        files.sort(key=lambda x: x[0])
        total = sum(f[1] for f in files)
        for mtime, size, fpath in files:
            if total <= IP_LOGS_MAX_BYTES * 0.9:  # marge 10%
                break
            try:
                os.unlink(fpath)
                total -= size
                app.logger.info(f"[INFO] Rotation logs IP : suppression {fpath} ({size} octets)")
            except OSError:
                pass
    except OSError:
        pass


def archive_ip_log(ip: str, entry: dict) -> None:
    """
    Archive une ligne de log associee a une IP dans son fichier JSONL dedie.
    Verifie le quota 1 Go et declenche une rotation si necessaire.
    Ne leve jamais d'exception (non bloquant pour le flux principal).
    """
    try:
        os.makedirs(IP_LOGS_DIR, exist_ok=True)
        line = json.dumps({
            "ts":      entry.get("timestamp", ""),
            "type":    entry.get("type", ""),
            "service": entry.get("service", ""),
            "line":    entry.get("line", "")
        }, ensure_ascii=False)
        fpath = _ip_log_path(ip)
        with _ip_logs_lock:
            with open(fpath, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            # Verifier le quota toutes les 100 appels environ (evite stat() a chaque event)
            if not hasattr(archive_ip_log, "_call_counter"):
                archive_ip_log._call_counter = 0
            archive_ip_log._call_counter += 1
            if archive_ip_log._call_counter % 100 == 0:
                if _ip_logs_total_size() > IP_LOGS_MAX_BYTES:
                    _rotate_ip_logs()
    except Exception as exc:
        app.logger.warning(f"[WARNING] archive_ip_log({ip}) : {exc}")


# ---------------------------------------------------------------------------
# Blocage actif des IPs via nftables
# ---------------------------------------------------------------------------

_blocked_ips: dict = {}   # { "1.2.3.4": { "blocked_at": "...", "method": "...", "reason": "..." } }
_blocked_lock = threading.Lock()


def _validate_ipv4(ip: str) -> bool:
    """Retourne True si ip est une adresse IPv4 valide (protection injection shell)."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.version == 4
    except ValueError:
        return False


def _nft_setup_monitoria() -> tuple[bool, str]:
    """
    Cree la table, le set et la chaine MonitorIA dans nftables si absents.
    La table 'monitoria' contient un set 'blocklist' et une chaine 'input' hookee
    en priorite -1 (avant les autres regles) qui drop les IPs du set.
    """
    cmds = [
        ["nft", "add", "table", "inet", NFT_TABLE],
        ["nft", "add", "set", "inet", NFT_TABLE, NFT_SET,
         "{ type ipv4_addr ; flags interval ; }"],
        ["nft", "add", "chain", "inet", NFT_TABLE, "input",
         "{ type filter hook input priority -1 ; policy accept ; }"],
        ["nft", "add", "rule", "inet", NFT_TABLE, "input",
         "ip", "saddr", f"@{NFT_SET}", "counter", "drop"],
    ]
    for cmd in cmds:
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0 and "File exists" not in r.stderr and "already exists" not in r.stderr:
            return False, f"nft setup : {r.stderr.strip()}"
    return True, "Table monitoria configuree avec succes"


def _nft_set_exists() -> bool:
    """Verifie si le set monitoria/blocklist existe dans nftables."""
    r = subprocess.run(
        ["nft", "list", "set", "inet", NFT_TABLE, NFT_SET],
        capture_output=True, text=True
    )
    return r.returncode == 0


def block_ip(ip: str, reason: str = "manuel") -> tuple[bool, str]:
    """
    Bloque une IP via le set nftables 'inet monitoria blocklist'.
    Cree la table monitoria automatiquement si elle n'existe pas.
    Retourne (succes, message).
    """
    if not _validate_ipv4(ip):
        return False, f"Adresse IPv4 invalide : {ip}"

    with _blocked_lock:
        if ip in _blocked_ips:
            return False, f"IP {ip} deja bloquee"

    # Creer la table monitoria si necessaire
    if not _nft_set_exists():
        ok, msg = _nft_setup_monitoria()
        if not ok:
            return False, msg

    r = subprocess.run(
        ["nft", "add", "element", "inet", NFT_TABLE, NFT_SET, "{", ip, "}"],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        return False, f"nft : {r.stderr.strip()}"

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with _blocked_lock:
        _blocked_ips[ip] = {"blocked_at": now, "method": "nft", "reason": reason}
    save_blocked_ips()
    app.logger.info(f"[INFO] IP bloquee : {ip} (raison : {reason})")
    return True, f"IP {ip} bloquee avec succes"


def unblock_ip(ip: str) -> tuple[bool, str]:
    """
    Retire une IP du set nftables et de la liste interne.
    Retourne (succes, message).
    """
    if not _validate_ipv4(ip):
        return False, f"Adresse IPv4 invalide : {ip}"

    r = subprocess.run(
        ["nft", "delete", "element", "inet", NFT_TABLE, NFT_SET, "{", ip, "}"],
        capture_output=True, text=True
    )
    # On continue meme si nft echoue (peut etre deja retiree)
    if r.returncode != 0:
        app.logger.warning(f"[WARNING] nft delete element {ip} : {r.stderr.strip()}")

    with _blocked_lock:
        _blocked_ips.pop(ip, None)
    save_blocked_ips()
    app.logger.info(f"[INFO] IP debloquee : {ip}")
    return True, f"IP {ip} debloquee"


def load_blocked_ips() -> None:
    """Charge la liste des IPs bloquees depuis le fichier JSON persistant."""
    global _blocked_ips
    try:
        with open(BLOCKLIST_PATH, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            _blocked_ips = data
            app.logger.info(f"[INFO] Blocklist chargee : {len(_blocked_ips)} IP(s) bloquee(s)")
    except FileNotFoundError:
        app.logger.info("[INFO] Aucune blocklist existante")
    except (json.JSONDecodeError, IOError) as exc:
        app.logger.error(f"[ERROR] Chargement blocklist : {exc}")


def save_blocked_ips() -> None:
    """Persiste la liste des IPs bloquees (ecriture atomique)."""
    with _blocked_lock:
        snapshot = dict(_blocked_ips)
    tmp_path = BLOCKLIST_PATH + ".tmp"
    try:
        dirpath = os.path.dirname(BLOCKLIST_PATH)
        if dirpath:
            os.makedirs(dirpath, exist_ok=True)
        with open(tmp_path, "w") as f:
            json.dump(snapshot, f, indent=2)
        os.replace(tmp_path, BLOCKLIST_PATH)
    except IOError as exc:
        app.logger.error(f"[ERROR] Sauvegarde blocklist : {exc}")
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def get_nft_ruleset() -> tuple[bool, str]:
    """Retourne la sortie complete de 'nft list ruleset' (lecture seule)."""
    r = subprocess.run(
        ["nft", "list", "ruleset"],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode == 0:
        return True, r.stdout
    return False, r.stderr.strip()


def nft_verify() -> tuple[bool, str]:
    """Verifie la configuration nftables via 'nft -c -f /etc/nftables.conf'."""
    r = subprocess.run(
        ["nft", "-c", "-f", "/etc/nftables.conf"],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode == 0:
        return True, "Configuration nftables valide"
    return False, r.stderr.strip() or "Erreur de verification"


def nft_restart() -> tuple[bool, str]:
    """Redemarre le service nftables via systemctl."""
    r = subprocess.run(
        ["systemctl", "restart", "nftables"],
        capture_output=True, text=True, timeout=10
    )
    if r.returncode == 0:
        return True, "nftables redémarre avec succes"
    return False, r.stderr.strip() or "Echec redemarrage nftables"


# ---------------------------------------------------------------------------
# Traitement des lignes de log
# ---------------------------------------------------------------------------

def process_line(line: str, fallback_service: str = None) -> None:
    """
    Traite une ligne de log brute : classification, diffusion SSE et alerte mail.
    fallback_service est utilise si la classification retourne 'system'
    (utile pour les fichiers de logs generiques comme auth.log).
    """
    line = line.strip()
    if not line:
        return

    log_type, service = classify_line(line)
    if fallback_service and service == "system":
        service = fallback_service

    # Suivi des tentatives hostiles par IP
    # Les IPs en liste blanche et les evenements correspondant a une regle d'exception
    # (ex: connexions root locales declenchees par des crons) sont exclus du suivi.
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "timestamp": now_str,
        "line":      line,
        "type":      log_type,
        "service":   service
    }

    if log_type in _HOSTILE_TYPES:
        ip = extract_ip(line)
        if ip and not is_whitelisted(ip) and not matches_exception_rule(log_type, ip, line):
            record_ip_event(ip, service, log_type, line)
            # Archivage du log dans le fichier dedie a cette IP
            threading.Thread(target=archive_ip_log, args=(ip, entry), daemon=True).start()

    broadcast(entry)
    send_alert(entry)


# ---------------------------------------------------------------------------
# Surveillance des sources de logs
# ---------------------------------------------------------------------------

def tail_journald() -> None:
    """
    Surveille les journaux systemd des services cibles via journalctl.
    Redemarre automatiquement en cas de crash du processus.
    """
    units = ["-u", "ssh", "-u", "sshd", "-u", "wg-quick@wg0", "-u", "fail2ban"]
    cmd   = ["journalctl", "-f", "-n", "100", "--no-pager", "--output=short-iso"] + units

    app.logger.info("[INFO] Demarrage surveillance journalctl")

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
    Surveille un fichier de log en continu via lecture incrementale.
    Gere la rotation des fichiers (logrotate) : detecte quand le fichier
    est remplace et rouvre le nouveau fichier automatiquement.
    """
    app.logger.info(f"[INFO] Surveillance fichier : {filepath}")

    while True:
        try:
            inode_initial = os.stat(filepath).st_ino
            with open(filepath, "r", errors="replace") as f:
                f.seek(0, 2)  # Se positionner en fin de fichier
                while True:
                    line = f.readline()
                    if line:
                        process_line(line, fallback_service=service)
                    else:
                        # Detecter une rotation : si l'inode a change, rouvrir
                        try:
                            if os.stat(filepath).st_ino != inode_initial:
                                app.logger.info(f"[INFO] Rotation detectee : {filepath}")
                                break
                        except FileNotFoundError:
                            break
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
    Demarre tous les threads de surveillance des logs et le thread de sauvegarde des stats IP.
    journalctl couvre SSH, wg-quick et fail2ban via systemd.
    Les fichiers de logs completent la couverture pour kern.log (WireGuard/nftables)
    et auth.log (SSH via PAM, non present dans systemd sur certaines distros).
    syslog est exclu : il duplique kern.log pour les messages kernel.
    journalctl -k est exclu : ne trouve pas les fichiers journal dans le container
    (mismatch machine-id hote/container) ; kern.log couvre le meme contenu via rsyslog.
    """
    threading.Thread(target=tail_journald,  daemon=True).start()
    threading.Thread(target=ip_stats_saver, daemon=True).start()

    log_files = [
        ("/var/log/fail2ban.log", "fail2ban"),
        ("/var/log/auth.log",     "SSH"),
        ("/var/log/secure",       "SSH"),
        ("/var/log/kern.log",     "nftables"),
    ]
    for filepath, service in log_files:
        if os.path.exists(filepath):
            threading.Thread(target=tail_file, args=(filepath, service), daemon=True).start()


# ---------------------------------------------------------------------------
# Configuration email
# ---------------------------------------------------------------------------

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
        dirpath = os.path.dirname(CONFIG_PATH)
        if dirpath:
            os.makedirs(dirpath, exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(email_config, f, indent=2)
        app.logger.info("[INFO] Configuration email sauvegardee")
    except IOError as exc:
        app.logger.error(f"[ERROR] Sauvegarde configuration : {exc}")


# ---------------------------------------------------------------------------
# Routes Flask
# ---------------------------------------------------------------------------

@app.after_request
def add_security_headers(response: Response) -> Response:
    """
    Ajoute les headers de securite HTTP a chaque reponse.
    Previent le clickjacking, le MIME sniffing et les attaques XSS reflechies.
    """
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Referrer-Policy"]          = "strict-origin-when-cross-origin"
    return response


@app.route("/")
def index():
    """Page principale du dashboard."""
    return render_template("index.html")


@app.route("/health")
def health():
    """
    Endpoint de sante de l'application.
    Utilise par le HEALTHCHECK du Containerfile et les sondes de monitoring externes.
    """
    uptime = int((datetime.now(timezone.utc) - _start_time).total_seconds())
    with clients_lock:
        nb_clients = len(clients)
    with _ip_lock:
        nb_ips = len(_ip_stats)
    return jsonify({
        "status":            "ok",
        "uptime_seconds":    uptime,
        "clients_connected": nb_clients,
        "ips_tracked":       nb_ips
    })


@app.route("/stream")
def stream():
    """
    Endpoint SSE : diffuse les evenements de logs en temps reel.
    Chaque client recoit sa propre queue pour eviter les pertes d'evenements.
    Un keepalive est envoye toutes les 30s pour maintenir la connexion ouverte.
    """
    client_queue: queue.Queue = queue.Queue(maxsize=200)

    with clients_lock:
        clients.append(client_queue)

    app.logger.info(f"[INFO] Nouveau client SSE connecte ({len(clients)} actif(s))")

    def event_stream():
        try:
            while True:
                try:
                    entry = client_queue.get(timeout=30)
                    yield f"data: {json.dumps(entry)}\n\n"
                except queue.Empty:
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
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":       "keep-alive"
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

    if not data.get("smtp_pass") and email_config.get("smtp_pass"):
        data["smtp_pass"] = email_config["smtp_pass"]

    email_config.update(data)
    save_config()
    _compile_whitelist()
    return jsonify({"status": "ok"})


@app.route("/api/ip-stats")
def api_ip_stats() -> Response:
    """
    Retourne les statistiques de tentatives hostiles par IP sur les RETENTION_DAYS derniers jours.
    Triees par nombre de tentatives decroissant, limitees aux 200 premieres.
    Inclut les lignes de log contextuelles, le taux horaire et l'indicateur 'nouvelle IP'.
    """
    now = datetime.now(timezone.utc)
    with _ip_lock:
        result = []
        for ip, entry in _ip_stats.items():
            agg = _aggregate_buckets(entry["buckets"])
            if agg:
                is_new = False
                if agg["first_seen"]:
                    try:
                        age_h = (now - datetime.fromisoformat(agg["first_seen"])).total_seconds() / 3600
                        is_new = age_h < 24
                    except Exception:
                        pass
                result.append({
                    "ip":            ip,
                    "count":         agg["count"],
                    "first_seen":    agg["first_seen"],
                    "last_seen":     agg["last_seen"],
                    "services":      agg["services"],
                    "types":         agg["types"],
                    "threat":        classify_threat(agg),
                    "log_lines":     agg.get("log_lines", []),
                    "rate_per_hour": agg.get("rate_per_hour", 0.0),
                    "is_new":        is_new
                })
    result.sort(key=lambda x: x["count"], reverse=True)
    return jsonify(result[:200])


@app.route("/api/alerts")
def api_alerts() -> Response:
    """
    Retourne l'historique des ALERT_LOG_MAXLEN dernieres alertes mail envoyees.
    Chaque entree contient le timestamp d'envoi, le type, le service, l'IP et la ligne brute.
    """
    with _alert_log_lock:
        return jsonify(list(_alert_log))


@app.route("/api/logs/export")
def export_logs() -> Response:
    """
    Exporte les EVENT_BUFFER_MAXLEN derniers evenements au format CSV.
    Permet l'analyse hors ligne ou l'archivage des evenements recents.
    """
    with _buffer_lock:
        events = list(_event_buffer)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "service", "type", "line"])
    for e in events:
        writer.writerow([e["timestamp"], e["service"], e["type"], e["line"]])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=monitoria_export.csv"}
    )


@app.route("/api/test-email", methods=["POST"])
def test_email():
    """Envoie un email de test pour valider la configuration SMTP."""
    if not email_config.get("smtp_host") or not email_config.get("recipient"):
        return jsonify({"error": "Configuration SMTP incomplete"}), 400

    try:
        msg = MIMEMultipart()
        msg["From"]    = email_config["smtp_user"]
        msg["To"]      = email_config["recipient"]
        msg["Subject"] = "[MonitorIA] Test de configuration"
        msg.attach(MIMEText(
            "Ceci est un email de test envoye par MonitorIA. La configuration SMTP est correcte.",
            "plain"
        ))
        smtp_send(msg)
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


@app.route("/api/block-ip", methods=["POST"])
def api_block_ip() -> Response:
    """
    Bloque une IP via le set nftables 'inet monitoria blocklist'.
    Corps JSON attendu : { "ip": "1.2.3.4", "reason": "optionnel" }
    """
    data = request.get_json(silent=True)
    if not data or not data.get("ip"):
        return jsonify({"error": "Champ 'ip' manquant"}), 400
    ok, msg = block_ip(data["ip"].strip(), data.get("reason", "manuel via dashboard"))
    if ok:
        return jsonify({"status": "ok", "message": msg})
    return jsonify({"error": msg}), 400


@app.route("/api/unblock-ip", methods=["POST"])
def api_unblock_ip() -> Response:
    """
    Retire une IP du blocklist nftables.
    Corps JSON attendu : { "ip": "1.2.3.4" }
    """
    data = request.get_json(silent=True)
    if not data or not data.get("ip"):
        return jsonify({"error": "Champ 'ip' manquant"}), 400
    ok, msg = unblock_ip(data["ip"].strip())
    if ok:
        return jsonify({"status": "ok", "message": msg})
    return jsonify({"error": msg}), 400


@app.route("/api/blocked-ips")
def api_blocked_ips() -> Response:
    """Retourne la liste des IPs actuellement bloquees par MonitorIA."""
    with _blocked_lock:
        result = [
            {"ip": ip, **info}
            for ip, info in _blocked_ips.items()
        ]
    result.sort(key=lambda x: x.get("blocked_at", ""), reverse=True)
    return jsonify(result)


@app.route("/api/nftables/ruleset")
def api_nft_ruleset() -> Response:
    """Retourne la sortie complete de 'nft list ruleset' (lecture seule)."""
    ok, output = get_nft_ruleset()
    return jsonify({"ok": ok, "output": output})


@app.route("/api/nftables/action", methods=["POST"])
def api_nft_action() -> Response:
    """
    Execute une action nftables.
    Corps JSON attendu : { "action": "verify"|"restart"|"setup" }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Corps JSON invalide"}), 400
    action = data.get("action", "")

    if action == "verify":
        ok, msg = nft_verify()
    elif action == "restart":
        ok, msg = nft_restart()
    elif action == "setup":
        ok, msg = _nft_setup_monitoria()
    else:
        return jsonify({"error": f"Action inconnue : {action}"}), 400

    if ok:
        app.logger.info(f"[INFO] nftables action '{action}' : {msg}")
        return jsonify({"status": "ok", "message": msg})
    app.logger.error(f"[ERROR] nftables action '{action}' : {msg}")
    return jsonify({"error": msg}), 500


@app.route("/api/nftables/rules")
def api_nft_rules() -> Response:
    """
    Retourne les tables, chaines et regles nftables sous forme structuree (JSON nft).
    Fallback vers le texte brut si la version de nft ne supporte pas -j.
    """
    return jsonify(get_nft_rules_json())


@app.route("/api/nftables/rule", methods=["DELETE"])
def api_nft_delete_rule() -> Response:
    """
    Supprime une regle nftables par son handle.
    Corps JSON : { "family": "inet", "table": "filter", "chain": "input", "handle": 4 }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Corps JSON invalide"}), 400

    family  = data.get("family", "inet")
    table   = data.get("table", "")
    chain   = data.get("chain", "")
    handle  = data.get("handle")

    if family not in _VALID_NFT_FAMILIES:
        return jsonify({"error": f"Family invalide : {family}"}), 400
    if not _RE_NFT_NAME.match(table):
        return jsonify({"error": f"Nom de table invalide : {table}"}), 400
    if not _RE_NFT_NAME.match(chain):
        return jsonify({"error": f"Nom de chaine invalide : {chain}"}), 400
    try:
        handle = int(handle)
        if handle <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"error": "Handle doit etre un entier positif"}), 400

    r = subprocess.run(
        ["nft", "delete", "rule", family, table, chain, "handle", str(handle)],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode == 0:
        app.logger.info(f"[INFO] Regle supprimee : {family} {table} {chain} handle {handle}")
        return jsonify({"status": "ok"})
    return jsonify({"error": r.stderr.strip()}), 500


@app.route("/api/nftables/add-rule", methods=["POST"])
def api_nft_add_rule() -> Response:
    """
    Ajoute une regle nftables simple via un formulaire guide.
    Corps JSON : { "family", "table", "chain", "ip", "port", "proto", "action" }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Corps JSON invalide"}), 400

    family = data.get("family", "inet")
    table  = data.get("table", "")
    chain  = data.get("chain", "input")
    ip     = data.get("ip", "").strip()
    port   = data.get("port", 0)
    proto  = data.get("proto", "any")
    action = data.get("action", "drop")

    if family not in _VALID_NFT_FAMILIES:
        return jsonify({"error": f"Family invalide : {family}"}), 400
    if not _RE_NFT_NAME.match(table):
        return jsonify({"error": f"Nom de table invalide : {table}"}), 400
    if not _RE_NFT_NAME.match(chain):
        return jsonify({"error": f"Nom de chaine invalide : {chain}"}), 400
    if action not in _VALID_NFT_ACTIONS:
        return jsonify({"error": f"Action invalide : {action}"}), 400
    if proto not in _VALID_NFT_PROTOS:
        return jsonify({"error": f"Protocol invalide : {proto}"}), 400

    # Validation IP/CIDR (protection injection)
    net_str = None
    if ip:
        try:
            net_str = str(ipaddress.ip_network(ip, strict=False))
        except ValueError:
            return jsonify({"error": f"IP/CIDR invalide : {ip}"}), 400

    try:
        port = int(port)
        if not (0 <= port <= 65535):
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"error": "Port invalide (0-65535)"}), 400

    # Construction de la commande (liste, jamais de shell=True)
    cmd = ["nft", "add", "rule", family, table, chain]
    if net_str:
        cmd += ["ip", "saddr", net_str]
    if proto != "any":
        cmd += [proto]
    if port > 0:
        cmd += ["dport", str(port)]
    cmd += ["counter", action]

    r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    if r.returncode == 0:
        app.logger.info(f"[INFO] Regle ajoutee : {' '.join(cmd)}")
        return jsonify({"status": "ok", "message": "Regle ajoutee avec succes"})
    return jsonify({"error": r.stderr.strip()}), 500


@app.route("/api/flux")
def api_flux() -> Response:
    """Retourne les flux de trafic hostile des 60 dernieres minutes."""
    return jsonify(compute_flux())


@app.route("/api/ip-logs/<path:ip>")
def api_ip_logs(ip: str) -> Response:
    """
    Retourne les logs archives pour une IP donnee.
    Parametres optionnels : ?limit=200&offset=0
    """
    if not _validate_ipv4(ip):
        return jsonify({"error": "IP invalide"}), 400

    limit  = min(int(request.args.get("limit", 200)), 1000)
    offset = int(request.args.get("offset", 0))

    fpath = _ip_log_path(ip)
    logs  = []
    try:
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        logs.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except FileNotFoundError:
        pass
    except IOError as exc:
        return jsonify({"error": str(exc)}), 500

    # Plus recents en premier
    logs.reverse()
    total = len(logs)
    page  = logs[offset:offset + limit]

    return jsonify({
        "ip":     ip,
        "total":  total,
        "offset": offset,
        "limit":  limit,
        "logs":   page
    })


@app.route("/api/ip-logs-stats")
def api_ip_logs_stats() -> Response:
    """Retourne la taille totale du dossier de logs IP et la liste des IPs archivees."""
    total_bytes = _ip_logs_total_size()
    files = []
    try:
        for fname in sorted(os.listdir(IP_LOGS_DIR)):
            if not fname.endswith(".jsonl"):
                continue
            fpath = os.path.join(IP_LOGS_DIR, fname)
            try:
                sz    = os.path.getsize(fpath)
                mtime = os.path.getmtime(fpath)
                ip    = fname[:-6].replace("_", ".")  # reverse sanitize
                files.append({"ip": ip, "size_bytes": sz,
                               "last_seen": datetime.fromtimestamp(mtime, tz=timezone.utc)
                                             .strftime("%Y-%m-%d %H:%M:%S")})
            except OSError:
                pass
    except OSError:
        pass
    files.sort(key=lambda x: x["size_bytes"], reverse=True)
    return jsonify({
        "total_bytes":    total_bytes,
        "total_mb":       round(total_bytes / 1024 / 1024, 1),
        "max_bytes":      IP_LOGS_MAX_BYTES,
        "usage_pct":      round(total_bytes / IP_LOGS_MAX_BYTES * 100, 1),
        "files":          files
    })


@app.route("/api/threat-status")
def api_threat_status() -> Response:
    """
    Retourne un resume des menaces actives des 15 dernieres minutes
    calcule depuis le buffer d'evenements en memoire.
    """
    cutoff_dt = datetime.now(timezone.utc).replace(
        second=0, microsecond=0
    ) - timedelta(minutes=15)
    cutoff_str = cutoff_dt.strftime("%Y-%m-%d %H:%M:%S")

    with _buffer_lock:
        recent = [e for e in _event_buffer if e.get("timestamp", "") >= cutoff_str
                  and e.get("type") in _HOSTILE_TYPES]

    types: dict = {}
    active_ips: set = set()
    for e in recent:
        types[e["type"]] = types.get(e["type"], 0) + 1
        ip = extract_ip(e.get("line", ""))
        if ip:
            active_ips.add(ip)

    rate = round(len(recent) / 15, 1)  # evenements par minute sur la fenetre
    threat_level = "calm"
    if rate > 20:
        threat_level = "critical"
    elif rate > 5:
        threat_level = "high"
    elif rate > 1:
        threat_level = "medium"
    elif recent:
        threat_level = "low"

    return jsonify({
        "threat_level":  threat_level,
        "events_15min":  len(recent),
        "rate_per_min":  rate,
        "active_ips":    len(active_ips),
        "types":         types
    })


# ---------------------------------------------------------------------------
# nftables JSON : parsing des regles avec handles
# ---------------------------------------------------------------------------

def _parse_nft_expr(expr_list: list) -> dict:
    """
    Parse la liste 'expr' d'une regle nft JSON pour extraire les champs utiles.
    Retourne un dict : saddr, dport, proto, action, packets, bytes.
    """
    saddr   = None
    dport   = None
    proto   = None
    action  = None
    packets = None
    nbytes  = None

    for expr in expr_list:
        if not isinstance(expr, dict):
            continue
        # Compteur de paquets
        if "counter" in expr:
            c = expr["counter"]
            if isinstance(c, dict):
                packets = c.get("packets")
                nbytes  = c.get("bytes")
        # Action terminale
        for act in ("drop", "accept", "reject", "masquerade", "return"):
            if act in expr:
                action = act
                break
        # Match : adresse source, port destination, proto
        if "match" in expr:
            m = expr["match"]
            left  = m.get("left", {})
            right = m.get("right")
            payload = left.get("payload", {})
            field   = payload.get("field", "")
            prot    = payload.get("protocol", "")
            if field == "saddr":
                saddr = str(right) if right is not None else None
            elif field == "dport":
                if isinstance(right, int):
                    dport = right
                elif isinstance(right, dict) and "range" in right:
                    dport = right["range"][0]
            if prot in ("tcp", "udp", "icmp"):
                proto = prot

    return {
        "saddr":   saddr,
        "dport":   dport,
        "proto":   proto,
        "action":  action or "unknown",
        "packets": packets,
        "bytes":   nbytes
    }


def get_nft_rules_json() -> dict:
    """
    Retourne les tables, chaines et regles nftables via 'nft -j list ruleset'.
    Fallback vers le texte brut si le flag -j n'est pas supporte.
    """
    r = subprocess.run(
        ["nft", "-j", "list", "ruleset"],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0:
        # Fallback texte
        ok, raw = get_nft_ruleset()
        return {"json_available": False, "raw": raw if ok else r.stderr.strip()}

    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        ok, raw = get_nft_ruleset()
        return {"json_available": False, "raw": raw}

    tables = []
    chains = []
    rules  = []

    for item in data.get("nftables", []):
        if "table" in item:
            t = item["table"]
            tables.append({"family": t.get("family", ""), "name": t.get("name", ""),
                            "handle": t.get("handle")})
        elif "chain" in item:
            c = item["chain"]
            chains.append({
                "family": c.get("family", ""), "table": c.get("table", ""),
                "name":   c.get("name", ""),   "handle": c.get("handle"),
                "hook":   c.get("hook"),        "prio":   c.get("prio"),
                "policy": c.get("policy"),      "type":   c.get("type")
            })
        elif "rule" in item:
            ru = item["rule"]
            parsed = _parse_nft_expr(ru.get("expr", []))
            rules.append({
                "family":  ru.get("family", ""),
                "table":   ru.get("table", ""),
                "chain":   ru.get("chain", ""),
                "handle":  ru.get("handle"),
                "comment": ru.get("comment", ""),
                **parsed
            })

    return {
        "json_available": True,
        "tables": tables,
        "chains": chains,
        "rules":  rules
    }


# ---------------------------------------------------------------------------
# Flux trafic hostile : analyse temps reel depuis _event_buffer
# ---------------------------------------------------------------------------

def compute_flux() -> dict:
    """
    Calcule les flux de trafic hostile des 60 dernieres minutes
    depuis _event_buffer. Retourne flows, timeline, port_heatmap, active_scans.
    """
    now    = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=60)

    with _buffer_lock:
        snapshot = list(_event_buffer)

    # Buckets par minute pour la timeline (60 slots)
    timeline_buckets: dict[str, int] = {}
    flows: dict[tuple, dict]         = {}
    ports_per_ip: dict[str, set]     = {}

    for evt in snapshot:
        ts_str = evt.get("timestamp", "")
        etype  = evt.get("type", "")
        if etype not in _HOSTILE_TYPES:
            continue
        try:
            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if ts < cutoff:
            continue

        line    = evt.get("line", "")
        service = evt.get("service", "")
        ip      = extract_ip(line)
        port    = extract_port(line, service)
        if not ip:
            continue

        # Timeline : cle = "HH:MM"
        bucket_key = ts.strftime("%H:%M")
        timeline_buckets[bucket_key] = timeline_buckets.get(bucket_key, 0) + 1

        # Flux par (ip, port)
        key = (ip, port)
        if key not in flows:
            flows[key] = {
                "source_ip":      ip,
                "target_port":    port,
                "target_service": service,
                "count":          0,
                "first_seen":     ts_str,
                "last_seen":      ts_str,
                "types":          {}
            }
        f = flows[key]
        f["count"]        += 1
        f["last_seen"]     = ts_str
        f["types"][etype]  = f["types"].get(etype, 0) + 1

        # Ports uniques par IP pour detection de scan
        if ip not in ports_per_ip:
            ports_per_ip[ip] = set()
        if port:
            ports_per_ip[ip].add(port)

    # Taux par flux et classification
    flow_list = []
    for f in flows.values():
        try:
            span_s = max(1, (
                datetime.strptime(f["last_seen"], "%Y-%m-%d %H:%M:%S") -
                datetime.strptime(f["first_seen"], "%Y-%m-%d %H:%M:%S")
            ).total_seconds())
        except ValueError:
            span_s = 1
        rate = round(f["count"] / span_s * 60, 1)
        score = sum(f["types"].get(t, 0) * w for t, w in THREAT_WEIGHTS.items())
        nb_svc = len(ports_per_ip.get(f["source_ip"], set()))
        if nb_svc >= SCAN_MIN_SERVICES:
            threat = "scan"
        elif score >= BRUTE_FORCE_MIN_COUNT:
            threat = "brute_force"
        else:
            threat = "probe"
        flow_list.append({**f, "rate": rate, "threat_level": threat})

    flow_list.sort(key=lambda x: x["count"], reverse=True)

    # Heatmap des ports : 30 dernières minutes vs 30 précédentes pour la tendance
    mid_cutoff = now - timedelta(minutes=30)
    mid_str    = mid_cutoff.strftime("%Y-%m-%d %H:%M:%S")
    port_recent: dict[int, int] = {}
    port_older:  dict[int, int] = {}
    port_svcs:   dict[int, str] = {}

    with _buffer_lock:
        for evt in _event_buffer:
            if evt.get("type") not in _HOSTILE_TYPES:
                continue
            port = extract_port(evt.get("line", ""), evt.get("service"))
            if port is None:
                continue
            port_svcs.setdefault(port, evt.get("service", ""))
            if evt.get("timestamp", "") >= mid_str:
                port_recent[port] = port_recent.get(port, 0) + 1
            else:
                port_older[port] = port_older.get(port, 0) + 1

    all_ports = set(port_recent) | set(port_older)
    heatmap   = []
    for p in all_ports:
        recent_cnt = port_recent.get(p, 0)
        older_cnt  = port_older.get(p, 0)
        total_cnt  = recent_cnt + older_cnt
        if older_cnt > 0:
            delta = (recent_cnt - older_cnt) / older_cnt
        else:
            delta = 1.0 if recent_cnt > 0 else 0.0
        trend = "up" if delta > 0.2 else ("down" if delta < -0.2 else "stable")
        heatmap.append({"port": p, "service": port_svcs.get(p, ""), "count": total_cnt,
                        "recent": recent_cnt, "trend": trend})
    heatmap.sort(key=lambda x: x["count"], reverse=True)

    # Scans actifs : IP ciblant >= 2 ports distincts
    active_scans = []
    for ip, ports in ports_per_ip.items():
        if len(ports) >= SCAN_MIN_SERVICES:
            # first_seen du scan = oldest event pour cette IP dans les 60 min
            ip_first = now.strftime("%Y-%m-%d %H:%M:%S")
            with _buffer_lock:
                for evt in _event_buffer:
                    if evt.get("type") not in _HOSTILE_TYPES:
                        continue
                    if extract_ip(evt.get("line", "")) == ip:
                        if evt.get("timestamp", "") < ip_first:
                            ip_first = evt["timestamp"]
            active_scans.append({
                "ip":         ip,
                "ports":      sorted(ports),
                "port_count": len(ports),
                "started":    ip_first
            })
    active_scans.sort(key=lambda x: x["port_count"], reverse=True)

    # Timeline : generer les 60 derniers slots (une entree par minute)
    timeline = []
    for i in range(59, -1, -1):
        t = now - timedelta(minutes=i)
        key = t.strftime("%H:%M")
        timeline.append({"minute": key, "count": timeline_buckets.get(key, 0)})

    return {
        "flows":        flow_list[:100],
        "timeline":     timeline,
        "port_heatmap": heatmap[:15],
        "active_scans": active_scans
    }


# ---------------------------------------------------------------------------
# Arret propre
# ---------------------------------------------------------------------------

def _handle_shutdown(signum, frame) -> None:
    """
    Handler SIGTERM/SIGINT : sauvegarde les stats IP avant de quitter.
    Necessaire car Podman envoie SIGTERM au container ; sans ce handler,
    Flask ne quitte pas proprement et atexit n'est jamais declenche.
    """
    app.logger.info(f"[INFO] Signal {signum} recu - sauvegarde des stats IP et arret")
    save_ip_stats()
    save_blocked_ips()
    sys.exit(0)


if __name__ == "__main__":
    load_config()
    _compile_whitelist()
    load_ip_stats()
    load_blocked_ips()
    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT,  _handle_shutdown)
    # atexit en dernier recours (arret hors signal, ex: exception non rattrapee)
    atexit.register(save_ip_stats)
    atexit.register(save_blocked_ips)
    start_log_watchers()
    app.logger.info("[INFO] MonitorIA demarre sur le port 8080")
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
