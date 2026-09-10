import ipaddress
import os
import sqlite3
import threading
import time
from queue import Queue
import geoip2.database
import psutil
import requests
from rich.console import Console
from rich.live import Live
from rich.table import Table

console = Console()

# --- CONFIGURATION & GLOBALS ---
GEOIP_DB_PATH = "GeoLite2-City.mmdb"
DB_CACHE_PATH = "nettracer_cache.db"
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")  # Clé via variable d'environnement
CACHE_TTL_HOURS = 24

# Queue pour l'enrichissement en arrière-plan
ip_queue = Queue()
# Set en mémoire des IP déjà en cours de traitement
pending_ips = set()

# Initialisation BDD MaxMind
geoip_reader = None
if os.path.exists(GEOIP_DB_PATH):
    try:
        geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
    except Exception as e:
        console.print(f"[bold yellow]GeoIP warning: {e}[/bold yellow]")


# --- CACHE SQLITE LOCAL ---
def init_sqlite_cache():
    """Initialise la table de cache SQLite pour la réputation IP."""
    conn = sqlite3.connect(DB_CACHE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS ip_reputation (
            ip TEXT PRIMARY KEY,
            score INTEGER,
            usage_type TEXT,
            updated_at INTEGER
        )
    """
    )
    conn.commit()
    conn.close()


def get_cached_reputation(ip: str):
    """Récupère le score depuis le cache SQLite s'il n'est pas expiré (24h)."""
    conn = sqlite3.connect(DB_CACHE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT score, usage_type, updated_at FROM ip_reputation WHERE ip = ?",
        (ip,),
    )
    row = cursor.fetchone()
    conn.close()

    if row:
        score, usage, updated_at = row
        # Vérification du TTL (24 heures)
        if time.time() - updated_at < (CACHE_TTL_HOURS * 3600):
            return score, usage
    return None, None


def save_cached_reputation(ip: str, score: int, usage_type: str):
    """Enregistre le score de réputation dans SQLite."""
    conn = sqlite3.connect(DB_CACHE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT OR REPLACE INTO ip_reputation (ip, score, usage_type, updated_at)
        VALUES (?, ?, ?, ?)
    """,
        (ip, score, usage_type, int(time.time())),
    )
    conn.commit()
    conn.close()


# --- WORKER ASYNCHRONE THREAT INTEL ---
def fetch_abuseipdb_score(ip: str) -> tuple[int, str]:
    """Interroge l'API AbuseIPDB (ou simule si pas de clé)."""
    if not ABUSEIPDB_API_KEY:
        # Mock / Simulation en l'absence de clé API
        return 0, "Clean (No API Key)"

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=3)
        if response.status_code == 200:
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            usage = data.get("usageType", "Unknown")
            return score, usage
    except Exception:
        pass
    return 0, "API Error"


def reputation_worker():
    """Thread d'arrière-plan traitant la file d'attente d'IPs."""
    while True:
        ip = ip_queue.get()
        if ip is None:
            break

        # Traitement uniquement si pas en cache
        score, usage = get_cached_reputation(ip)
        if score is None:
            score, usage = fetch_abuseipdb_score(ip)
            save_cached_reputation(ip, score, usage)

        pending_ips.discard(ip)
        ip_queue.task_done()


# --- HELPER FUNCTIONS ---
def get_country_flag(country_code: str) -> str:
    if not country_code or len(country_code) != 2:
        return "🌐"
    return chr(ord(country_code[0].upper()) + 127397) + chr(
        ord(country_code[1].upper()) + 127397
    )


def get_geoip_info(ip_str: str) -> str:
    if not geoip_reader:
        return "N/A"
    try:
        response = geoip_reader.city(ip_str)
        country_code = response.country.iso_code or ""
        country_name = response.country.name or "Inconnu"
        flag = get_country_flag(country_code)
        return f"{flag} {country_name}"
    except Exception:
        return "🌐 Inconnu"


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return True


def format_reputation_score(score: int | None) -> str:
    """Formate le score avec un code couleur Rich."""
    if score is None:
        return "[dim]Analyse...[/dim]"
    if score == 0:
        return "[bold green]0% (Sûr)[/bold green]"
    if score < 20:
        return f"[green]{score}% (Faible)[/green]"
    if score < 50:
        return f"[bold yellow]{score}% (Suspect)[/bold yellow]"
    return f"[bold red]{score}% (DANGEREUX)[/bold red]"


def get_process_name(pid: int) -> str:
    if not pid:
        return "N/A"
    try:
        proc = psutil.Process(pid)
        return proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "Inconnu"


# --- GENERATION DU TABLEAU TUI ---
def generate_connections_table() -> Table:
    table = Table(
        title="NetTracer v1.0 - Sockets, Processus, GeoIP & Threat Intel",
        expand=True,
    )

    table.add_column("PID", style="cyan", justify="right", no_wrap=True)
    table.add_column("Processus", style="bold green")
    table.add_column("IP Distante", style="bold yellow")
    table.add_column("Port D.", style="bold yellow", justify="right")
    table.add_column("Géolocalisation", style="bold white")
    table.add_column("Score Abus (AbuseIPDB)", style="bold")
    table.add_column("Statut", style="magenta")

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        console.print(
            "[bold red]Erreur : Relancez avec sudo / privilèges root.[/bold red]"
        )
        exit(1)

    for conn in connections:
        if not conn.raddr:
            continue

        r_host, r_port = conn.raddr.ip, conn.raddr.port
        if is_private_ip(r_host):
            continue

        proc_name = get_process_name(conn.pid)
        pid_str = str(conn.pid) if conn.pid else "N/A"
        geo_str = get_geoip_info(r_host)

        # Récupération de la réputation (Cache / Queue)
        score, _ = get_cached_reputation(r_host)

        if score is None and r_host not in pending_ips:
            pending_ips.add(r_host)
            ip_queue.put(r_host)

        rep_str = format_reputation_score(score)

        table.add_row(
            pid_str,
            proc_name,
            r_host,
            str(r_port),
            geo_str,
            rep_str,
            conn.status,
        )

    return table


# --- MAIN ---
def main():
    init_sqlite_cache()

    # Démarrage du worker asynchrone Threat Intel
    worker_thread = threading.Thread(target=reputation_worker, daemon=True)
    worker_thread.start()

    console.print(
        "[bold cyan]Lancement de NetTracer Phase 3...[/bold cyan]"
    )

    try:
        with Live(
            generate_connections_table(), refresh_per_second=1, console=console
        ) as live:
            while True:
                time.sleep(1)
                live.update(generate_connections_table())
    except KeyboardInterrupt:
        if geoip_reader:
            geoip_reader.close()
        console.print("\n[bold yellow]Arrêt de NetTracer.[/bold yellow]")


if __name__ == "__main__":
    main()