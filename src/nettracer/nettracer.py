import csv
import ipaddress
import json
import os
import sqlite3
import threading
import time
from datetime import datetime
from queue import Queue
from typing import Optional

import geoip2.database
import psutil
import requests
import typer
from rich.console import Console
from rich.live import Live
from rich.table import Table

app = typer.Typer(
    help="NetTracer - Moniteur de sockets temps réel avec GeoIP & Threat Intel."
)
console = Console()

# --- CONFIGURATION & CACHE ---
GEOIP_DB_PATH = "GeoLite2-City.mmdb"
DB_CACHE_PATH = "nettracer_cache.db"
CACHE_TTL_HOURS = 24

ip_queue = Queue()
pending_ips = set()

geoip_reader = None
if os.path.exists(GEOIP_DB_PATH):
    try:
        geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
    except Exception:
        pass


def init_sqlite_cache():
    conn = sqlite3.connect(DB_CACHE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS ip_reputation (
            ip TEXT PRIMARY KEY, score INTEGER, usage_type TEXT, updated_at INTEGER
        )
    """
    )
    conn.commit()
    conn.close()


def get_cached_reputation(ip: str):
    conn = sqlite3.connect(DB_CACHE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT score, usage_type, updated_at FROM ip_reputation WHERE ip = ?",
        (ip,),
    )
    row = cursor.fetchone()
    conn.close()
    if row and (time.time() - row[2] < CACHE_TTL_HOURS * 3600):
        return row[0], row[1]
    return None, None


def save_cached_reputation(ip: str, score: int, usage_type: str):
    conn = sqlite3.connect(DB_CACHE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO ip_reputation VALUES (?, ?, ?, ?)",
        (ip, score, usage_type, int(time.time())),
    )
    conn.commit()
    conn.close()


def fetch_abuseipdb_score(ip: str, api_key: str) -> tuple[int, str]:
    if not api_key:
        return 0, "No Key"
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": api_key}
    try:
        res = requests.get(
            url,
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=3,
        )
        if res.status_code == 200:
            data = res.json().get("data", {})
            return data.get("abuseConfidenceScore", 0), data.get(
                "usageType", "Unknown"
            )
    except Exception:
        pass
    return 0, "API Error"


def reputation_worker(api_key: str):
    while True:
        ip = ip_queue.get()
        if ip is None:
            break
        score, usage = get_cached_reputation(ip)
        if score is None:
            score, usage = fetch_abuseipdb_score(ip, api_key)
            save_cached_reputation(ip, score, usage)
        pending_ips.discard(ip)
        ip_queue.task_done()


# --- HELPERS ---
def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return True


def get_country_flag(code: str) -> str:
    if not code or len(code) != 2:
        return "🌐"
    return chr(ord(code[0].upper()) + 127397) + chr(ord(code[1].upper()) + 127397)


def get_geoip_info(ip_str: str) -> str:
    if not geoip_reader:
        return "N/A"
    try:
        res = geoip_reader.city(ip_str)
        return f"{get_country_flag(res.country.iso_code or '')} {res.country.name or 'Inconnu'}"
    except Exception:
        return "🌐 Inconnu"


def format_reputation(score: Optional[int]) -> str:
    if score is None:
        return "[dim]Analyse...[/dim]"
    if score == 0:
        return "[bold green]0% (Clean)[/bold green]"
    if score < 20:
        return f"[green]{score}% (Faible)[/green]"
    if score < 50:
        return f"[bold yellow]{score}% (Suspect)[/bold yellow]"
    return f"[bold red]{score}% (DANGEREUX)[/bold red]"


def get_active_connections(
    proc_filter: Optional[str], port_filter: Optional[int], min_score: int
):
    results = []
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        console.print(
            "[bold red]Erreur: Droits root/sudo requis pour lister les PIDs.[/bold red]"
        )
        raise typer.Exit(1)

    for conn in connections:
        if not conn.raddr or is_private_ip(conn.raddr.ip):
            continue

        r_host, r_port = conn.raddr.ip, conn.raddr.port

        # Filtre par port
        if port_filter and r_port != port_filter:
            continue

        # Récupération processus
        proc_name = "Inconnu"
        if conn.pid:
            try:
                proc_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Filtre par nom de processus
        if proc_filter and proc_filter.lower() not in proc_name.lower():
            continue

        score, _ = get_cached_reputation(r_host)
        if score is None and r_host not in pending_ips:
            pending_ips.add(r_host)
            ip_queue.put(r_host)

        # Filtre par score minimal d'abus
        if min_score > 0 and (score is None or score < min_score):
            continue

        results.append(
            {
                "pid": conn.pid or "N/A",
                "process": proc_name,
                "r_host": r_host,
                "r_port": r_port,
                "geo": get_geoip_info(r_host),
                "score": score,
                "status": conn.status,
            }
        )

    return results


# --- COMMANDES CLI ---
@app.command()
def monitor(
    process: Optional[str] = typer.Option(
        None, "--proc", "-p", help="Filtrer par nom de processus (ex: curl)"
    ),
    port: Optional[int] = typer.Option(
        None, "--port", help="Filtrer par port distant (ex: 443)"
    ),
    min_score: int = typer.Option(
        0, "--min-score", "-s", help="Afficher seulement si score >= valeur"
    ),
    export_csv: Optional[str] = typer.Option(
        None, "--csv", help="Fichier de sortie CSV pour enregistrer les sessions"
    ),
    api_key: Optional[str] = typer.Option(
        None,
        "--api-key",
        envvar="ABUSEIPDB_API_KEY",
        help="Clé API AbuseIPDB (ou via env ABUSEIPDB_API_KEY)",
    ),
):
    """Lance le moniteur de connexions réseau TUI en temps réel."""
    init_sqlite_cache()

    worker = threading.Thread(
        target=reputation_worker, args=(api_key or "",), daemon=True
    )
    worker.start()

    def generate_table():
        table = Table(
            title="NetTracer v1.0 - Network Socket & Threat Intel Monitor",
            expand=True,
        )
        table.add_column("PID", style="cyan", justify="right")
        table.add_column("Processus", style="bold green")
        table.add_column("IP Distante", style="bold yellow")
        table.add_column("Port D.", style="bold yellow", justify="right")
        table.add_column("Géolocalisation", style="bold white")
        table.add_column("Score Abus", style="bold")
        table.add_column("Statut", style="magenta")

        conns = get_active_connections(process, port, min_score)
        for c in conns:
            table.add_row(
                str(c["pid"]),
                c["process"],
                c["r_host"],
                str(c["r_port"]),
                c["geo"],
                format_reputation(c["score"]),
                c["status"],
            )
        return table

    try:
        with Live(generate_table(), refresh_per_second=1, console=console) as live:
            while True:
                time.sleep(1)
                conns = get_active_connections(process, port, min_score)

                # Export CSV au fil de l'eau si demandé
                if export_csv and conns:
                    file_exists = os.path.exists(export_csv)
                    with open(export_csv, "a", newline="") as f:
                        writer = csv.writer(f)
                        if not file_exists:
                            writer.writerow(
                                [
                                    "timestamp",
                                    "pid",
                                    "process",
                                    "r_host",
                                    "r_port",
                                    "geo",
                                    "score",
                                    "status",
                                ]
                            )
                        now = datetime.now().isoformat()
                        for c in conns:
                            writer.writerow(
                                [
                                    now,
                                    c["pid"],
                                    c["process"],
                                    c["r_host"],
                                    c["r_port"],
                                    c["geo"],
                                    c["score"],
                                    c["status"],
                                ]
                            )

                live.update(generate_table())
    except KeyboardInterrupt:
        if geoip_reader:
            geoip_reader.close()
        console.print("\n[bold yellow]NetTracer arrêté.[/bold yellow]")


if __name__ == "__main__":
    app()