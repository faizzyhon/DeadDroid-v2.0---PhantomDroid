"""
Ngrok handler — manages HTTP/TCP tunnels via the ngrok agent API (v3).
Requires: ngrok binary installed and authenticated (ngrok config add-authtoken <token>).
"""

import time
import threading
import subprocess
from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.prompt import Prompt
from core.utils import check_tool, run_cmd, port_in_use, log_event

console = Console()

_ngrok_proc: Optional[subprocess.Popen] = None


def _ngrok_api(endpoint: str, method: str = "GET", data: dict = None) -> Optional[dict]:
    try:
        import urllib.request, urllib.error, json
        url  = f"http://127.0.0.1:4040/api/{endpoint}"
        body = json.dumps(data).encode() if data else None
        req  = urllib.request.Request(url, data=body, method=method)
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def get_active_tunnels() -> list[dict]:
    data = _ngrok_api("tunnels")
    if data and "tunnels" in data:
        return data["tunnels"]
    return []


def start_ngrok_tcp(local_port: int) -> Optional[dict]:
    """Start an ngrok TCP tunnel. Returns {'host': ..., 'port': ...} or None."""
    if not check_tool("ngrok"):
        console.print("[red]✘ ngrok not found. Install from https://ngrok.com/download[/]")
        return None

    global _ngrok_proc

    # Check if agent already running
    tunnels = get_active_tunnels()
    for t in tunnels:
        if t.get("proto") == "tcp" and str(local_port) in t.get("config", {}).get("addr", ""):
            pub = t["public_url"].replace("tcp://", "")
            host, port = pub.rsplit(":", 1)
            return {"host": host, "port": int(port), "url": t["public_url"]}

    # Start ngrok agent if not running
    if not _ngrok_api("tunnels"):
        _ngrok_proc = subprocess.Popen(
            ["ngrok", "start", "--none", "--log", "stdout"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(3)  # wait for agent to initialise

    # Request TCP tunnel via API
    result = _ngrok_api("tunnels", method="POST", data={
        "name":  f"deaddroid_tcp_{local_port}",
        "proto": "tcp",
        "addr":  str(local_port),
    })

    if result and "public_url" in result:
        pub  = result["public_url"].replace("tcp://", "")
        host, port = pub.rsplit(":", 1)
        log_event(f"ngrok TCP tunnel: {pub} -> localhost:{local_port}")
        return {"host": host, "port": int(port), "url": result["public_url"]}

    console.print("[red]✘ Failed to start ngrok tunnel.[/]")
    return None


def start_ngrok_http(local_port: int) -> Optional[str]:
    """Start an ngrok HTTP tunnel. Returns the public HTTPS URL or None."""
    if not check_tool("ngrok"):
        console.print("[red]✘ ngrok not found.[/]")
        return None

    if not _ngrok_api("tunnels"):
        subprocess.Popen(
            ["ngrok", "start", "--none", "--log", "stdout"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(3)

    result = _ngrok_api("tunnels", method="POST", data={
        "name":  f"deaddroid_http_{local_port}",
        "proto": "http",
        "addr":  str(local_port),
    })

    if result and "public_url" in result:
        url = result["public_url"]
        if url.startswith("http://"):
            url = url.replace("http://", "https://")
        log_event(f"ngrok HTTP tunnel: {url} -> localhost:{local_port}")
        return url

    console.print("[red]✘ Failed to start ngrok HTTP tunnel.[/]")
    return None


def stop_all_tunnels():
    tunnels = get_active_tunnels()
    for t in tunnels:
        name = t.get("name", "")
        _ngrok_api(f"tunnels/{name}", method="DELETE")
        console.print(f"[yellow]  Stopped tunnel:[/] {name}")
    if _ngrok_proc:
        _ngrok_proc.terminate()
    console.print("[green]✔ All ngrok tunnels stopped.[/]")


def list_tunnels():
    tunnels = get_active_tunnels()
    if not tunnels:
        console.print("[yellow]No active ngrok tunnels.[/]")
        return

    from rich.table import Table
    t = Table(title="Active ngrok Tunnels", show_lines=True)
    t.add_column("Name",       style="cyan")
    t.add_column("Public URL", style="green")
    t.add_column("Local",      style="yellow")
    t.add_column("Proto",      style="white")
    for tn in tunnels:
        t.add_row(
            tn.get("name", ""),
            tn.get("public_url", ""),
            tn.get("config", {}).get("addr", ""),
            tn.get("proto", ""),
        )
    console.print(t)


def interactive_ngrok():
    console.rule("[bold cyan]ngrok Tunnel Manager[/]")
    options = {
        "1": "Start TCP tunnel",
        "2": "Start HTTP tunnel",
        "3": "List active tunnels",
        "4": "Stop all tunnels",
        "5": "Back",
    }
    from rich.table import Table
    m = Table(show_header=False, box=None)
    for k, v in options.items():
        m.add_row(f"[yellow][{k}][/]", v)
    console.print(m)

    choice = Prompt.ask("Select", choices=list(options.keys()), default="5")

    if choice == "1":
        from core.utils import find_free_port
        port = int(Prompt.ask("Local port", default=str(find_free_port(4444))))
        res  = start_ngrok_tcp(port)
        if res:
            console.print(f"[green]✔ TCP Tunnel:[/] {res['host']}:{res['port']}")
    elif choice == "2":
        port = int(Prompt.ask("Local port", default="8080"))
        url  = start_ngrok_http(port)
        if url:
            console.print(f"[green]✔ HTTP Tunnel:[/] {url}")
    elif choice == "3":
        list_tunnels()
    elif choice == "4":
        stop_all_tunnels()
