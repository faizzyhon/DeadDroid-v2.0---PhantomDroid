import os
import sys
import shutil
import socket
import subprocess
import platform
import json
import hashlib
import random
import string
import time
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

WORKSPACE = Path.home() / ".deaddroid"
PAYLOADS_DIR  = WORKSPACE / "payloads"
SESSIONS_DIR  = WORKSPACE / "sessions"
REPORTS_DIR   = WORKSPACE / "reports"
LOGS_DIR      = WORKSPACE / "logs"
CERTS_DIR     = WORKSPACE / "certs"


def init_workspace():
    for d in [WORKSPACE, PAYLOADS_DIR, SESSIONS_DIR, REPORTS_DIR, LOGS_DIR, CERTS_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    console.print("[green]✔[/] Workspace initialised at [cyan]~/.deaddroid[/]")


def check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def require_tools(tools: list[str]) -> bool:
    missing = [t for t in tools if not check_tool(t)]
    if missing:
        console.print(f"[red]✘ Missing tools:[/] {', '.join(missing)}")
        console.print("[yellow]Install them and re-run.[/]")
        return False
    return True


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_public_ip() -> str:
    try:
        import urllib.request
        return urllib.request.urlopen("https://api.ipify.org", timeout=5).read().decode()
    except Exception:
        return "Unknown"


def random_str(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=length))


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()


def run_cmd(cmd: str, capture: bool = True, timeout: int = 120) -> tuple[int, str, str]:
    result = subprocess.run(
        cmd, shell=True, capture_output=capture,
        text=True, timeout=timeout
    )
    return result.returncode, result.stdout or "", result.stderr or ""


def is_linux() -> bool:
    return platform.system().lower() == "linux"


def is_root() -> bool:
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False


def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("localhost", port)) == 0


def find_free_port(start: int = 4444) -> int:
    port = start
    while port_in_use(port):
        port += 1
    return port


def print_table(title: str, headers: list[str], rows: list[list]):
    t = Table(title=title, show_lines=True, header_style="bold cyan")
    for h in headers:
        t.add_column(h)
    for row in rows:
        t.add_row(*[str(c) for c in row])
    console.print(t)


def spinner(message: str):
    return Progress(SpinnerColumn(), TextColumn(f"[cyan]{message}[/]"), transient=True)


def save_json(path: Path, data: dict):
    path.write_text(json.dumps(data, indent=2))


def load_json(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text())
    return {}


def log_event(msg: str):
    log_file = LOGS_DIR / "deaddroid.log"
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")
