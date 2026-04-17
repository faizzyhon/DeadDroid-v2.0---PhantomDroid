"""
Live Real-Time Session Dashboard — unique to DeadDroid.
Shows all active sessions, health, device info, keepalive status
in a live-refreshing Rich TUI. No other Android pentest tool has this.
"""

import time
import threading
from datetime import datetime
from typing import Optional
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt
from rich.align import Align
from rich import box
from core.utils import log_event, get_local_ip

console = Console()

_session_meta: dict[str, dict] = {}   # sid -> {first_seen, last_seen, cmd_count, location}
_lock = threading.Lock()


def _format_uptime(first_seen: float) -> str:
    secs = int(time.time() - first_seen)
    h, rem = divmod(secs, 3600)
    m, s   = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def _health_bar(pct: int) -> Text:
    filled = int(pct / 10)
    bar    = "█" * filled + "░" * (10 - filled)
    color  = "green" if pct > 60 else "yellow" if pct > 30 else "red"
    return Text(f"[{bar}] {pct}%", style=color)


def _build_session_table(sessions: dict) -> Table:
    t = Table(
        title="[bold red]◈ Active Sessions[/]",
        box=box.SIMPLE_HEAVY,
        show_lines=True,
        header_style="bold cyan",
        min_width=100,
    )
    t.add_column("ID",        width=5,  style="bold yellow")
    t.add_column("Type",      width=12, style="cyan")
    t.add_column("Device",    width=22)
    t.add_column("Platform",  width=10, style="magenta")
    t.add_column("Tunnel",    width=22, style="green")
    t.add_column("Uptime",    width=10)
    t.add_column("Cmds",      width=6,  style="dim")
    t.add_column("Keepalive", width=12)
    t.add_column("Location",  width=20, style="yellow")

    if not sessions:
        t.add_row(*["—"] * 9)
        return t

    for sid, info in sessions.items():
        with _lock:
            meta = _session_meta.get(str(sid), {})

        uptime   = _format_uptime(meta.get("first_seen", time.time()))
        cmds     = str(meta.get("cmd_count", 0))
        location = meta.get("location", "Unknown")

        from core.session_mgr import _keepalive_threads
        ka_alive = str(sid) in [str(k) for k in _keepalive_threads] and \
                   _keepalive_threads.get(int(sid), threading.Thread()).is_alive()
        ka_str   = "[green]● Active[/]" if ka_alive else "[dim]○ Off[/]"

        t.add_row(
            str(sid),
            info.get("type", ""),
            info.get("info", "")[:20],
            info.get("platform", ""),
            info.get("tunnel_local", "")[:20],
            uptime,
            cmds,
            ka_str,
            location[:18],
        )
    return t


def _build_stats_panel(sessions: dict) -> Panel:
    total  = len(sessions)
    active = sum(1 for s in sessions.values() if s.get("type"))
    local  = get_local_ip()
    now    = datetime.now().strftime("%H:%M:%S")

    content = (
        f"[bold white]Sessions:[/]  [green]{total}[/] total  [cyan]{active}[/] active\n"
        f"[bold white]Local IP:[/]  [cyan]{local}[/]\n"
        f"[bold white]Time:[/]      [dim]{now}[/]\n"
        f"[bold white]Dashboard:[/] [green]LIVE[/] [dim](refreshes every 2s)[/]"
    )
    return Panel(content, title="[bold red]System Status[/]", border_style="red", width=40)


def _build_quickcmd_panel() -> Panel:
    cmds = (
        "[dim]While dashboard is running:[/]\n"
        "[yellow]Ctrl+C[/] → Exit dashboard\n\n"
        "[bold white]Auto-actions on new session:[/]\n"
        "  • Keepalive started\n"
        "  • Telegram notified\n"
        "  • Device info logged"
    )
    return Panel(cmds, title="[bold cyan]Info[/]", border_style="cyan", width=38)


def _build_layout(sessions: dict) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header",  size=3),
        Layout(name="body"),
        Layout(name="footer",  size=3),
    )
    layout["body"].split_row(
        Layout(name="sessions", ratio=3),
        Layout(name="sidebar",  ratio=1),
    )
    layout["sidebar"].split_column(
        Layout(name="stats"),
        Layout(name="quick"),
    )

    layout["header"].update(Panel(
        Align.center("[bold red]◈ DeadDroid Live Dashboard ◈[/]  [dim]Real-time session monitoring[/]"),
        border_style="red",
    ))
    layout["sessions"].update(_build_session_table(sessions))
    layout["stats"].update(_build_stats_panel(sessions))
    layout["quick"].update(_build_quickcmd_panel())
    layout["footer"].update(Panel(
        Align.center("[dim]github.com/faizzyhon | faizzyhon.dev | t.me/faizzyhon[/]"),
        border_style="dim",
    ))
    return layout


def _register_session(sid, info: dict):
    with _lock:
        if str(sid) not in _session_meta:
            _session_meta[str(sid)] = {
                "first_seen": time.time(),
                "cmd_count":  0,
                "location":   "Unknown",
            }
            log_event(f"Dashboard registered new session {sid}")


def run_dashboard(refresh_interval: float = 2.0, auto_keepalive: bool = True):
    """
    Launch the live dashboard. Polls Metasploit RPC every refresh_interval seconds.
    Auto-starts keepalive and Telegram notification for every new session.
    """
    from core.session_mgr import list_sessions, start_keepalive, MSF_AVAILABLE, _client

    if not MSF_AVAILABLE or _client is None:
        console.print("[red]✘ Not connected to Metasploit RPC.[/]  Connect via Session Manager first.")
        return

    known_sids: set = set()

    try:
        with Live(console=console, refresh_per_second=1, screen=True) as live:
            while True:
                sessions = list_sessions()

                # Detect new sessions
                current = set(str(k) for k in sessions)
                new     = current - known_sids
                for sid in new:
                    sid_int = int(sid)
                    info    = sessions.get(sid, sessions.get(sid_int, {}))
                    _register_session(sid, info)

                    if auto_keepalive:
                        start_keepalive(sid_int, interval=60)

                    # Telegram notify
                    try:
                        from core.telegram_bot import notify_new_session
                        notify_new_session(sid_int, info)
                    except Exception:
                        pass

                known_sids = current
                live.update(_build_layout(sessions))
                time.sleep(refresh_interval)

    except KeyboardInterrupt:
        console.print("\n[yellow]Dashboard closed.[/]")


def interactive_dashboard():
    console.rule("[bold red]Live Dashboard[/]")
    console.print("[dim]Requires active Metasploit RPC connection.[/]\n")

    auto_ka = True
    try:
        from rich.prompt import Confirm
        auto_ka = Confirm.ask("Auto-start keepalive on new sessions?", default=True)
    except Exception:
        pass

    run_dashboard(auto_keepalive=auto_ka)
