"""
Network module — port forwarding, SSH tunnels, reverse tunnels, socat helpers.
"""

import subprocess
import threading
import time
from typing import Optional
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from core.utils import check_tool, port_in_use, find_free_port, get_local_ip, get_public_ip, log_event

console = Console()

_processes: dict[str, subprocess.Popen] = {}


# ── socat ──────────────────────────────────────────────────────────────────────

def socat_forward(local_port: int, remote_host: str, remote_port: int) -> bool:
    """Forward local_port → remote_host:remote_port via socat."""
    if not check_tool("socat"):
        console.print("[red]✘ socat not installed.[/]")
        return False

    key = f"socat_{local_port}"
    if key in _processes:
        console.print(f"[yellow]Port {local_port} already forwarded.[/]")
        return True

    cmd = ["socat", f"TCP-LISTEN:{local_port},fork", f"TCP:{remote_host}:{remote_port}"]
    p   = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _processes[key] = p
    log_event(f"socat forward: {local_port} -> {remote_host}:{remote_port}")
    console.print(f"[green]✔ socat forwarding[/] :{local_port} → {remote_host}:{remote_port}  (PID {p.pid})")
    return True


def socat_reverse(listen_port: int, callback_host: str, callback_port: int) -> bool:
    """Open a reverse socat listener."""
    if not check_tool("socat"):
        console.print("[red]✘ socat not installed.[/]")
        return False

    key = f"socat_rev_{listen_port}"
    cmd = [
        "socat",
        f"TCP-LISTEN:{listen_port},fork,reuseaddr",
        f"TCP:{callback_host}:{callback_port}",
    ]
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _processes[key] = p
    log_event(f"socat reverse: {listen_port} -> {callback_host}:{callback_port}")
    console.print(f"[green]✔ socat reverse[/] :{listen_port} → {callback_host}:{callback_port}")
    return True


# ── SSH tunnel ──────────────────────────────────────────────────────────────────

def ssh_local_forward(
    local_port: int,
    remote_host: str,
    remote_port: int,
    ssh_host: str,
    ssh_user: str,
    ssh_key: Optional[str] = None,
    ssh_port: int = 22,
) -> bool:
    """SSH -L tunnel: localhost:local_port → remote_host:remote_port via SSH server."""
    if not check_tool("ssh"):
        console.print("[red]✘ ssh not found.[/]")
        return False

    key = f"ssh_L_{local_port}"
    key_flag = f"-i {ssh_key}" if ssh_key else ""
    cmd = (
        f"ssh -N -L {local_port}:{remote_host}:{remote_port} "
        f"{key_flag} -p {ssh_port} -o StrictHostKeyChecking=no "
        f"{ssh_user}@{ssh_host}"
    )
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _processes[key] = p
    log_event(f"SSH -L {local_port}:{remote_host}:{remote_port} via {ssh_user}@{ssh_host}")
    console.print(f"[green]✔ SSH local forward[/] :{local_port} → {remote_host}:{remote_port}")
    return True


def ssh_reverse_forward(
    remote_port: int,
    local_port: int,
    ssh_host: str,
    ssh_user: str,
    ssh_key: Optional[str] = None,
    ssh_port: int = 22,
) -> bool:
    """SSH -R tunnel: expose local_port as remote_port on SSH server."""
    if not check_tool("ssh"):
        console.print("[red]✘ ssh not found.[/]")
        return False

    key = f"ssh_R_{remote_port}"
    key_flag = f"-i {ssh_key}" if ssh_key else ""
    cmd = (
        f"ssh -N -R {remote_port}:localhost:{local_port} "
        f"{key_flag} -p {ssh_port} -o StrictHostKeyChecking=no "
        f"{ssh_user}@{ssh_host}"
    )
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _processes[key] = p
    log_event(f"SSH -R {remote_port}:localhost:{local_port} via {ssh_user}@{ssh_host}")
    console.print(f"[green]✔ SSH reverse forward[/] remote:{remote_port} ← local:{local_port}")
    return True


# ── iptables ────────────────────────────────────────────────────────────────────

def iptables_forward(local_port: int, dest_host: str, dest_port: int) -> bool:
    """iptables PREROUTING redirect — requires root."""
    if not check_tool("iptables"):
        console.print("[red]✘ iptables not found.[/]")
        return False

    import os
    if os.geteuid() != 0:
        console.print("[red]✘ iptables requires root privileges.[/]")
        return False

    cmds = [
        f"iptables -t nat -A PREROUTING -p tcp --dport {local_port} "
        f"-j DNAT --to-destination {dest_host}:{dest_port}",
        "iptables -t nat -A POSTROUTING -j MASQUERADE",
        "echo 1 > /proc/sys/net/ipv4/ip_forward",
    ]
    for c in cmds:
        subprocess.run(c, shell=True)

    log_event(f"iptables PREROUTING: :{local_port} -> {dest_host}:{dest_port}")
    console.print(f"[green]✔ iptables rule added:[/] :{local_port} → {dest_host}:{dest_port}")
    return True


# ── Process manager ─────────────────────────────────────────────────────────────

def list_forwarders():
    if not _processes:
        console.print("[yellow]No active port forwarders.[/]")
        return

    from rich.table import Table
    t = Table(title="Active Port Forwarders", show_lines=True)
    t.add_column("Key",   style="cyan")
    t.add_column("PID",   style="yellow")
    t.add_column("Status")
    for k, p in _processes.items():
        status = "[green]running[/]" if p.poll() is None else "[red]stopped[/]"
        t.add_row(k, str(p.pid), status)
    console.print(t)


def stop_forwarder(key: str):
    if key in _processes:
        _processes[key].terminate()
        del _processes[key]
        console.print(f"[green]✔ Stopped:[/] {key}")
    else:
        console.print(f"[red]✘ Not found:[/] {key}")


def stop_all_forwarders():
    for k, p in list(_processes.items()):
        p.terminate()
        console.print(f"[yellow]  Stopped:[/] {k}")
    _processes.clear()
    console.print("[green]✔ All forwarders stopped.[/]")


def interactive_network():
    console.rule("[bold cyan]Network & Port Forwarding[/]")

    local_ip  = get_local_ip()
    public_ip = get_public_ip()
    console.print(f"[dim]  Local IP:[/] {local_ip}   [dim]Public IP:[/] {public_ip}\n")

    menu = {
        "1": "socat port forward",
        "2": "socat reverse",
        "3": "SSH local forward (-L)",
        "4": "SSH reverse forward (-R)",
        "5": "iptables PREROUTING",
        "6": "List active forwarders",
        "7": "Stop a forwarder",
        "8": "Stop all forwarders",
        "9": "Back",
    }

    from rich.table import Table
    m = Table(show_header=False, box=None)
    for k, v in menu.items():
        m.add_row(f"[yellow][{k}][/]", v)
    console.print(m)

    choice = Prompt.ask("Select", choices=list(menu.keys()), default="9")

    if choice == "1":
        lp = IntPrompt.ask("Local port", default=find_free_port(8080))
        rh = Prompt.ask("Remote host")
        rp = IntPrompt.ask("Remote port")
        socat_forward(lp, rh, rp)

    elif choice == "2":
        lp = IntPrompt.ask("Listen port")
        ch = Prompt.ask("Callback host")
        cp = IntPrompt.ask("Callback port")
        socat_reverse(lp, ch, cp)

    elif choice == "3":
        lp   = IntPrompt.ask("Local port", default=find_free_port(4444))
        rh   = Prompt.ask("Remote host (through SSH server)")
        rp   = IntPrompt.ask("Remote port")
        sh   = Prompt.ask("SSH server host")
        su   = Prompt.ask("SSH user", default="root")
        skey = Prompt.ask("SSH key path (blank = password auth)", default="")
        sp   = IntPrompt.ask("SSH port", default=22)
        ssh_local_forward(lp, rh, rp, sh, su, skey or None, sp)

    elif choice == "4":
        rp   = IntPrompt.ask("Remote port (on SSH server)")
        lp   = IntPrompt.ask("Local port to expose")
        sh   = Prompt.ask("SSH server host")
        su   = Prompt.ask("SSH user", default="root")
        skey = Prompt.ask("SSH key path (blank = password auth)", default="")
        sp   = IntPrompt.ask("SSH port", default=22)
        ssh_reverse_forward(rp, lp, sh, su, skey or None, sp)

    elif choice == "5":
        lp = IntPrompt.ask("Local port to intercept")
        dh = Prompt.ask("Destination host")
        dp = IntPrompt.ask("Destination port")
        iptables_forward(lp, dh, dp)

    elif choice == "6":
        list_forwarders()

    elif choice == "7":
        list_forwarders()
        key = Prompt.ask("Enter key to stop")
        stop_forwarder(key)

    elif choice == "8":
        stop_all_forwarders()
