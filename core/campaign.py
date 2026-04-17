"""
Campaign Manager — unique to DeadDroid.
Track multiple targets, payloads, sessions, notes and timelines
in a single persistent campaign. No other Android pentest tool has this.
"""

import time
import uuid
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from core.utils import WORKSPACE, save_json, load_json, log_event

console = Console()

CAMPAIGNS_DIR = WORKSPACE / "campaigns"
CAMPAIGNS_DIR.mkdir(parents=True, exist_ok=True)


# ── Data model ──────────────────────────────────────────────────────────────────

def _new_campaign(name: str, description: str, tester: str) -> dict:
    return {
        "id":          str(uuid.uuid4())[:8],
        "name":        name,
        "description": description,
        "tester":      tester,
        "created":     time.strftime("%Y-%m-%d %H:%M"),
        "status":      "active",
        "targets":     [],
        "payloads":    [],
        "sessions":    [],
        "notes":       [],
        "timeline":    [],
    }


def _campaign_path(cid: str) -> Path:
    return CAMPAIGNS_DIR / f"{cid}.json"


def _load_all() -> list[dict]:
    return [load_json(p) for p in sorted(CAMPAIGNS_DIR.glob("*.json"))]


def _load(cid: str) -> Optional[dict]:
    p = _campaign_path(cid)
    if p.exists():
        return load_json(p)
    return None


def _save(campaign: dict):
    save_json(_campaign_path(campaign["id"]), campaign)


def _add_timeline(campaign: dict, event: str):
    campaign["timeline"].append({
        "time":  time.strftime("%Y-%m-%d %H:%M:%S"),
        "event": event,
    })


# ── CRUD ────────────────────────────────────────────────────────────────────────

def create_campaign() -> dict:
    name  = Prompt.ask("Campaign name")
    desc  = Prompt.ask("Description")
    tester = Prompt.ask("Tester name", default="faizzyhon")
    c     = _new_campaign(name, desc, tester)
    _save(c)
    log_event(f"Campaign created: {c['id']} — {name}")
    console.print(f"[green]✔ Campaign created:[/] ID=[yellow]{c['id']}[/]  Name={name}")
    return c


def list_campaigns():
    campaigns = _load_all()
    if not campaigns:
        console.print("[yellow]No campaigns found.[/]")
        return

    t = Table(title="[bold cyan]Campaigns[/]", box=box.SIMPLE_HEAVY, show_lines=True)
    t.add_column("ID",          style="yellow")
    t.add_column("Name",        style="bold white")
    t.add_column("Status",      style="green")
    t.add_column("Targets",     style="cyan")
    t.add_column("Payloads",    style="magenta")
    t.add_column("Sessions",    style="red")
    t.add_column("Created",     style="dim")

    for c in campaigns:
        status = "[green]Active[/]" if c["status"] == "active" else "[dim]Closed[/]"
        t.add_row(
            c["id"], c["name"], status,
            str(len(c.get("targets", []))),
            str(len(c.get("payloads", []))),
            str(len(c.get("sessions", []))),
            c.get("created", ""),
        )
    console.print(t)


def select_campaign() -> Optional[dict]:
    list_campaigns()
    campaigns = _load_all()
    if not campaigns:
        return None
    cid = Prompt.ask("Enter campaign ID")
    return _load(cid.strip())


# ── Target management ───────────────────────────────────────────────────────────

def add_target(campaign: dict):
    target = {
        "id":     str(uuid.uuid4())[:6],
        "name":   Prompt.ask("Target name / alias"),
        "device": Prompt.ask("Device model (optional)", default=""),
        "os":     Prompt.ask("Android version (optional)", default=""),
        "notes":  Prompt.ask("Notes", default=""),
        "added":  time.strftime("%Y-%m-%d %H:%M"),
        "status": "pending",
    }
    campaign["targets"].append(target)
    _add_timeline(campaign, f"Target added: {target['name']}")
    _save(campaign)
    console.print(f"[green]✔ Target added:[/] {target['name']} (ID={target['id']})")


def list_targets(campaign: dict):
    targets = campaign.get("targets", [])
    if not targets:
        console.print("[yellow]No targets in this campaign.[/]")
        return

    t = Table(title="Targets", show_lines=True)
    t.add_column("ID",     style="yellow")
    t.add_column("Name",   style="bold")
    t.add_column("Device", style="cyan")
    t.add_column("OS",     style="magenta")
    t.add_column("Status", style="green")
    t.add_column("Notes",  style="dim")

    for tgt in targets:
        t.add_row(
            tgt["id"], tgt["name"], tgt.get("device",""),
            tgt.get("os",""), tgt.get("status","pending"),
            tgt.get("notes","")[:30],
        )
    console.print(t)


def update_target_status(campaign: dict):
    list_targets(campaign)
    tid    = Prompt.ask("Target ID")
    status = Prompt.ask("New status", choices=["pending","active","compromised","failed","completed"])
    for tgt in campaign["targets"]:
        if tgt["id"] == tid:
            tgt["status"] = status
            _add_timeline(campaign, f"Target {tgt['name']} status → {status}")
            _save(campaign)
            console.print(f"[green]✔ Updated.[/]")
            return
    console.print("[red]Target not found.[/]")


# ── Payload linking ─────────────────────────────────────────────────────────────

def link_payload(campaign: dict, payload_path: str, lhost: str, lport: int, target_id: str = ""):
    entry = {
        "id":        str(uuid.uuid4())[:6],
        "path":      payload_path,
        "lhost":     lhost,
        "lport":     lport,
        "target_id": target_id,
        "generated": time.strftime("%Y-%m-%d %H:%M"),
        "sessions":  [],
    }
    campaign["payloads"].append(entry)
    _add_timeline(campaign, f"Payload linked: {payload_path} → {lhost}:{lport}")
    _save(campaign)
    console.print(f"[green]✔ Payload linked to campaign.[/]  ID={entry['id']}")


def list_payloads(campaign: dict):
    payloads = campaign.get("payloads", [])
    if not payloads:
        console.print("[yellow]No payloads in this campaign.[/]")
        return
    t = Table(title="Payloads", show_lines=True)
    t.add_column("ID",     style="yellow")
    t.add_column("Path",   style="cyan")
    t.add_column("LHOST",  style="green")
    t.add_column("LPORT",  style="magenta")
    t.add_column("Target", style="white")
    t.add_column("When",   style="dim")
    for p in payloads:
        t.add_row(
            p["id"], str(p["path"])[-40:],
            p.get("lhost",""), str(p.get("lport","")),
            p.get("target_id",""), p.get("generated",""),
        )
    console.print(t)


# ── Session linking ─────────────────────────────────────────────────────────────

def link_session(campaign: dict, session_id: int, payload_id: str = "", target_id: str = ""):
    entry = {
        "session_id":  session_id,
        "payload_id":  payload_id,
        "target_id":   target_id,
        "opened":      time.strftime("%Y-%m-%d %H:%M:%S"),
        "closed":      None,
    }
    campaign["sessions"].append(entry)
    _add_timeline(campaign, f"Session {session_id} opened (payload={payload_id}, target={target_id})")
    _save(campaign)


# ── Notes ───────────────────────────────────────────────────────────────────────

def add_note(campaign: dict):
    note = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "text": Prompt.ask("Note"),
    }
    campaign["notes"].append(note)
    _add_timeline(campaign, f"Note added")
    _save(campaign)
    console.print("[green]✔ Note saved.[/]")


def view_notes(campaign: dict):
    for n in campaign.get("notes", []):
        console.print(f"[dim]{n['time']}[/]  {n['text']}")


# ── Timeline ────────────────────────────────────────────────────────────────────

def view_timeline(campaign: dict):
    console.rule(f"[bold cyan]Timeline — {campaign['name']}[/]")
    for ev in campaign.get("timeline", []):
        console.print(f"  [dim]{ev['time']}[/]  {ev['event']}")


# ── Close campaign ──────────────────────────────────────────────────────────────

def close_campaign(campaign: dict):
    campaign["status"] = "closed"
    _add_timeline(campaign, "Campaign closed")
    _save(campaign)
    console.print("[yellow]Campaign closed.[/]")


# ── Export to report ────────────────────────────────────────────────────────────

def export_to_report(campaign: dict):
    from core.reporter import generate_report

    targets_str = ", ".join(t["name"] for t in campaign.get("targets", []))
    findings    = []
    for note in campaign.get("notes", []):
        findings.append({
            "title":          "Observation",
            "severity":       "Info",
            "description":    note["text"],
            "impact":         "",
            "evidence":       "",
            "recommendation": "",
        })

    payloads_data = [
        {
            "name":  p.get("path","")[-30:],
            "type":  "meterpreter/reverse_tcp",
            "lhost": p.get("lhost",""),
            "lport": p.get("lport",""),
            "notes": f"target={p.get('target_id','')}",
        }
        for p in campaign.get("payloads", [])
    ]

    path = generate_report(
        title=campaign["name"],
        tester=campaign.get("tester",""),
        target=targets_str or "Multiple",
        summary=campaign.get("description",""),
        findings=findings,
        payloads=payloads_data,
    )
    console.print(f"[green]✔ Report exported:[/] {path}")


# ── Interactive ─────────────────────────────────────────────────────────────────

def interactive_campaign():
    console.rule("[bold cyan]Campaign Manager[/]")

    outer_menu = {
        "1": "New campaign",
        "2": "Open campaign",
        "3": "Back",
    }
    from rich.table import Table
    m = Table(show_header=False, box=None)
    for k, v in outer_menu.items():
        m.add_row(f"[yellow][{k}][/]", v)
    console.print(m)
    outer = Prompt.ask("Select", choices=list(outer_menu.keys()), default="3")

    if outer == "1":
        campaign = create_campaign()
    elif outer == "2":
        campaign = select_campaign()
        if not campaign:
            return
    else:
        return

    # Inner campaign menu
    while True:
        console.rule(f"[bold yellow]{campaign['name']}[/]  [dim](ID={campaign['id']})[/]")

        inner = {
            "1":  "Add target",
            "2":  "List targets",
            "3":  "Update target status",
            "4":  "Link payload",
            "5":  "List payloads",
            "6":  "Add note",
            "7":  "View notes",
            "8":  "View timeline",
            "9":  "Export to HTML report",
            "10": "Close campaign",
            "0":  "Back",
        }
        m2 = Table(show_header=False, box=None)
        for k, v in inner.items():
            m2.add_row(f"[yellow][{k:>2}][/]", v)
        console.print(m2)

        choice = Prompt.ask("Select", choices=list(inner.keys()), default="0")

        if choice == "0":
            break
        elif choice == "1":
            add_target(campaign)
        elif choice == "2":
            list_targets(campaign)
        elif choice == "3":
            update_target_status(campaign)
        elif choice == "4":
            pp = Prompt.ask("Payload path")
            lh = Prompt.ask("LHOST")
            lp = int(Prompt.ask("LPORT"))
            ti = Prompt.ask("Target ID (optional)", default="")
            link_payload(campaign, pp, lh, lp, ti)
        elif choice == "5":
            list_payloads(campaign)
        elif choice == "6":
            add_note(campaign)
        elif choice == "7":
            view_notes(campaign)
        elif choice == "8":
            view_timeline(campaign)
        elif choice == "9":
            export_to_report(campaign)
        elif choice == "10":
            close_campaign(campaign)
            break
