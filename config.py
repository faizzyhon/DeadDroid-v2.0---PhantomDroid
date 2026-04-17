"""
DeadDroid configuration — reads/writes ~/.deaddroid/config.json
"""

from pathlib import Path
from core.utils import WORKSPACE, save_json, load_json

CONFIG_FILE = WORKSPACE / "config.json"

DEFAULTS = {
    "msf_rpc_host":     "127.0.0.1",
    "msf_rpc_port":     55553,
    "msf_rpc_password": "msf123",
    "default_lhost":    "",
    "default_lport":    4444,
    "keepalive_interval": 60,
    "auto_sign_apk":    True,
    "ngrok_authtoken":  "",
    "theme":            "dark",
}


def get(key: str):
    cfg = load_json(CONFIG_FILE)
    return cfg.get(key, DEFAULTS.get(key))


def set_key(key: str, value):
    cfg = load_json(CONFIG_FILE)
    cfg[key] = value
    save_json(CONFIG_FILE, cfg)


def all_config() -> dict:
    cfg = load_json(CONFIG_FILE)
    merged = {**DEFAULTS, **cfg}
    return merged


def interactive_config():
    from rich.console import Console
    from rich.prompt import Prompt, IntPrompt, Confirm
    from rich.table import Table

    console = Console()
    console.rule("[bold cyan]Configuration[/]")

    cfg = all_config()

    t = Table(title="Current Settings", show_lines=True)
    t.add_column("Key",   style="cyan")
    t.add_column("Value", style="yellow")
    for k, v in cfg.items():
        display = "***" if "password" in k or "token" in k or "key" in k else str(v)
        t.add_row(k, display)
    console.print(t)

    if Confirm.ask("Edit a setting?", default=False):
        key   = Prompt.ask("Setting name", choices=list(DEFAULTS.keys()))
        value = Prompt.ask(f"New value for {key}")
        # Type coercion
        if isinstance(DEFAULTS.get(key), int):
            value = int(value)
        elif isinstance(DEFAULTS.get(key), bool):
            value = value.lower() in ("true", "1", "yes")
        set_key(key, value)
        console.print(f"[green]✔ {key} updated.[/]")
