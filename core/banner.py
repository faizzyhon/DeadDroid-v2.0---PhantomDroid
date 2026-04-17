from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.align import Align
import random

console = Console()

BANNER = r"""
██████╗ ███████╗ █████╗ ██████╗ ██████╗ ██████╗  ██████╗ ██╗██████╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗
██║  ██║█████╗  ███████║██║  ██║██║  ██║██████╔╝██║   ██║██║██║  ██║
██║  ██║██╔══╝  ██╔══██║██║  ██║██║  ██║██╔══██╗██║   ██║██║██║  ██║
██████╔╝███████╗██║  ██║██████╔╝██████╔╝██║  ██║╚██████╔╝██║██████╔╝
╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝
"""

VERSION   = "2.0.0"
CODENAME  = "PhantomDroid"
AUTHOR    = "faizzyhon"
GITHUB    = "https://github.com/faizzyhon"
TELEGRAM  = "https://t.me/faizzyhon"
WEBSITE   = "https://faizzyhon.dev"
LINKEDIN  = "https://linkedin.com/in/faizzyhon"


def show_banner():
    colors = ["bold red", "bold cyan", "bold magenta", "bold yellow"]
    color  = random.choice(colors)

    console.print(f"[{color}]{BANNER}[/{color}]")

    info = (
        f"[bold white]  Version  :[/] [green]{VERSION}[/]  [bold white]Code:[/] [cyan]{CODENAME}[/]\n"
        f"[bold white]  Author   :[/] [yellow]{AUTHOR}[/]\n"
        f"[bold white]  GitHub   :[/] [blue]{GITHUB}[/]\n"
        f"[bold white]  Telegram :[/] [cyan]{TELEGRAM}[/]\n"
        f"[bold white]  Website  :[/] [magenta]{WEBSITE}[/]\n"
        f"[bold white]  LinkedIn :[/] [blue]{LINKEDIN}[/]\n"
        f"\n[bold red]  ⚠  For authorized penetration testing ONLY. Misuse is illegal.[/]"
    )

    console.print(Panel(info, title="[bold red]◈ DeadDroid ◈[/]", border_style="red"))
    console.print()


def show_module_header(title: str, subtitle: str = ""):
    console.print(Panel(
        Align.center(f"[bold yellow]{title}[/]\n[dim]{subtitle}[/]"),
        border_style="cyan"
    ))
