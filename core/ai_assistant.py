"""
AI Assistant — Claude-powered pentest advisor with prompt caching.
Sign in with your Anthropic API key to get real-time AI guidance.
"""

import os
import json
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.markdown import Markdown
from core.utils import WORKSPACE, save_json, load_json

console = Console()

CONFIG_FILE = WORKSPACE / "ai_config.json"

SYSTEM_PROMPT = """You are DeadDroid AI — an expert Android penetration testing assistant.
You assist authorised security professionals with:
- Android vulnerability assessment and penetration testing techniques
- Metasploit framework usage and payload strategies
- APK analysis and reverse engineering
- Network configuration, port forwarding, and tunneling
- Post-exploitation analysis on Android devices (authorised tests only)
- Writing pentest reports and findings documentation
- Defensive recommendations and patch advice

You always remind users that testing must be authorised. You do not assist with
illegal activities. You provide technical, accurate, actionable advice.
"""

_conversation_history: list[dict] = []
_api_key: Optional[str] = None


def load_api_key() -> Optional[str]:
    global _api_key
    cfg = load_json(CONFIG_FILE)
    if "api_key" in cfg:
        _api_key = cfg["api_key"]
        return _api_key
    env_key = os.environ.get("ANTHROPIC_API_KEY")
    if env_key:
        _api_key = env_key
        return _api_key
    return None


def save_api_key(key: str):
    global _api_key
    _api_key = key
    cfg = load_json(CONFIG_FILE)
    cfg["api_key"] = key
    save_json(CONFIG_FILE, cfg)
    console.print("[green]✔ API key saved.[/]")


def sign_in():
    console.rule("[bold cyan]Claude AI Sign-In[/]")
    console.print(
        "[dim]Get your free API key at:[/] [blue]https://console.anthropic.com[/]\n"
    )

    existing = load_api_key()
    if existing:
        masked = existing[:8] + "..." + existing[-4:]
        console.print(f"[yellow]Existing key found:[/] {masked}")
        if not Confirm.ask("Replace it?", default=False):
            return

    key = Prompt.ask("Enter Anthropic API key", password=True)
    if not key.startswith("sk-ant-"):
        console.print("[red]✘ Invalid key format. Should start with 'sk-ant-'[/]")
        return

    # Verify the key works
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=key)
        client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=10,
            messages=[{"role": "user", "content": "ping"}],
        )
        save_api_key(key)
        console.print("[bold green]✔ Claude AI connected successfully![/]")
    except ImportError:
        console.print("[red]✘ anthropic package not installed.[/]  Run: pip install anthropic")
    except Exception as e:
        console.print(f"[red]✘ Verification failed:[/] {e}")


def sign_out():
    global _api_key
    cfg = load_json(CONFIG_FILE)
    cfg.pop("api_key", None)
    save_json(CONFIG_FILE, cfg)
    _api_key = None
    _conversation_history.clear()
    console.print("[yellow]Signed out of Claude AI.[/]")


def chat(user_message: str) -> Optional[str]:
    key = _api_key or load_api_key()
    if not key:
        console.print("[red]✘ Not signed in. Use 'AI Assistant > Sign In'.[/]")
        return None

    try:
        import anthropic
    except ImportError:
        console.print("[red]✘ anthropic package not installed.[/]  Run: pip install anthropic")
        return None

    _conversation_history.append({"role": "user", "content": user_message})

    # Keep last 20 turns in history
    if len(_conversation_history) > 40:
        del _conversation_history[:2]

    try:
        client = anthropic.Anthropic(api_key=key)

        # Use prompt caching on the system prompt for efficiency
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=[
                {
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=_conversation_history,
        )

        reply = response.content[0].text
        _conversation_history.append({"role": "assistant", "content": reply})
        return reply

    except Exception as e:
        console.print(f"[red]✘ API error:[/] {e}")
        _conversation_history.pop()  # remove the unanswered user message
        return None


def interactive_ai():
    console.rule("[bold cyan]DeadDroid AI Assistant — Powered by Claude[/]")

    key = load_api_key()
    if not key:
        console.print("[yellow]Not signed in.[/]")
        sign_in()
        key = _api_key

    if not key:
        return

    console.print(
        Panel(
            "[bold white]Ask anything about Android pentesting, Metasploit, payloads,\n"
            "network setup, post-exploitation, or report writing.[/]\n\n"
            "[dim]Commands: /clear (reset chat)  /exit (back to menu)[/]",
            title="[bold cyan]DeadDroid AI[/]",
            border_style="cyan",
        )
    )

    while True:
        try:
            user_input = Prompt.ask("\n[bold green]You[/]")
        except (KeyboardInterrupt, EOFError):
            break

        if not user_input.strip():
            continue

        if user_input.strip() == "/exit":
            break

        if user_input.strip() == "/clear":
            _conversation_history.clear()
            console.print("[yellow]Conversation cleared.[/]")
            continue

        with console.status("[cyan]Claude is thinking...[/]", spinner="dots"):
            reply = chat(user_input)

        if reply:
            console.print(
                Panel(
                    Markdown(reply),
                    title="[bold cyan]Claude[/]",
                    border_style="cyan",
                    padding=(1, 2),
                )
            )


def ai_status() -> str:
    key = load_api_key()
    if key:
        return f"[green]✔ Signed in[/] ({key[:8]}...)"
    return "[red]✘ Not signed in[/]"
