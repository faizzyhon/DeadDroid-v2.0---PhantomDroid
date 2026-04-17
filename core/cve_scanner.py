"""
Android CVE Scanner — unique to DeadDroid.

Fingerprints a connected device's Android version + build info via ADB,
then checks it against a local CVE database and the NVD API to list
known unpatched vulnerabilities. Gives the tester an instant attack surface.

No other Android pentest tool has built-in CVE correlation.
"""

import json
import time
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import box
from core.utils import WORKSPACE, run_cmd, check_tool, log_event

console = Console()

CVE_CACHE = WORKSPACE / "cve_cache.json"

# Curated high-impact Android CVEs with version ranges
BUILTIN_CVES = [
    {
        "id":          "CVE-2023-21492",
        "description": "Kernel information disclosure via race condition",
        "severity":    "High",
        "cvss":        7.4,
        "affects":     {"min_api": 28, "max_api": 33},
        "patch_level": "2023-05-01",
    },
    {
        "id":          "CVE-2023-20963",
        "description": "WorkSource privilege escalation — allows app to run as system",
        "severity":    "High",
        "cvss":        7.8,
        "affects":     {"min_api": 30, "max_api": 33},
        "patch_level": "2023-03-01",
    },
    {
        "id":          "CVE-2022-20465",
        "description": "Lockscreen bypass — access device without PIN",
        "severity":    "Critical",
        "cvss":        9.1,
        "affects":     {"min_api": 30, "max_api": 32},
        "patch_level": "2022-11-01",
    },
    {
        "id":          "CVE-2022-20452",
        "description": "Permission bypass in NotificationManager leads to privilege escalation",
        "severity":    "High",
        "cvss":        8.4,
        "affects":     {"min_api": 30, "max_api": 33},
        "patch_level": "2022-12-01",
    },
    {
        "id":          "CVE-2021-39793",
        "description": "GPU driver heap OOB write — local privilege escalation",
        "severity":    "Critical",
        "cvss":        8.8,
        "affects":     {"min_api": 26, "max_api": 32},
        "patch_level": "2022-03-05",
    },
    {
        "id":          "CVE-2021-0954",
        "description": "Intent redirection in Android framework",
        "severity":    "High",
        "cvss":        7.3,
        "affects":     {"min_api": 26, "max_api": 31},
        "patch_level": "2021-12-01",
    },
    {
        "id":          "CVE-2020-0041",
        "description": "Binder OOB write — full root exploit chain available",
        "severity":    "Critical",
        "cvss":        9.8,
        "affects":     {"min_api": 26, "max_api": 29},
        "patch_level": "2020-03-01",
    },
    {
        "id":          "CVE-2019-2215",
        "description": "Use-after-free in Binder IPC driver — used in in-the-wild exploits",
        "severity":    "Critical",
        "cvss":        9.3,
        "affects":     {"min_api": 21, "max_api": 28},
        "patch_level": "2019-10-06",
    },
    {
        "id":          "CVE-2017-13156",
        "description": "Janus vulnerability — APK signature bypass allows code injection",
        "severity":    "High",
        "cvss":        7.8,
        "affects":     {"min_api": 21, "max_api": 26},
        "patch_level": "2017-12-01",
    },
    {
        "id":          "CVE-2015-3864",
        "description": "Stagefright — MMS media processing RCE",
        "severity":    "Critical",
        "cvss":        10.0,
        "affects":     {"min_api": 16, "max_api": 22},
        "patch_level": "2015-09-01",
    },
    {
        "id":          "CVE-2024-0044",
        "description": "run-as privilege escalation via PackageManager race condition",
        "severity":    "High",
        "cvss":        7.7,
        "affects":     {"min_api": 31, "max_api": 34},
        "patch_level": "2024-06-01",
    },
    {
        "id":          "CVE-2024-31317",
        "description": "ZygoteProcess command injection — system-level code execution",
        "severity":    "Critical",
        "cvss":        9.8,
        "affects":     {"min_api": 30, "max_api": 34},
        "patch_level": "2024-07-01",
    },
]


def _get_device_info_adb() -> Optional[dict]:
    """Fingerprint device via ADB."""
    if not check_tool("adb"):
        console.print("[red]✘ adb not found.[/]")
        return None

    props = {
        "android_version": "ro.build.version.release",
        "api_level":       "ro.build.version.sdk",
        "security_patch":  "ro.build.version.security_patch",
        "model":           "ro.product.model",
        "manufacturer":    "ro.product.manufacturer",
        "build_id":        "ro.build.id",
        "build_type":      "ro.build.type",
        "cpu_abi":         "ro.product.cpu.abi",
    }

    result = {}
    for key, prop in props.items():
        rc, out, _ = run_cmd(f"adb shell getprop {prop}", timeout=10)
        result[key] = out.strip() if rc == 0 else "Unknown"

    return result


def _version_to_api(version_str: str) -> int:
    version_api_map = {
        "15": 35, "14": 34, "13": 33, "12": 31, "11": 30,
        "10": 29, "9": 28,  "8.1": 27, "8.0": 26, "7.1": 25,
        "7.0": 24, "6.0": 23, "5.1": 22, "5.0": 21,
    }
    for v, api in version_api_map.items():
        if version_str.startswith(v):
            return api
    try:
        return int(version_str.split(".")[0]) + 20  # rough estimate
    except Exception:
        return 0


def _patch_level_to_date(patch: str) -> Optional[tuple[int, int, int]]:
    try:
        parts = patch.split("-")
        return int(parts[0]), int(parts[1]), int(parts[2])
    except Exception:
        return None


def _is_vulnerable(cve: dict, api_level: int, security_patch: str) -> bool:
    affects  = cve.get("affects", {})
    min_api  = affects.get("min_api", 0)
    max_api  = affects.get("max_api", 99)

    if not (min_api <= api_level <= max_api):
        return False

    # Check if security patch predates the fix
    patch_date = _patch_level_to_date(security_patch)
    fix_date   = _patch_level_to_date(cve.get("patch_level", "9999-12-01"))

    if patch_date and fix_date:
        return patch_date < fix_date

    return True  # conservative: flag it if we can't determine


def _query_nvd(keyword: str, android_version: str) -> list[dict]:
    """Query NVD API for recent Android CVEs."""
    try:
        query   = urllib.parse.quote(f"Android {android_version}")
        url     = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=10"
        req     = urllib.request.Request(url, headers={"User-Agent": "DeadDroid/2.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())

        results = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id   = cve_data.get("id", "")
            desc     = ""
            for d in cve_data.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:120]
                    break
            metrics  = cve_data.get("metrics", {})
            cvss     = 0.0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss = metrics[key][0].get("cvssData", {}).get("baseScore", 0.0)
                    break
            results.append({"id": cve_id, "description": desc, "cvss": cvss, "source": "NVD"})
        return results
    except Exception:
        return []


def scan_device(use_nvd: bool = False) -> list[dict]:
    """Main entry: fingerprint device, match CVEs, return findings."""
    console.print("[cyan]► Fingerprinting device via ADB...[/]")
    info = _get_device_info_adb()
    if not info:
        return []

    api_level = int(info.get("api_level", "0") or "0")
    if api_level == 0:
        api_level = _version_to_api(info.get("android_version", "0"))

    security_patch = info.get("security_patch", "1970-01-01")

    from rich.table import Table as RTable
    t = RTable(title="Device Fingerprint", show_lines=True)
    t.add_column("Property", style="cyan")
    t.add_column("Value",    style="yellow")
    for k, v in info.items():
        t.add_row(k.replace("_", " ").title(), v)
    console.print(t)

    console.print(f"\n[cyan]► Checking against CVE database (API={api_level}, Patch={security_patch})...[/]")

    vulns = [
        cve for cve in BUILTIN_CVES
        if _is_vulnerable(cve, api_level, security_patch)
    ]

    if use_nvd:
        console.print("[cyan]► Querying NVD API...[/]")
        nvd_results = _query_nvd("Android", info.get("android_version", ""))
        for r in nvd_results:
            r["severity"] = "High" if r.get("cvss", 0) >= 7 else "Medium"
            r["affects"]  = {}
        vulns.extend(nvd_results)

    if not vulns:
        console.print("[green]✔ No matching CVEs found for this device/patch level.[/]")
        return []

    # Display results
    result_table = RTable(
        title=f"[bold red]⚠  {len(vulns)} CVE(s) Found[/]",
        box=box.SIMPLE_HEAVY,
        show_lines=True,
    )
    result_table.add_column("CVE ID",      style="bold yellow")
    result_table.add_column("Severity",    style="red")
    result_table.add_column("CVSS",        style="magenta")
    result_table.add_column("Description", style="white")
    result_table.add_column("Patch Date",  style="dim")

    for v in sorted(vulns, key=lambda x: x.get("cvss", 0), reverse=True):
        sev = v.get("severity","")
        sev_colored = (
            f"[bold red]{sev}[/]"    if sev == "Critical" else
            f"[red]{sev}[/]"         if sev == "High"     else
            f"[yellow]{sev}[/]"      if sev == "Medium"   else
            f"[green]{sev}[/]"
        )
        result_table.add_row(
            v.get("id",""),
            sev_colored,
            str(v.get("cvss","")),
            v.get("description","")[:70],
            v.get("patch_level","NVD"),
        )
    console.print(result_table)
    log_event(f"CVE scan: device API={api_level} patch={security_patch} | found {len(vulns)} CVEs")
    return vulns


def scan_manual(android_version: str, security_patch: str) -> list[dict]:
    """Scan without ADB — provide version + patch level manually."""
    api_level = _version_to_api(android_version)
    console.print(f"[dim]  API level inferred: {api_level}[/]")

    vulns = [
        cve for cve in BUILTIN_CVES
        if _is_vulnerable(cve, api_level, security_patch)
    ]

    for v in sorted(vulns, key=lambda x: x.get("cvss", 0), reverse=True):
        console.print(
            f"  [bold yellow]{v['id']}[/]  CVSS {v['cvss']}  "
            f"[red]{v['severity']}[/]  {v['description'][:60]}"
        )
    return vulns


def interactive_cve():
    console.rule("[bold cyan]Android CVE Scanner[/]")

    menu = {
        "1": "Scan connected device (ADB)",
        "2": "Manual scan (enter version)",
        "3": "Back",
    }
    from rich.table import Table
    m = Table(show_header=False, box=None)
    for k, v in menu.items():
        m.add_row(f"[yellow][{k}][/]", v)
    console.print(m)

    choice = Prompt.ask("Select", choices=list(menu.keys()), default="3")

    if choice == "1":
        nvd = Confirm.ask("Also query NVD API? (requires internet)", default=False)
        scan_device(use_nvd=nvd)
    elif choice == "2":
        ver   = Prompt.ask("Android version (e.g. 12, 13, 14)")
        patch = Prompt.ask("Security patch level (YYYY-MM-DD)", default="2022-01-01")
        scan_manual(ver, patch)
