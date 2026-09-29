#!/usr/bin/env python3
"""Read-only defensive keylogger-indicator detector.

This tool does not install keyboard hooks, capture keystrokes, modify the
registry, kill processes, or contact external services.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import platform
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

SUSPICIOUS_TERMS = {
    "setwindowshookex": 18,
    "getasynckeystate": 16,
    "getkeystate": 12,
    "lowlevelkeyboardproc": 16,
    "keyboardlistener": 12,
    "pynput": 10,
    "pyhook": 10,
    "keylogger": 22,
    "keylogging": 22,
    "inputcapture": 12,
    "win32api": 6,
    "win32gui": 6,
    "user32.dll": 4,
}
SUSPICIOUS_PATH_PARTS = {
    "\\appdata\\roaming\\": 7,
    "\\appdata\\local\\temp\\": 8,
    "\\startup\\": 12,
    "\\programdata\\": 4,
}
PERSISTENCE_LOCATIONS = (
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
)
CMDLINE_RE = re.compile(r"(?i)(setwindowshookex|getasynckeystate|getkeystate|"
                         r"lowlevelkeyboardproc|keyboardlistener|pynput|"
                         r"pyhook|keylogger|keylogging|inputcapture|win32api|win32gui|user32\.dll)")


@dataclass
class Finding:
    source: str
    severity: str
    detail: str
    weight: int


def severity_for(weight: int) -> str:
    if weight >= 15:
        return "high"
    if weight >= 8:
        return "medium"
    return "low"


def score_findings(findings: Iterable[Finding]) -> int:
    return min(100, sum(item.weight for item in findings))


def verdict_for(score: int) -> str:
    if score >= 60:
        return "high-risk-review"
    if score >= 30:
        return "suspicious-review"
    return "no-strong-indicator"


def inspect_text(text: str, source: str) -> list[Finding]:
    lowered = text.lower()
    findings: list[Finding] = []
    for term, weight in SUSPICIOUS_TERMS.items():
        if term in lowered:
            findings.append(Finding(
                source=source,
                severity=severity_for(weight),
                detail=f"suspicious indicator: {term}",
                weight=weight,
            ))
    for part, weight in SUSPICIOUS_PATH_PARTS.items():
        if part in lowered:
            findings.append(Finding(
                source=source,
                severity=severity_for(weight),
                detail=f"unusual execution location: {part}",
                weight=weight,
            ))
    return findings


def analyze_process_record(record: dict[str, Any]) -> dict[str, Any]:
    """Analyze a normalized process record; useful for tests and integrations."""
    name = str(record.get("name") or "")
    exe = str(record.get("exe") or "")
    cmdline = " ".join(str(value) for value in record.get("cmdline", []))
    findings = inspect_text(" ".join((name, exe, cmdline)), "process")
    return {
        "pid": record.get("pid"),
        "name": name,
        "exe": exe,
        "cmdline": cmdline,
        "findings": [asdict(item) for item in findings],
        "score": score_findings(findings),
    }


def collect_processes() -> tuple[list[dict[str, Any]], str | None]:
    """Collect basic process metadata with optional psutil support."""
    try:
        import psutil  # type: ignore
    except ImportError:
        psutil = None

    processes: list[dict[str, Any]] = []
    errors: list[str] = []
    if psutil is not None:
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                info = proc.info
                processes.append(analyze_process_record(info))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
            except Exception as exc:
                errors.append(type(exc).__name__)
    elif platform.system() == "Windows":
        try:
            completed = subprocess.run(
                ["tasklist", "/fo", "csv", "/nh"],
                check=True, capture_output=True, text=True, timeout=15,
            )
            for row in csv.reader(io.StringIO(completed.stdout)):
                if len(row) >= 2:
                    processes.append(analyze_process_record({
                        "pid": int(row[1]) if row[1].isdigit() else row[1],
                        "name": row[0],
                        "exe": "",
                        "cmdline": [],
                    }))
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(type(exc).__name__)
    else:
        errors.append("psutil-not-installed")
    return processes, "; ".join(sorted(set(errors))) or None


def read_windows_persistence() -> tuple[list[dict[str, Any]], str | None]:
    """Read Run/RunOnce registry values; never writes to the registry."""
    if platform.system() != "Windows":
        return [], "windows-only-check"
    try:
        import winreg
    except ImportError:
        return [], "winreg-unavailable"

    entries: list[dict[str, Any]] = []
    for location in PERSISTENCE_LOCATIONS:
        hive_name, subkey = location.split("\\", 1)
        hive = winreg.HKEY_CURRENT_USER if hive_name == "HKCU" else winreg.HKEY_LOCAL_MACHINE
        try:
            with winreg.OpenKey(hive, subkey) as key:
                for index in range(winreg.QueryInfoKey(key)[1]):
                    name, value, _ = winreg.EnumValue(key, index)
                    findings = inspect_text(f"{name} {value}", "registry")
                    entries.append({
                        "location": location,
                        "name": name,
                        "command": str(value),
                        "findings": [asdict(item) for item in findings],
                        "score": score_findings(findings),
                    })
        except (FileNotFoundError, PermissionError, OSError):
            continue
    return entries, None


def build_report() -> dict[str, Any]:
    processes, process_error = collect_processes()
    persistence, persistence_error = read_windows_persistence()
    findings: list[Finding] = []
    for item in processes + persistence:
        findings.extend(Finding(**finding) for finding in item["findings"])
    score = score_findings(findings)
    return {
        "tool": "Keylogger Detection Toolkit",
        "version": "1.0.0",
        "safe_mode": True,
        "captures_keystrokes": False,
        "modifies_system": False,
        "platform": platform.platform(),
        "process_count": len(processes),
        "processes": processes,
        "persistence_entries": persistence,
        "collection_notes": [note for note in (process_error, persistence_error) if note],
        "risk_score": score,
        "verdict": verdict_for(score),
        "limitations": [
            "Indicators are heuristic and require analyst review.",
            "A clean result does not prove that a system is free of keylogging malware.",
            "Full process visibility may require an elevated read-only session.",
            "The default checks do not inspect kernel drivers or memory contents.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only Windows keylogger-indicator detection"
    )
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args()
    report = build_report()
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    print(f"Platform:      {report['platform']}")
    print(f"Processes:     {report['process_count']}")
    print(f"Persistence:   {len(report['persistence_entries'])}")
    print(f"Risk score:     {report['risk_score']}/100")
    print(f"Verdict:        {report['verdict']}")
    print(f"Keyboard input captured: {report['captures_keystrokes']}")
    print(f"System modified:         {report['modifies_system']}")
    for process in report["processes"]:
        for finding in process["findings"]:
            print(f"[{finding['severity']}] PID {process['pid']}: {finding['detail']}")
    for entry in report["persistence_entries"]:
        for finding in entry["findings"]:
            print(f"[{finding['severity']}] {entry['location']}\\{entry['name']}: {finding['detail']}")
    for note in report["collection_notes"]:
        print(f"Note: {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
