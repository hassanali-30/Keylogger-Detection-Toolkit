# Keylogger Detection Toolkit

[![CI](https://github.com/hassanali-30/Keylogger-Detection-Toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/hassanali-30/Keylogger-Detection-Toolkit/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

A read-only, defensive Windows toolkit for identifying indicators commonly associated with keylogger activity.

> **Safety boundary:** This project never captures keystrokes, installs keyboard hooks, modifies the registry, terminates processes, or contacts external services.

## Checks

- Running-process names, executable paths, and command lines
- Indicators such as `SetWindowsHookEx`, `GetAsyncKeyState`, `LowLevelKeyboardProc`, `pynput`, and `keylogger`
- Unusual execution locations such as user startup, roaming AppData, temporary folders, and ProgramData
- Windows `Run` and `RunOnce` persistence values
- Explainable per-finding severity and weighted risk score
- Human-readable and JSON reports
- Optional `psutil` process metadata
- Starter YARA rule
- Automated tests and GitHub Actions CI

## Quick start

Requires Python 3.10 or newer.

```
git clone https://github.com/hassanali-30/Keylogger-Detection-Toolkit.git
cd Keylogger-Detection-Toolkit
python -m venv .venv
```

Activate the environment:

**Windows PowerShell**

```
.venv\\Scripts\\Activate.ps1
```

**macOS/Linux**

```
source .venv/bin/activate
```

Install optional process metadata support:

```
python -m pip install -r requirements.txt
```

## Run

Run a normal report:

```
python keylogger_detector.py
```

Print machine-readable JSON:

```
python keylogger_detector.py --json > report.json
```

For the most complete Windows process view, run from an authorized elevated read-only session. Elevation is not required for the basic workflow, and the toolkit does not request or use write privileges.

## Report meaning

- `no-strong-indicator`: no configured high-value indicators were found
- `suspicious-review`: one or more indicators deserve analyst review
- `high-risk-review`: multiple or high-weight indicators deserve urgent review

These are triage labels, not proof of maliciousness. Legitimate accessibility tools, automation utilities, remote-support software, and security tools can use similar Windows APIs.

## Project layout

```
keylogger_detector.py          # Read-only detector
rules/keylogger-indicators.yar # Review-oriented YARA rule
tests/test_detector.py         # Unit tests
requirements.txt               # Optional psutil dependency
SECURITY.md                    # Defensive-use policy
```

## Testing

```
python -m pip install "pytest>=8,<9"
python -m pytest -q
```

## Detection limitations

This project does not inspect kernel drivers, protected processes, live memory, or every possible persistence mechanism. A clean result does not prove that a system is free of keylogging malware. Combine the report with approved endpoint security, threat-intelligence, and incident-response procedures.

## License

See [LICENSE](LICENSE).
