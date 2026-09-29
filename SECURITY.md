# Security Policy

This repository is defensive tooling. It is intentionally read-only.

## Safety guarantees

The toolkit does not:

- capture, log, or transmit keystrokes
- install keyboard hooks
- modify registry keys or startup folders
- terminate processes
- download samples or contact external services

Run it in an authorized environment and treat findings as triage signals. Do not publish credentials, private process data, or live malware samples in issues or pull requests.

## Reporting

Use a private security report when possible. Include the operating system, Python version, command used, and a sanitized JSON report.