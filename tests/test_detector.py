from keylogger_detector import (
    analyze_process_record,
    inspect_text,
    score_findings,
    verdict_for,
)


def test_detector_does_not_capture_or_modify():
    report = analyze_process_record({
        "pid": 1234,
        "name": "normal.exe",
        "exe": r"C:\\Program Files\\normal.exe",
        "cmdline": [],
    })
    assert report["findings"] == []
    assert report["score"] == 0


def test_suspicious_hook_indicators_are_explained():
    report = analyze_process_record({
        "pid": 9876,
        "name": "helper.exe",
        "exe": r"C:\\Users\\Public\\AppData\\Roaming\\helper.exe",
        "cmdline": ["--callback", "SetWindowsHookEx", "GetAsyncKeyState"],
    })
    assert report["score"] >= 30
    assert any("setwindowshookex" in item["detail"] for item in report["findings"])
    assert any("getasynckeystate" in item["detail"] for item in report["findings"])


def test_thresholds():
    assert verdict_for(0) == "no-strong-indicator"
    assert verdict_for(30) == "suspicious-review"
    assert verdict_for(60) == "high-risk-review"


def test_text_scan_is_read_only():
    findings = inspect_text("pynput keyboardlistener", "test")
    assert score_findings(findings) >= 20
