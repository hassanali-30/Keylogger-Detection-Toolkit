rule Keylogger_Indicator_Strings
{
    meta:
        description = "Review-oriented strings associated with keylogger behavior"
        author = "Keylogger Detection Toolkit"
        confidence = "low"

    strings:
        $hook = "SetWindowsHookEx" nocase
        $async = "GetAsyncKeyState" nocase
        $state = "GetKeyState" nocase
        $proc = "LowLevelKeyboardProc" nocase
        $python = "pynput" nocase
        $keylogger = "keylogger" nocase
        $user32 = "user32.dll" nocase

    condition:
        2 of them
}
