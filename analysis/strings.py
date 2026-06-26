import re

MIN_LENGTH = 4
MAX_STRINGS = 500

_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LENGTH)
_WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_LENGTH)

SUSPICIOUS_PATTERNS = {
    "Process Injection API": re.compile(
        r"\b(CreateRemoteThread|WriteProcessMemory|VirtualAllocEx|"
        r"NtUnmapViewOfSection|QueueUserAPC|SetThreadContext)\b"
    ),
    "Dynamic Loading API": re.compile(
        r"\b(LoadLibraryA|LoadLibraryW|GetProcAddress|LdrLoadDll)\b"
    ),
    "Execution API": re.compile(
        r"\b(WinExec|ShellExecuteA|ShellExecuteW|CreateProcessA|CreateProcessW)\b"
    ),
    "Memory API": re.compile(r"\b(VirtualAlloc|VirtualProtect|HeapCreate)\b"),
    "Command Interpreter": re.compile(
        r"\b(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|rundll32\.exe|mshta\.exe)\b",
        re.IGNORECASE,
    ),
    "Persistence / Registry": re.compile(
        r"(HKEY_[A-Z_]+|\\CurrentVersion\\Run|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run)"
    ),
    "URL": re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE),
    "IP Address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "Anti-Debug / Anti-VM": re.compile(
        r"\b(IsDebuggerPresent|CheckRemoteDebuggerPresent|vmware|virtualbox|sandboxie)\b",
        re.IGNORECASE,
    ),
}


def extract_strings(file_path, min_length=MIN_LENGTH, max_strings=MAX_STRINGS):
    """
    Extract printable ASCII and UTF-16LE strings from a file and flag
    any that match known-suspicious patterns.
    """

    with open(file_path, "rb") as f:
        data = f.read()

    found = []

    for match in _ASCII_RE.finditer(data):
        found.append(match.group().decode("ascii", errors="ignore"))

    for match in _WIDE_RE.finditer(data):
        found.append(match.group().decode("utf-16le", errors="ignore"))

    unique_strings = list(dict.fromkeys(found))

    suspicious = []

    for category, pattern in SUSPICIOUS_PATTERNS.items():
        for s in unique_strings:
            m = pattern.search(s)
            if m:
                suspicious.append({
                    "category": category,
                    "value": m.group()
                })

    unique_suspicious = list(
        {(s["category"], s["value"]): s for s in suspicious}.values()
    )

    return {
        "total_strings": len(unique_strings),
        "strings": unique_strings[:max_strings],
        "suspicious": unique_suspicious
    }
