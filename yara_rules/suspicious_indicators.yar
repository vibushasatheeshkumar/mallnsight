import "math"

rule Suspicious_Process_Injection
{
    meta:
        description = "References APIs commonly used for process injection"
        severity = "HIGH"

    strings:
        $a1 = "CreateRemoteThread" ascii wide
        $a2 = "WriteProcessMemory" ascii wide
        $a3 = "VirtualAllocEx" ascii wide
        $a4 = "NtUnmapViewOfSection" ascii wide
        $a5 = "QueueUserAPC" ascii wide

    condition:
        2 of ($a*)
}

rule Suspicious_Dynamic_API_Resolution
{
    meta:
        description = "Resolves APIs dynamically, often used to evade static detection"
        severity = "MEDIUM"

    strings:
        $a1 = "LoadLibraryA" ascii wide
        $a2 = "LoadLibraryW" ascii wide
        $a3 = "GetProcAddress" ascii wide

    condition:
        all of them
}

rule Suspicious_Command_Execution
{
    meta:
        description = "Contains references to command interpreters / script hosts"
        severity = "MEDIUM"

    strings:
        $a1 = "cmd.exe" ascii wide nocase
        $a2 = "powershell.exe" ascii wide nocase
        $a3 = "wscript.exe" ascii wide nocase
        $a4 = "mshta.exe" ascii wide nocase
        $a5 = "WinExec" ascii

    condition:
        any of them
}

rule Suspicious_AntiDebug_AntiVM
{
    meta:
        description = "Contains anti-debugging or anti-VM checks"
        severity = "MEDIUM"

    strings:
        $a1 = "IsDebuggerPresent" ascii
        $a2 = "CheckRemoteDebuggerPresent" ascii
        $a3 = "VMware" ascii nocase
        $a4 = "VBox" ascii nocase
        $a5 = "Sandboxie" ascii nocase

    condition:
        any of them
}

rule Packed_File_High_Entropy
{
    meta:
        description = "Overall file entropy is very high, indicative of packing/encryption"
        severity = "MEDIUM"

    condition:
        filesize > 256 and math.entropy(0, filesize) >= 7.5
}
