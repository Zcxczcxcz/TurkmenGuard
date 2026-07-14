rule Lateral_PsExec {
    meta:
        description = "PsExec remote execution"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $psexec = "psexec" nocase
        $sysinternal = "Sysinternals" nocase
        $remote = "\\\\" nocase
    condition:
        filesize < 10MB and $psexec and 1 of ($sysinternal, $remote)
}

rule Lateral_WMI_Remote {
    meta:
        description = "WMI remote process creation"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $wmi = "wmic" nocase
        $node = "/node:" nocase
        $process = "process call create" nocase
    condition:
        filesize < 512KB and $wmi and 1 of ($node, $process)
}

rule Lateral_WinRM {
    meta:
        description = "WinRM remote PowerShell"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $winrm = "winrm" nocase
        $invoke = "Invoke-Command" nocase
        $computer = "-ComputerName" nocase
    condition:
        filesize < 1MB and 2 of them
}

rule Lateral_SMB_Exec {
    meta:
        description = "SMB remote service execution"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $sc = "sc \\\\" nocase
        $share = "ADMIN$" nocase
        $ipc = "IPC$" nocase
    condition:
        filesize < 512KB and 2 of them
}
