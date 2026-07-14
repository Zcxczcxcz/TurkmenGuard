rule Persist_RunKey_PowerShell {
    meta:
        description = "Registry Run key persistence via PowerShell"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $run = "CurrentVersion\\Run" nocase
        $ps = "powershell" nocase
        $set = "Set-ItemProperty" nocase
    condition:
        filesize < 512KB and 2 of them
}

rule Persist_RunOnce {
    meta:
        description = "RunOnce registry persistence"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $runonce = "RunOnce" nocase
        $reg = "reg add" nocase
        $hkcu = "HKCU" nocase
    condition:
        filesize < 512KB and $runonce and 1 of ($reg, $hkcu)
}

rule Persist_StartupFolder {
    meta:
        description = "Copy to Startup folder persistence"
        severity = "Medium"
        author = "TurkmenGuard"
    strings:
        $startup = "Startup" nocase
        $shell = "shell:startup" nocase
        $copy = "copy " nocase
    condition:
        filesize < 512KB and 2 of them
}

rule Persist_Schtasks_Create {
    meta:
        description = "Scheduled task persistence"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $sch = "schtasks" nocase
        $create = "/create" nocase
        $onlogon = "/sc onlogon" nocase
        $onstart = "/sc onstart" nocase
    condition:
        filesize < 512KB and $sch and $create and 1 of ($onlogon, $onstart)
}
