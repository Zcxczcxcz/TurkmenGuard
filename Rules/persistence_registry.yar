// Persistence — requires registry target AND malicious payload together.

rule Persist_RunKey_Malicious {
    meta:
        description = "Run key persistence with encoded/hidden payload"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $run = "CurrentVersion\\Run" nocase
        $ps = "powershell" nocase
        $set = "Set-ItemProperty" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $enc = "-EncodedCommand" nocase
    condition:
        filesize < 256KB and
        $run and $ps and $set and (1 of ($hidden, $enc))
}

rule Persist_Schtasks_Hidden {
    meta:
        description = "Hidden scheduled task persistence at logon/startup"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $sch = "schtasks" nocase
        $create = "/create" nocase
        $onlogon = "/sc onlogon" nocase
        $onstart = "/sc onstart" nocase
        $hidden = "/rl highest" nocase
        $ps = "powershell" nocase
    condition:
        filesize < 256KB and
        all of ($sch, $create, $ps, $hidden) and
        (1 of ($onlogon, $onstart))
}

rule Persist_StartupFolder_Executable {
    meta:
        description = "Copy executable to Startup folder"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $startup = "shell:startup" nocase
        $copy = "copy " nocase
        $exe = ".exe" nocase
        $bat = "@echo off" nocase
    condition:
        filesize < 128KB and
        all of ($startup, $copy, $exe, $bat)
}
