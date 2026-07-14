rule Batch_SelfCopy_Startup {
    meta:
        description = "Batch self-copy to startup"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $copy = "copy " nocase
        $startup = "startup" nocase
        $bat = "@echo off" nocase
    condition:
        filesize < 256KB and $bat and $copy and $startup
}

rule Batch_Disable_Defender {
    meta:
        description = "Batch disabling Windows Defender"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $def = "Defender" nocase
        $dis = "DisableRealtimeMonitoring" nocase
        $mp = "MpPreference" nocase
    condition:
        filesize < 256KB and 2 of them
}

rule Batch_Del_Firewall {
    meta:
        description = "Batch firewall rule manipulation"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $fw = "netsh advfirewall" nocase
        $off = "state off" nocase
        $add = "add rule" nocase
    condition:
        filesize < 256KB and $fw and 1 of ($off, $add)
}
