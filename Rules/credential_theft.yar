rule CredTheft_Mimikatz_Strings {
    meta:
        description = "Mimikatz-like credential dumping strings"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "lsadump::sam" nocase
        $s3 = "kerberos::golden" nocase
        $s4 = "mimikatz" nocase
    condition:
        filesize < 10MB and 2 of them
}

rule CredTheft_Procdump_LSASS {
    meta:
        description = "Procdump LSASS memory dump pattern"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $proc = "procdump" nocase
        $lsass = "lsass" nocase
        $accept = "-accepteula" nocase
    condition:
        filesize < 2MB and all of them
}

rule CredTheft_Comsvcs_MiniDump {
    meta:
        description = "comsvcs.dll MiniDump LSASS technique"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $comsvcs = "comsvcs.dll" nocase
        $minidump = "MiniDump" nocase
        $lsass = "lsass" nocase
    condition:
        filesize < 1MB and all of them
}

rule CredTheft_SamHive_Export {
    meta:
        description = "SAM and SYSTEM hive export for offline cracking"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $reg = "reg save" nocase
        $sam = " sam" nocase
        $system = " system" nocase
    condition:
        filesize < 256KB and all of ($reg, $sam, $system)
}
