rule AMSI_Bypass_Patch {
    meta:
        description = "AMSI.dll patch bypass pattern"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $amsi = "amsi.dll" nocase
        $patch = "AmsiScanBuffer" nocase
        $init = "AmsiInitialize" nocase
    condition:
        filesize < 2MB and $amsi and 1 of ($patch, $init)
}

rule AMSI_Bypass_String_Replace {
    meta:
        description = "AMSI string replacement bypass"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $amsi = "amsi" nocase
        $replace = "-replace" nocase
        $bypass = "amsiInitFailed" nocase
    condition:
        filesize < 1MB and 2 of them
}

rule AMSI_Bypass_Reflection {
    meta:
        description = "PowerShell reflection AMSI bypass"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $ref = "System.Management.Automation.AmsiUtils" nocase
        $field = "GetField" nocase
        $amsi = "amsiContext" nocase
    condition:
        filesize < 1MB and 2 of them
}
