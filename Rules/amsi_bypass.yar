// AMSI bypass — require concrete PowerShell/AMSI patch chains, not the word "amsi".

rule AMSI_Bypass_Patch {
    meta:
        description = "AMSI.dll patch bypass pattern"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $amsi = "amsi.dll" nocase
        $patch = "AmsiScanBuffer" nocase
        $virt = "VirtualProtect" nocase
    condition:
        filesize < 256KB and all of them
}

rule AMSI_Bypass_String_Replace {
    meta:
        description = "AMSI string replacement bypass"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $bypass = "amsiInitFailed" nocase
        $replace = "-replace" nocase
        $context = "amsiContext" nocase
        $utils = "AmsiUtils" nocase
    condition:
        filesize < 256KB and
        $bypass and $replace and
        1 of ($context, $utils)
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
        $set = "SetValue" nocase
    condition:
        filesize < 256KB and all of them
}
