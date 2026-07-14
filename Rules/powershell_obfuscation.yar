rule PowerShell_Obfuscated_Download {
    meta:
        description = "PowerShell obfuscated download/execute pattern"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $iex = "IEX" nocase
        $iex2 = "Invoke-Expression" nocase
        $enc = "-EncodedCommand" nocase
        $b64 = "FromBase64String" nocase
        $dl = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $web = "Net.WebClient" nocase
    condition:
        filesize < 2MB and
        (uint16(0) == 0x2320 or uint16(0) == 0x3C3F or uint16(0) == 0xFFFE) and
        (1 of ($iex, $iex2)) and
        (2 of ($enc, $b64, $dl, $dl2, $web))
}

rule PowerShell_Encoded_Only {
    meta:
        description = "PowerShell encoded command with execution"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $enc = "-EncodedCommand" nocase
        $b64 = "FromBase64String" nocase
        $iex = "IEX" nocase
        $invoke = "Invoke-Expression" nocase
    condition:
        filesize < 1MB and
        $enc and $b64 and (1 of ($iex, $invoke))
}
