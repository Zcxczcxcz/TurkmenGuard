rule PS_Downloader_IEX {
    meta:
        description = "PowerShell IEX download cradle"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $iex = "IEX" nocase
        $download = "DownloadString" nocase
        $web = "Net.WebClient" nocase
    condition:
        filesize < 1MB and 2 of them
}

rule PS_Downloader_InvokeWebRequest {
    meta:
        description = "PowerShell Invoke-WebRequest dropper"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $iwr = "Invoke-WebRequest" nocase
        $out = "-OutFile" nocase
        $uri = "-Uri" nocase
    condition:
        filesize < 1MB and $iwr and 1 of ($out, $uri)
}

rule PS_Downloader_BitsTransfer {
    meta:
        description = "PowerShell BitsTransfer download"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $bits = "Start-BitsTransfer" nocase
        $source = "-Source" nocase
        $dest = "-Destination" nocase
    condition:
        filesize < 1MB and $bits and 1 of ($source, $dest)
}

rule PS_Downloader_FromBase64 {
    meta:
        description = "PowerShell base64 encoded payload execution"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $b64 = "FromBase64String" nocase
        $enc = "-EncodedCommand" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
    condition:
        filesize < 2MB and 2 of them
}
