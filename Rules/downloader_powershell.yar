// Strict PowerShell download cradles — requires bypass + download + execute together.

rule PS_Malicious_Cradle_IEX {
    meta:
        description = "PowerShell IEX download cradle with execution policy bypass"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $iex = "IEX" nocase
        $download = "DownloadString" nocase
        $web = "Net.WebClient" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $hidden = "-WindowStyle Hidden" nocase
    condition:
        filesize < 512KB and
        $iex and $download and $web and (1 of ($bypass, $hidden))
}

rule PS_Malicious_EncodedPayload {
    meta:
        description = "PowerShell encoded command with decode and execute"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $enc = "-EncodedCommand" nocase
        $b64 = "FromBase64String" nocase
        $iex = "IEX" nocase
        $invoke = "Invoke-Expression" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
    condition:
        filesize < 512KB and
        $enc and $b64 and (1 of ($iex, $invoke)) and $bypass
}

rule PS_Malicious_WebDropper {
    meta:
        description = "PowerShell web dropper with hidden execution"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $iwr = "Invoke-WebRequest" nocase
        $out = "-OutFile" nocase
        $uri = "-Uri" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $start = "Start-Process" nocase
    condition:
        filesize < 512KB and
        $iwr and $out and $uri and (1 of ($hidden, $bypass, $start))
}
