rule RAT_AsyncRAT_Markers {
    meta:
        description = "AsyncRAT family strings"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $async = "AsyncRAT" nocase
        $stub = "Stub.exe" nocase
        $paste = "pastebin.com" nocase
    condition:
        filesize < 20MB and 2 of them
}

rule RAT_NjRAT_Strings {
    meta:
        description = "njRAT / Bladabindi markers"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $nj = "njRAT" nocase
        $bla = "Bladabindi" nocase
        $7e = "7e72e5" nocase
    condition:
        filesize < 20MB and any of them
}

rule RAT_Quasar_Markers {
    meta:
        description = "Quasar RAT client markers"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $quasar = "Quasar" nocase
        $client = "QuasarClient" nocase
        $mosaic = "MosaicLoader" nocase
    condition:
        filesize < 30MB and 1 of ($quasar, $client, $mosaic)
}

rule RAT_Reverse_Shell {
    meta:
        description = "Reverse shell connection pattern"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $rev = "reverse_tcp" nocase
        $bind = "bind_tcp" nocase
        $meter = "meterpreter" nocase
        $nc = "nc.exe" nocase
    condition:
        filesize < 5MB and any of them
}
