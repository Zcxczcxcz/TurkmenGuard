// RAT families — multiple family-specific markers required.

rule RAT_AsyncRAT_Family {
    meta:
        description = "AsyncRAT family markers"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $async = "AsyncRAT" nocase
        $stub = "Stub.exe" nocase
        $paste = "pastebin.com" nocase
        $server = "ServerCertificate" nocase
    condition:
        filesize < 20MB and 3 of them
}

rule RAT_NjRAT_Family {
    meta:
        description = "njRAT / Bladabindi family markers"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $nj = "njRAT" nocase
        $bla = "Bladabindi" nocase
        $7e = "7e72e5" nocase
        $dc = "DcRat" nocase
    condition:
        filesize < 20MB and 2 of them
}

rule RAT_Quasar_Client {
    meta:
        description = "Quasar RAT client binary markers"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $quasar = "QuasarClient" nocase
        $mosaic = "MosaicLoader" nocase
        $conn = "ConnectServer" nocase
    condition:
        filesize < 30MB and 2 of them
}

rule RAT_Metasploit_Payload {
    meta:
        description = "Metasploit reverse shell payload markers"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $rev = "reverse_tcp" nocase
        $meter = "meterpreter" nocase
        $stage = "metsrv.dll" nocase
    condition:
        filesize < 5MB and 2 of them
}
