// Office macro malware — requires auto-run trigger AND payload action together.

rule Macro_AutoRun_With_Shell {
    meta:
        description = "VBA auto-run macro with shell execution"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $auto = "AutoOpen" nocase
        $doc = "Document_Open" nocase
        $workbook = "Workbook_Open" nocase
        $shell = "Shell(" nocase
        $wsh = "WScript.Shell" nocase
    condition:
        filesize < 10MB and
        (1 of ($auto, $doc, $workbook)) and
        (1 of ($shell, $wsh))
}

rule Macro_AutoRun_PowerShell_Hidden {
    meta:
        description = "VBA auto-run launching hidden PowerShell"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $auto = "AutoOpen" nocase
        $doc = "Document_Open" nocase
        $ps = "powershell" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $enc = "-EncodedCommand" nocase
    condition:
        filesize < 10MB and
        (1 of ($auto, $doc)) and $ps and (1 of ($hidden, $enc))
}

rule Macro_Download_And_Execute {
    meta:
        description = "VBA macro downloading and executing external payload"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $url = "URLDownloadToFile" nocase
        $msxml = "MSXML2.XMLHTTP" nocase
        $shell = "Shell(" nocase
        $auto = "AutoOpen" nocase
        $doc = "Document_Open" nocase
    condition:
        filesize < 10MB and
        (1 of ($url, $msxml)) and $shell and (1 of ($auto, $doc))
}
