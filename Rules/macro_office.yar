rule Macro_AutoOpen_Sub {
    meta:
        description = "VBA AutoOpen/Document_Open macro trigger"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $auto = "AutoOpen" nocase
        $doc = "Document_Open" nocase
        $workbook = "Workbook_Open" nocase
    condition:
        filesize < 20MB and 1 of ($auto, $doc, $workbook)
}

rule Macro_Shell_Execute {
    meta:
        description = "VBA Shell/WScript.Shell execution"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $shell_call = "Shell(" nocase
        $wsh = "WScript.Shell" nocase
        $create = "CreateObject" nocase
    condition:
        filesize < 20MB and 2 of ($shell_call, $wsh, $create)
}

rule Macro_PowerShell_From_VBA {
    meta:
        description = "VBA launching PowerShell"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $ps = "powershell" nocase
        $cmd_exe = "cmd.exe" nocase
        $vba_sub = "Sub " nocase
        $hidden = "-WindowStyle Hidden" nocase
    condition:
        filesize < 20MB and $ps and 1 of ($cmd_exe, $vba_sub, $hidden)
}

rule Macro_Download_File {
    meta:
        description = "VBA macro downloading external file"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $url = "URLDownloadToFile" nocase
        $msxml = "MSXML2.XMLHTTP" nocase
        $winhttp = "WinHttp.WinHttpRequest" nocase
    condition:
        filesize < 20MB and 1 of ($url, $msxml, $winhttp)
}
