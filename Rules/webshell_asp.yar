// ASP/ASPX/JSP webshells — require real page markup, not random Process.Start in binaries.

rule WebShell_ASP_Execute {
    meta:
        description = "ASP/ASPX execute command webshell"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $asp = "<%@" nocase
        $runat = "runat=\"server\"" nocase
        $exec = "Execute(" nocase
        $eval = "Eval(" nocase
        $cmd = "cmd.exe" nocase
        $wscript = "WScript.Shell" nocase
    condition:
        filesize < 512KB and
        $asp and $runat and
        1 of ($exec, $eval) and
        1 of ($cmd, $wscript)
}

rule WebShell_ASPX_Shell {
    meta:
        description = "ASPX webshell with Process.Start"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $aspx = "<%@" nocase
        $runat = "runat=\"server\"" nocase
        $process = "Process.Start" nocase
        $cmd = "cmd.exe" nocase
        $psi = "ProcessStartInfo" nocase
    condition:
        filesize < 512KB and
        $aspx and $runat and
        1 of ($process, $psi) and
        $cmd
}

rule WebShell_JSP_Runtime {
    meta:
        description = "JSP Runtime.exec webshell"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $jsp = "<%@" nocase
        $page = "page language=\"java\"" nocase
        $runtime = "Runtime.getRuntime" nocase
        $exec = ".exec(" nocase
    condition:
        filesize < 512KB and
        $jsp and $page and $runtime and $exec
}
