rule WebShell_ASP_Execute {
    meta:
        description = "ASP/ASPX execute command webshell"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $exec = "Execute(" nocase
        $eval = "Eval(" nocase
        $cmd = "cmd.exe" nocase
        $asp = "<%@" nocase
    condition:
        filesize < 2MB and $asp and 1 of ($exec, $eval) and $cmd
}

rule WebShell_ASPX_Shell {
    meta:
        description = "ASPX webshell with Process.Start"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $process = "Process.Start" nocase
        $cmd = "cmd.exe" nocase
        $aspx = "<%@" nocase
        $runat = "runat=\"server\"" nocase
    condition:
        filesize < 2MB and 2 of ($process, $cmd, $aspx, $runat)
}

rule WebShell_JSP_Runtime {
    meta:
        description = "JSP Runtime.exec webshell"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $runtime = "Runtime.getRuntime" nocase
        $exec = ".exec(" nocase
        $jsp = "<%@" nocase
    condition:
        filesize < 2MB and $jsp and $runtime and $exec
}
