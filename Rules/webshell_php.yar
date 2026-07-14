rule WebShell_PHP_Eval {
    meta:
        description = "PHP webshell with eval/exec"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $eval = "eval(" nocase
        $exec = "exec(" nocase
        $system = "system(" nocase
        $php = "<?php"
    condition:
        filesize < 2MB and $php and 1 of ($eval, $exec, $system)
}

rule WebShell_PHP_Base64_Decode {
    meta:
        description = "PHP base64 obfuscated webshell"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $b64 = "base64_decode" nocase
        $eval = "eval(" nocase
        $assert = "assert(" nocase
        $php = "<?php"
    condition:
        filesize < 2MB and $php and $b64 and 1 of ($eval, $assert)
}

rule WebShell_PHP_Shell_Exec {
    meta:
        description = "PHP shell_exec / passthru backdoor"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $shell = "shell_exec" nocase
        $pass = "passthru" nocase
        $proc = "proc_open" nocase
        $php_get = "_GET" nocase
        $post = "_POST" nocase
    condition:
        filesize < 2MB and 1 of ($shell, $pass, $proc) and 1 of ($php_get, $post)
}

rule WebShell_PHP_C99_R57 {
    meta:
        description = "Known PHP webshell family markers"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $c99 = "c99shell" nocase
        $r57 = "r57shell" nocase
        $wso = "wso.php" nocase
        $b374k = "b374k" nocase
    condition:
        filesize < 5MB and any of them
}
