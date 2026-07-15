// PHP webshells — require PHP open tag + dangerous sinks together.

rule WebShell_PHP_Eval {
    meta:
        description = "PHP webshell with eval/exec"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $php = "<?php"
        $eval = "eval(" nocase
        $assert = "assert(" nocase
        $create = "create_function(" nocase
        $get = "$_GET" nocase
        $post = "$_POST" nocase
        $req = "$_REQUEST" nocase
    condition:
        filesize < 512KB and
        $php and
        1 of ($eval, $assert, $create) and
        1 of ($get, $post, $req)
}

rule WebShell_PHP_Base64_Decode {
    meta:
        description = "PHP base64 obfuscated webshell"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $php = "<?php"
        $b64 = "base64_decode" nocase
        $eval = "eval(" nocase
        $assert = "assert(" nocase
        $gz = "gzinflate" nocase
    condition:
        filesize < 512KB and
        $php and $b64 and
        1 of ($eval, $assert, $gz)
}

rule WebShell_PHP_Shell_Exec {
    meta:
        description = "PHP shell_exec / passthru backdoor"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $php = "<?php"
        $shell = "shell_exec(" nocase
        $pass = "passthru(" nocase
        $proc = "proc_open(" nocase
        $system = "system(" nocase
        $get = "$_GET" nocase
        $post = "$_POST" nocase
        $cookie = "$_COOKIE" nocase
    condition:
        filesize < 512KB and
        $php and
        1 of ($shell, $pass, $proc, $system) and
        1 of ($get, $post, $cookie)
}

rule WebShell_PHP_C99_R57 {
    meta:
        description = "Known PHP webshell family markers"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $c99 = "c99shell" nocase
        $r57 = "r57shell" nocase
        $wso = "WSO " nocase
        $b374k = "b374k" nocase
        $php = "<?php"
    condition:
        filesize < 2MB and $php and any of ($c99, $r57, $wso, $b374k)
}
