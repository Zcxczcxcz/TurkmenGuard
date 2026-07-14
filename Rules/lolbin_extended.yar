rule LOLBin_Regsvr32_Script {
    meta:
        description = "Regsvr32 scrobj scriptlet execution"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $regsvr = "regsvr32" nocase
        $scrobj = "scrobj.dll" nocase
        $silent = "/s" nocase
        $unreg = "/u" nocase
    condition:
        filesize < 512KB and $regsvr and 1 of ($scrobj, $silent, $unreg)
}

rule LOLBin_Rundll32_JS {
    meta:
        description = "Rundll32 javascript execution"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $run = "rundll32" nocase
        $js_proto = "javascript:" nocase
        $url = "url.dll" nocase
    condition:
        filesize < 512KB and $run and 1 of ($js_proto, $url)
}

rule LOLBin_Msbuild_XML {
    meta:
        description = "MSBuild inline task execution"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $msb = "msbuild" nocase
        $task = "UsingTask" nocase
        $code = "Code" nocase
    condition:
        filesize < 2MB and $msb and 1 of ($task, $code)
}

rule LOLBin_Forfiles_CMD {
    meta:
        description = "Forfiles command execution bypass"
        severity = "Medium"
        author = "TurkmenGuard"
    strings:
        $forfiles_cmd = "forfiles" nocase
        $cmd_flag = "/c" nocase
        $path_flag = "/p" nocase
    condition:
        filesize < 512KB and $forfiles_cmd and ($cmd_flag or $path_flag)
}

rule LOLBin_Cscript_Wscript {
    meta:
        description = "Windows script host execution chain"
        severity = "Medium"
        author = "TurkmenGuard"
    strings:
        $cscript = "cscript" nocase
        $wscript = "wscript" nocase
        $vbs_ext = ".vbs" nocase
        $js_ext = ".js" nocase
    condition:
        filesize < 512KB and 1 of ($cscript, $wscript) and 1 of ($vbs_ext, $js_ext)
}
