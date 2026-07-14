// LOLBin abuse chains — all indicators required, no generic script host rules.

rule LOLBin_Regsvr32_Scriptlet {
    meta:
        description = "Regsvr32 scrobj scriptlet execution chain"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $regsvr = "regsvr32" nocase
        $scrobj = "scrobj.dll" nocase
        $silent = "/s" nocase
        $unreg = "/u" nocase
    condition:
        filesize < 256KB and all of ($regsvr, $scrobj, $silent, $unreg)
}

rule LOLBin_Rundll32_Javascript {
    meta:
        description = "Rundll32 javascript protocol execution"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $run = "rundll32" nocase
        $js = "javascript:" nocase
        $url = "url.dll" nocase
    condition:
        filesize < 256KB and all of ($run, $js, $url)
}

rule LOLBin_Msbuild_InlineTask {
    meta:
        description = "MSBuild inline malicious task"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $msb = "msbuild" nocase
        $task = "UsingTask" nocase
        $code = "TaskFactory=\"CodeTaskFactory\"" nocase
        $csharp = "System.CodeDom.Compiler" nocase
    condition:
        filesize < 1MB and all of ($msb, $task, $code, $csharp)
}
