rule Shellcode_PE_High_Entropy {
    meta:
        description = "PE with suspicious UPX-like section names"
        severity = "Medium"
        author = "TurkmenGuard"
    strings:
        $mz1 = { 4D 5A }
        $upx0 = ".UPX0" nocase
        $upx1 = ".UPX1" nocase
        $aspack = ".aspack" nocase
    condition:
        $mz1 at 0 and filesize < 20MB and 1 of ($upx0, $upx1, $aspack)
}

rule Shellcode_PE_No_Imports {
    meta:
        description = "PE suspicious empty import table marker"
        severity = "Medium"
        author = "TurkmenGuard"
    strings:
        $mz2 = { 4D 5A }
        $pe = { 50 45 00 00 }
        $nullimp = "kernel32.dll" nocase
    condition:
        $mz2 at 0 and $pe and $nullimp and filesize < 10MB
}

rule Shellcode_Suspicious_Section {
    meta:
        description = "PE section names common in shellcode loaders"
        severity = "Medium"
        author = "TurkmenGuard"
    strings:
        $mz3 = { 4D 5A }
        $s1 = ".textbss" nocase
        $s2 = "/4" nocase
        $s3 = ".adata" nocase
    condition:
        $mz3 at 0 and filesize < 15MB and 1 of ($s1, $s2, $s3)
}
