rule LOLBin_Certutil_Decode {
    meta:
        description = "Certutil decode dropper pattern"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $cert = "certutil" nocase
        $decode = "-decode" nocase
        $urlcache = "-urlcache" nocase
    condition:
        filesize < 512KB and
        all of them
}

rule LOLBin_Bitsadmin_Transfer {
    meta:
        description = "Bitsadmin file transfer dropper"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $bits = "bitsadmin" nocase
        $transfer = "/transfer" nocase
        $download = "/download" nocase
    condition:
        filesize < 512KB and
        $bits and (1 of ($transfer, $download))
}

rule LOLBin_Mshta_Javascript {
    meta:
        description = "Mshta javascript launcher"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $mshta = "mshta" nocase
        $js = "javascript:" nocase
        $vb = "vbscript:" nocase
    condition:
        filesize < 256KB and
        $mshta and (1 of ($js, $vb))
}
