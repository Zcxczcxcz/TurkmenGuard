rule Packed_UPX {
    meta:
        description = "UPX packer signature in PE"
        severity = "Info"
        author = "TurkmenGuard"
    strings:
        $mz = "MZ"
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
        $upx3 = "UPX2" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 20MB and
        $mz at 0 and (1 of ($upx0, $upx1, $upx2, $upx3))
}

rule Packed_Themida_Marker {
    meta:
        description = "Themida/WinLicense packer marker"
        severity = "Info"
        author = "TurkmenGuard"
    strings:
        $themida = ".themida" nocase
        $winlice = "WinLicense" ascii
        $mz = "MZ"
    condition:
        uint16(0) == 0x5A4D and filesize < 30MB and
        $mz at 0 and (1 of ($themida, $winlice))
}
