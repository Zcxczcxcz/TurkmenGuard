rule Ransomware_VssAdmin_Delete {
    meta:
        description = "Shadow copy deletion via vssadmin"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $vss = "vssadmin" nocase
        $del_shadows = "delete shadows" nocase
        $all = "/all" nocase
    condition:
        filesize < 512KB and $vss and $del_shadows and $all
}

rule Ransomware_BcdEdit_Recovery {
    meta:
        description = "Disable recovery via bcdedit"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $bcd = "bcdedit" nocase
        $recovery = "recoveryenabled" nocase
        $off = "off" nocase
    condition:
        filesize < 512KB and $bcd and $recovery and $off
}

rule Ransomware_WMIC_ShadowCopy {
    meta:
        description = "WMIC shadow copy deletion"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $wmic = "wmic" nocase
        $shadow = "shadowcopy" nocase
        $del_cmd = "delete" nocase
    condition:
        filesize < 512KB and all of ($wmic, $shadow, $del_cmd)
}

rule Ransomware_Encrypted_Extension {
    meta:
        description = "Ransom note with encrypted extension references"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $btc = "bitcoin" nocase
        $pay = "decrypt your files" nocase
        $wallet = "bitcoin wallet" nocase
        $locked = "your files have been encrypted" nocase
        $onion = ".onion" nocase
        $ransom = "ransom" nocase
    condition:
        filesize < 64KB and
        ($locked or $pay) and
        2 of ($btc, $wallet, $onion, $ransom)
}
