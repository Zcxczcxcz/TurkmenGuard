rule Ransomware_Shadow_Delete {
    meta:
        description = "Shadow copy deletion — ransomware indicator"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $vss = "vssadmin" nocase
        $del = "delete" nocase
        $shadow = "shadows" nocase
        $wbadmin = "wbadmin" nocase
        $catalog = "catalog" nocase
    condition:
        filesize < 1MB and
        (($vss and $del and $shadow) or ($wbadmin and $del and $catalog))
}

rule Ransomware_Note_Marker {
    meta:
        description = "Ransom note filename/content markers"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $readme = "README_TO_DECRYPT" nocase
        $recover = "HOW_TO_RECOVER" nocase
        $restore = "RESTORE_FILES" nocase
        $btc = "bitcoin" nocase
        $wallet = "wallet address" nocase
    condition:
        filesize < 64KB and
        (1 of ($readme, $recover, $restore)) and
        (1 of ($btc, $wallet))
}
