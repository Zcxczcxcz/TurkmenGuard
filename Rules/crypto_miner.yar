// Cryptocurrency miners — pool connection + miner binary markers together.

rule Miner_XMRig_Active {
    meta:
        description = "XMRig miner with pool configuration"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $xmrig = "xmrig" nocase
        $donate = "donate-level" nocase
        $pool = "stratum+tcp" nocase
        $randomx = "randomx" nocase
    condition:
        filesize < 50MB and 3 of them
}

rule Miner_Stratum_Wallet {
    meta:
        description = "Stratum pool with wallet address"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $stratum = "stratum+tcp://" nocase
        $stratum_ssl = "stratum+ssl://" nocase
        $wallet = "wallet" nocase
        $worker = "worker" nocase
        $xmr = "monero" nocase
    condition:
        filesize < 5MB and
        (1 of ($stratum, $stratum_ssl)) and
        2 of ($wallet, $worker, $xmr)
}

rule Miner_Known_Binary {
    meta:
        description = "Known miner binary with pool domain"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $cg = "cgminer" nocase
        $eth = "ethminer" nocase
        $nanopool = "nanopool.org" nocase
        $nicehash = "nicehash.com" nocase
        $pool = "stratum" nocase
    condition:
        filesize < 50MB and
        (1 of ($cg, $eth)) and
        (1 of ($nanopool, $nicehash, $pool))
}
