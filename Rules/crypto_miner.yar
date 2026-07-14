rule Miner_XMRig_Strings {
    meta:
        description = "XMRig cryptocurrency miner markers"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $xmrig = "xmrig" nocase
        $donate = "donate-level" nocase
        $randomx = "randomx" nocase
        $pool = "stratum+tcp" nocase
    condition:
        filesize < 50MB and 2 of them
}

rule Miner_Stratum_Pool {
    meta:
        description = "Stratum mining pool connection strings"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $stratum = "stratum+tcp://" nocase
        $stratum_ssl = "stratum+ssl://" nocase
        $wallet = "wallet" nocase
        $worker = "worker" nocase
    condition:
        filesize < 10MB and 1 of ($stratum, $stratum_ssl) and 1 of ($wallet, $worker)
}

rule Miner_CGMiner_Ethminer {
    meta:
        description = "Known miner binary strings"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $cg = "cgminer" nocase
        $eth = "ethminer" nocase
        $nanopool = "nanopool.org" nocase
        $nicehash = "nicehash.com" nocase
    condition:
        filesize < 50MB and any of them
}

rule Miner_Silent_CPU_Mining {
    meta:
        description = "Silent CPU mining script pattern"
        severity = "Medium"
        author = "TurkmenGuard"
    strings:
        $coinhive = "coinhive" nocase
        $cryptonight = "cryptonight" nocase
        $minero = "minero.cc" nocase
    condition:
        filesize < 5MB and any of them
}
