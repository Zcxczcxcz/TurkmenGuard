rule Stealer_Browser_Creds {
    meta:
        description = "Browser credential theft pattern"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $login = "Login Data" nocase
        $chrome = "Google\\Chrome" nocase
        $firefox = "Mozilla\\Firefox" nocase
        $cookies = "Cookies" nocase
    condition:
        filesize < 5MB and 2 of them
}

rule Stealer_Discord_Token {
    meta:
        description = "Discord token stealer pattern"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $discord = "discord" nocase
        $token = "token" nocase
        $local = "Local Storage" nocase
        $leveldb = "leveldb" nocase
    condition:
        filesize < 5MB and $discord and $token and 1 of ($local, $leveldb)
}

rule Stealer_Telegram_Session {
    meta:
        description = "Telegram session file theft"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $tg = "Telegram Desktop" nocase
        $tdata = "tdata" nocase
        $key = "key_datas" nocase
    condition:
        filesize < 5MB and 2 of them
}

rule Stealer_Crypto_Wallet {
    meta:
        description = "Cryptocurrency wallet file theft"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $eth = "Ethereum" nocase
        $wallet = "wallet.dat" nocase
        $metamask = "MetaMask" nocase
        $exodus = "Exodus" nocase
    condition:
        filesize < 5MB and 2 of them
}
