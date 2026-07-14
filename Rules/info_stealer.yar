// Info stealer — multiple theft-specific indicators required together.

rule Stealer_Browser_Credentials {
    meta:
        description = "Browser credential database theft"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $login = "Login Data" nocase
        $chrome = "Google\\Chrome\\User Data" nocase
        $firefox = "Mozilla\\Firefox\\Profiles" nocase
        $cookies = "Cookies" nocase
        $copy = "Copy-Item" nocase
    condition:
        filesize < 2MB and
        $login and (1 of ($chrome, $firefox)) and (1 of ($cookies, $copy))
}

rule Stealer_Discord_Token_Grab {
    meta:
        description = "Discord token extraction pattern"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $discord = "discord\\Local Storage" nocase
        $token = "mfa." nocase
        $token2 = "token" nocase
        $leveldb = "leveldb" nocase
        $hook = "GetAsyncKeyState" nocase
    condition:
        filesize < 2MB and
        $discord and $leveldb and (1 of ($token, $token2)) and $hook
}

rule Stealer_Telegram_Session {
    meta:
        description = "Telegram tdata session theft"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $tg = "Telegram Desktop\\tdata" nocase
        $key = "key_datas" nocase
        $copy = "Copy-Item" nocase
    condition:
        filesize < 2MB and all of ($tg, $key, $copy)
}

rule Stealer_Crypto_Wallet_Files {
    meta:
        description = "Cryptocurrency wallet file theft"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $wallet = "wallet.dat" nocase
        $metamask = "MetaMask" nocase
        $exodus = "Exodus" nocase
        $copy = "Copy-Item" nocase
        $appdata = "AppData\\Roaming" nocase
    condition:
        filesize < 2MB and
        $copy and $appdata and
        (1 of ($wallet, $metamask, $exodus))
}
