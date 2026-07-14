rule Persist_Service_Create {
    meta:
        description = "Windows service creation for persistence"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $sc = "sc create" nocase
        $binpath = "binpath=" nocase
        $start = "start=" nocase
    condition:
        filesize < 512KB and $sc and 1 of ($binpath, $start)
}

rule Persist_Service_NewService {
    meta:
        description = "PowerShell New-Service persistence"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $new = "New-Service" nocase
        $ps = "powershell" nocase
        $startup = "-StartupType" nocase
    condition:
        filesize < 512KB and $new and 1 of ($ps, $startup)
}

rule Persist_WMI_EventSubscription {
    meta:
        description = "WMI event subscription persistence"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $filter = "__EventFilter" nocase
        $consumer = "CommandLineEventConsumer" nocase
        $binding = "__FilterToConsumerBinding" nocase
    condition:
        filesize < 1MB and 2 of them
}
