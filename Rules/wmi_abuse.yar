rule WMI_Process_Create {
    meta:
        description = "WMI Win32_Process creation abuse"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $wmi = "Win32_Process" nocase
        $create = "Create" nocase
        $wmic = "wmic" nocase
    condition:
        filesize < 1MB and 2 of them
}

rule WMI_EventFilter_Abuse {
    meta:
        description = "WMI event filter for code execution"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $filter = "SELECT * FROM __InstanceModificationEvent" nocase
        $wmi = "root\\subscription" nocase
        $consumer = "ActiveScriptEventConsumer" nocase
    condition:
        filesize < 2MB and 2 of them
}

rule WMI_Remote_Exec {
    meta:
        description = "WMI remote execution via PowerShell"
        severity = "High"
        author = "TurkmenGuard"
    strings:
        $invoke = "Invoke-WmiMethod" nocase
        $cim = "Invoke-CimMethod" nocase
        $process = "Win32_Process" nocase
    condition:
        filesize < 1MB and 1 of ($invoke, $cim) and $process
}
