// WMI abuse — specific subscription or remote exec chains only.

rule WMI_EventFilter_Persistence {
    meta:
        description = "WMI event subscription persistence chain"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $filter = "SELECT * FROM __InstanceModificationEvent" nocase
        $wmi = "root\\subscription" nocase
        $consumer = "ActiveScriptEventConsumer" nocase
    condition:
        filesize < 1MB and all of them
}

rule WMI_Remote_Process_Create {
    meta:
        description = "WMI remote process creation via PowerShell"
        severity = "Critical"
        author = "TurkmenGuard"
    strings:
        $invoke = "Invoke-WmiMethod" nocase
        $cim = "Invoke-CimMethod" nocase
        $process = "Win32_Process" nocase
        $create = "Create" nocase
        $node = "-ComputerName" nocase
    condition:
        filesize < 512KB and
        (1 of ($invoke, $cim)) and $process and $create and $node
}
