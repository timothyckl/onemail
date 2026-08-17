rule Suspicious_PowerShell_Encoded_Command
{
    meta:
        description = "PowerShell encoded-command token"
        scope = "static indicator only"
    strings:
        $powershell = "powershell" nocase ascii wide
        $encoded = "-encodedcommand" nocase ascii wide
        $short = " -enc " nocase ascii wide
    condition:
        $powershell and any of ($encoded, $short)
}

rule Suspicious_Office_AutoOpen
{
    meta:
        description = "Office auto-execution macro token"
        scope = "static indicator only"
    strings:
        $a = "AutoOpen" nocase ascii wide
        $b = "Document_Open" nocase ascii wide
        $c = "Workbook_Open" nocase ascii wide
    condition:
        any of them
}
