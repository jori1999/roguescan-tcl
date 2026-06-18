rule SuspiciousStrings {
    meta:
        description = "Detects reverse shell, webshell, and obfuscation patterns"
    strings:
        $revshell1 = ">/dev/tcp/"
        $revshell2 = "mkfifo"
        $revshell3 = "bash -i"
        $webshell1 = "system($_"
        $webshell2 = "eval($_"
        $webshell3 = "assert($_"
        $obfus1 = "base64_decode"
        $obfus2 = "gzinflate"
    condition:
        any of ($revshell*) or any of ($webshell*) or ($obfus1 and ($obfus2 or $webshell1))
}

rule SuspiciousProcessNames {
    meta:
        description = "Detects known malware/rootkit process names"
    strings:
        $name1 = "meterpreter" nocase
        $name2 = "mimikatz" nocase
        $name3 = "xmrig" nocase
        $name4 = "cryptominer" nocase
        $name5 = "cobaltstrike" nocase
        $name6 = "beacon" nocase
        $name7 = "keylog" nocase
        $name8 = "rootkit" nocase
        $name9 = "payload" nocase
        $name10 = "dropper" nocase
        $name11 = "reverse_shell" nocase
        $name12 = "bindshell" nocase
    condition:
        any of ($name*)
}

rule SuspiciousFileExtensions {
    meta:
        description = "Detects double extensions and suspicious file types"
    strings:
        $double1 = /\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(exe|scr|bat|cmd|ps1|vbs|js)$/
        $double2 = /\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\s*\.(exe|scr|bat|cmd|ps1|vbs|js)\s*$/
        $hidden = /\.(exe|scr|bat|cmd|ps1|vbs|js)\s*$/
    condition:
        any of ($double*) or $hidden
}

rule Base64Obfuscation {
    meta:
        description = "Detects heavily obfuscated scripts using base64"
    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/ ascii
    condition:
        #b64 > 3
}
