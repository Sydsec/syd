# YARA Threat Hunting Techniques

## IOC-Based Hunting

Indicators of Compromise (IOCs) are artifacts that indicate a system may have been compromised.

### Hash-Based Detection

```yara
import "hash"

rule Known_Malware_Hash {
    meta:
        description = "Detects known malware by hash"
        hash1 = "44d88612fea8a8f36de82e1278abb02f"
        hash2 = "e3b0c44298fc1c149afbf4c8996fb924"

    condition:
        hash.md5(0, filesize) == "44d88612fea8a8f36de82e1278abb02f" or
        hash.sha256(0, filesize) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

### IP Address Hunting

```yara
rule Suspicious_IP_IOCs {
    meta:
        description = "Detects known malicious IP addresses"
        threat_intel = "APT campaign XYZ"

    strings:
        // Known C2 IPs
        $ip1 = "192.168.1.100" ascii wide
        $ip2 = "10.0.0.50" ascii wide

        // IP in various formats
        $ip_hex = { C0 A8 01 64 }  // 192.168.1.100 in hex

        // Regex for IP patterns
        $ip_pattern = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/

    condition:
        any of them
}
```

### Domain Hunting

```yara
rule Malicious_Domains {
    meta:
        description = "Detects known malicious domains"

    strings:
        // Known C2 domains
        $domain1 = "evil-c2-server.com" ascii wide nocase
        $domain2 = "malware-download.net" ascii wide nocase

        // DGA-like patterns
        $dga = /[a-z]{10,20}\.(com|net|org|info)/ nocase

        // Suspicious TLDs
        $sus_tld1 = ".tk" ascii nocase
        $sus_tld2 = ".top" ascii nocase
        $sus_tld3 = ".xyz" ascii nocase

    condition:
        any of ($domain*) or
        ($dga and any of ($sus_tld*))
}
```

## Behavioral Detection Rules

### Process Injection Detection

```yara
rule Behavior_Process_Injection {
    meta:
        description = "Detects process injection techniques"
        mitre_attack = "T1055"

    strings:
        // Classic injection APIs
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "NtCreateThreadEx" ascii wide

        // APC injection
        $apc1 = "QueueUserAPC" ascii wide
        $apc2 = "NtQueueApcThread" ascii wide

        // Process hollowing
        $hollow1 = "NtUnmapViewOfSection" ascii wide
        $hollow2 = "ZwUnmapViewOfSection" ascii wide

        // Atom bombing
        $atom1 = "GlobalAddAtomA" ascii wide
        $atom2 = "NtQueueApcThread" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            ($api1 and $api2 and ($api3 or $api4)) or
            (all of ($apc*)) or
            (any of ($hollow*) and $api2) or
            (all of ($atom*))
        )
}
```

### Privilege Escalation Detection

```yara
rule Behavior_Privilege_Escalation {
    meta:
        description = "Detects privilege escalation attempts"
        mitre_attack = "T1068, T1134"

    strings:
        // Token manipulation
        $token1 = "OpenProcessToken" ascii wide
        $token2 = "AdjustTokenPrivileges" ascii wide
        $token3 = "ImpersonateLoggedOnUser" ascii wide
        $token4 = "DuplicateTokenEx" ascii wide

        // Named pipe impersonation
        $pipe1 = "ImpersonateNamedPipeClient" ascii wide
        $pipe2 = "CreateNamedPipe" ascii wide

        // Kernel exploits indicators
        $kernel1 = "NtQuerySystemInformation" ascii wide
        $kernel2 = "EnumDeviceDrivers" ascii wide
        $kernel3 = "ZwAllocateVirtualMemory" ascii wide

        // UAC bypass
        $uac1 = "pkgmgr.exe" ascii wide nocase
        $uac2 = "fodhelper.exe" ascii wide nocase
        $uac3 = "computerdefaults.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (
            3 of ($token*) or
            all of ($pipe*) or
            2 of ($kernel*) or
            any of ($uac*)
        )
}
```

## Lateral Movement Artifacts

```yara
rule Lateral_Movement_Indicators {
    meta:
        description = "Detects lateral movement techniques"
        mitre_attack = "T1021, T1570"

    strings:
        // PsExec patterns
        $psexec1 = "psexec" ascii wide nocase
        $psexec2 = "PSEXESVC" ascii wide
        $psexec3 = "\\ADMIN$\\" ascii wide

        // WMI lateral movement
        $wmi1 = "Win32_Process" ascii wide
        $wmi2 = "Win32_ScheduledJob" ascii wide
        $wmi3 = "process call create" ascii wide nocase

        // WinRM/PowerShell remoting
        $winrm1 = "Invoke-Command" ascii wide nocase
        $winrm2 = "Enter-PSSession" ascii wide nocase
        $winrm3 = "New-PSSession" ascii wide nocase

        // RDP indicators
        $rdp1 = "mstsc" ascii wide nocase
        $rdp2 = "termsrv.dll" ascii wide

        // SMB lateral
        $smb1 = "\\\\\\\\[^\\\\]+\\\\c$" nocase
        $smb2 = "net use" ascii wide nocase

    condition:
        2 of them
}
```

## Persistence Mechanism Detection

```yara
rule Persistence_Registry {
    meta:
        description = "Detects registry persistence mechanisms"
        mitre_attack = "T1547.001"

    strings:
        // Run keys
        $run1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $run2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $run3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii wide nocase

        // Winlogon
        $winlogon1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide nocase
        $winlogon2 = "Userinit" ascii wide
        $winlogon3 = "Shell" ascii wide

        // Services
        $service1 = "SYSTEM\\CurrentControlSet\\Services" ascii wide nocase
        $service2 = "ImagePath" ascii wide

        // AppInit DLLs
        $appinit = "AppInit_DLLs" ascii wide

        // COM hijacking
        $com1 = "InprocServer32" ascii wide
        $com2 = "CLSID" ascii wide

    condition:
        any of ($run*) or
        (any of ($winlogon*)) or
        ($service1 and $service2) or
        $appinit or
        (all of ($com*))
}

rule Persistence_Scheduled_Tasks {
    meta:
        description = "Detects scheduled task persistence"
        mitre_attack = "T1053.005"

    strings:
        // Task scheduler APIs
        $api1 = "ITaskScheduler" ascii wide
        $api2 = "ITaskService" ascii wide
        $api3 = "RegisterTaskDefinition" ascii wide

        // Command line
        $cmd1 = "schtasks /create" ascii wide nocase
        $cmd2 = "at.exe" ascii wide nocase

        // XML task definition
        $xml1 = "<Task " ascii wide
        $xml2 = "<Actions>" ascii wide
        $xml3 = "<Exec>" ascii wide

    condition:
        any of ($api*) or
        any of ($cmd*) or
        all of ($xml*)
}
```

## Credential Dumping Patterns

```yara
rule Credential_Dumping_LSASS {
    meta:
        description = "Detects LSASS credential dumping"
        mitre_attack = "T1003.001"

    strings:
        // LSASS access
        $lsass1 = "lsass.exe" ascii wide nocase
        $lsass2 = "lsass" ascii wide nocase

        // Memory dumping
        $dump1 = "MiniDumpWriteDump" ascii wide
        $dump2 = "dbghelp.dll" ascii wide
        $dump3 = "comsvcs.dll" ascii wide

        // Mimikatz strings
        $mimi1 = "mimikatz" ascii wide nocase
        $mimi2 = "sekurlsa" ascii wide nocase
        $mimi3 = "logonpasswords" ascii wide nocase
        $mimi4 = "wdigest" ascii wide nocase

        // Process access
        $access1 = "PROCESS_VM_READ" ascii wide
        $access2 = "OpenProcess" ascii wide

    condition:
        ($lsass1 or $lsass2) and
        (any of ($dump*) or any of ($mimi*) or all of ($access*))
}

rule Credential_Dumping_SAM {
    meta:
        description = "Detects SAM database credential dumping"
        mitre_attack = "T1003.002"

    strings:
        // SAM/SECURITY/SYSTEM paths
        $sam1 = "\\SAM" ascii wide
        $sam2 = "\\SECURITY" ascii wide
        $sam3 = "\\SYSTEM" ascii wide

        // Reg save commands
        $reg1 = "reg save" ascii wide nocase
        $reg2 = "reg.exe save" ascii wide nocase

        // Shadow copy access
        $shadow1 = "HarddiskVolumeShadowCopy" ascii wide
        $shadow2 = "\\\\?\\GLOBALROOT\\Device" ascii wide

    condition:
        (2 of ($sam*) and any of ($reg*)) or
        (2 of ($sam*) and any of ($shadow*))
}
```

## PowerShell/Script Hunting

```yara
rule Suspicious_PowerShell_Activity {
    meta:
        description = "Detects suspicious PowerShell activity"
        mitre_attack = "T1059.001"

    strings:
        // Obfuscation indicators
        $obf1 = "-Join" ascii nocase
        $obf2 = "[char]" ascii nocase
        $obf3 = "-replace" ascii nocase
        $obf4 = "-bxor" ascii nocase
        $obf5 = "[Convert]::" ascii nocase

        // Dangerous commands
        $cmd1 = "Invoke-Expression" ascii nocase
        $cmd2 = "Invoke-Command" ascii nocase
        $cmd3 = "Start-Process" ascii nocase
        $cmd4 = "Invoke-WmiMethod" ascii nocase

        // Evasion
        $evade1 = "-WindowStyle Hidden" ascii nocase
        $evade2 = "-ExecutionPolicy Bypass" ascii nocase
        $evade3 = "-NoProfile" ascii nocase
        $evade4 = "AMSI" ascii nocase

        // Download
        $dl1 = "Net.WebClient" ascii nocase
        $dl2 = "DownloadString" ascii nocase
        $dl3 = "Invoke-WebRequest" ascii nocase
        $dl4 = "DownloadFile" ascii nocase

    condition:
        3 of ($obf*) or
        (any of ($cmd*) and any of ($evade*)) or
        (any of ($dl*) and any of ($cmd*))
}
```

## Network Anomaly Detection

```yara
rule Network_Suspicious_Beaconing {
    meta:
        description = "Detects potential C2 beaconing patterns"

    strings:
        // HTTP headers often used by malware
        $http1 = "User-Agent: Mozilla/5.0" ascii
        $http2 = "Content-Type: application/octet-stream" ascii
        $http3 = "Accept: */*" ascii

        // Encoded data indicators
        $enc1 = "base64," ascii
        $enc2 = ";base64" ascii

        // Common C2 paths
        $path1 = "/api/v1/" ascii
        $path2 = "/update/" ascii
        $path3 = "/beacon/" ascii
        $path4 = "/gate.php" ascii
        $path5 = "/panel/" ascii

        // Timing patterns (sleep)
        $sleep1 = "Sleep(" ascii
        $sleep2 = "Thread.Sleep" ascii
        $sleep3 = "WaitForSingleObject" ascii

    condition:
        (2 of ($http*) and any of ($path*)) or
        (any of ($enc*) and any of ($sleep*))
}
```

## Anti-Analysis Detection

```yara
rule Anti_Analysis_Techniques {
    meta:
        description = "Detects anti-analysis techniques"
        mitre_attack = "T1497"

    strings:
        // VM detection
        $vm1 = "VMware" ascii wide nocase
        $vm2 = "VirtualBox" ascii wide nocase
        $vm3 = "QEMU" ascii wide nocase
        $vm4 = "Hyper-V" ascii wide nocase
        $vm5 = "vbox" ascii wide nocase

        // Sandbox detection
        $sb1 = "SbieDll" ascii wide
        $sb2 = "Sandboxie" ascii wide nocase
        $sb3 = "cuckoomon" ascii wide nocase
        $sb4 = "sample" ascii wide nocase
        $sb5 = "virus" ascii wide nocase

        // Debugger detection
        $dbg1 = "IsDebuggerPresent" ascii wide
        $dbg2 = "CheckRemoteDebuggerPresent" ascii wide
        $dbg3 = "NtQueryInformationProcess" ascii wide
        $dbg4 = "OutputDebugString" ascii wide
        $dbg5 = "int 2d" ascii
        $dbg6 = { CC CC CC CC }  // Breakpoints

        // Timing checks
        $time1 = "GetTickCount" ascii wide
        $time2 = "QueryPerformanceCounter" ascii wide
        $time3 = "rdtsc" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            3 of ($vm*) or
            2 of ($sb*) or
            3 of ($dbg*) or
            2 of ($time*)
        )
}
```

## Hunting Methodology

### Step-by-Step Hunt Process

1. **Define Hypothesis**
   - What threat are you hunting?
   - What behaviors would it exhibit?

2. **Identify Indicators**
   - Strings, patterns, behaviors
   - MITRE ATT&CK techniques

3. **Write Detection Rules**
   - Start broad, then refine
   - Test for false positives

4. **Deploy and Monitor**
   - Run against endpoints
   - Collect and analyze results

5. **Refine and Iterate**
   - Adjust based on findings
   - Document discoveries

### Hunt Query Template

```yara
rule Hunt_[TECHNIQUE]_[DATE] {
    meta:
        author = "Threat Hunter"
        description = "Hunting for [SPECIFIC BEHAVIOR]"
        hypothesis = "Adversary may use [TECHNIQUE] to [OBJECTIVE]"
        mitre_attack = "T1xxx"
        date = "2024-01-15"
        hunt_status = "active"

    strings:
        // Indicators specific to hypothesis
        $indicator1 = "pattern1"
        $indicator2 = "pattern2"

    condition:
        // Logic based on hypothesis
        all of them
}
```
