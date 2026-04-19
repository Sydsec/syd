"""
Volatility 3 Output Parser with Intelligent Threat Detection
Parses output from common Volatility plugins and detects ransomware, malware, C2, and credential theft
"""

import re
from typing import Dict, List, Any, Tuple


# Comprehensive threat pattern dictionary - similar to Nmap's VULN_PATTERNS
THREAT_PATTERNS = {
    'RANSOMWARE_SHADOW_DELETE': {
        'patterns': [
            r'vssadmin.*delete.*shadows',
            r'vssadmin.*Delete.*Shadows',
            r'wmic.*shadowcopy.*delete',
            r'shadowcopy.*delete',
            r'bcdedit.*bootstatuspolicy.*ignoreallfailures',
            r'bcdedit.*recoveryenabled.*no',
            r'wbadmin.*delete.*catalog',
            r'Delete\s+Shadows\s*/All'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'Ransomware - Shadow Copy Deletion',
        'description': 'Ransomware attempting to delete backup shadow copies'
    },
    'RANSOMWARE_RECOVERY_DISABLE': {
        'patterns': [
            r'bcdedit.*set.*recoveryenabled.*no',
            r'bcdedit.*set.*bootstatuspolicy.*ignoreallfailures',
            r'reagentc.*disable',
            r'wbadmin.*delete.*systemstatebackup'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'Ransomware - Recovery Disabling',
        'description': 'Ransomware disabling Windows recovery features'
    },
    'RANSOMWARE_FILE_WIPE': {
        'patterns': [
            r'cipher\.exe.*\/w',
            r'sdelete',
            r'cipher.*delete',
            r'secure.*wipe'
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'Ransomware - Secure File Wiping',
        'description': 'Ransomware wiping free space to prevent file recovery'
    },
    'MALWARE_DOUBLE_EXTENSION': {
        'patterns': [
            r'\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|zip)\.(exe|scr|bat|cmd|ps1|vbs|js)',
            r'\.pdf\.exe',
            r'\.doc\.exe',
            r'invoice.*\.exe',
            r'receipt.*\.exe',
            r'document.*\.exe'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'Malware - Double Extension',
        'description': 'Malicious executable masquerading as document'
    },
    'MALWARE_TEMP_EXECUTION': {
        'patterns': [
            r'(temp|tmp|appdata|downloads|public).*\.exe',
            r'\\Temp\\.*\.exe',
            r'\\Downloads\\.*\.exe',
            r'\\AppData\\Local\\Temp',
            r'\\Public\\.*\.exe'
        ],
        'score': 7,
        'severity': 'HIGH',
        'category': 'Malware - Execution from Temp',
        'description': 'Executable running from temporary or suspicious location'
    },
    'MALWARE_SUSPICIOUS_NAMES': {
        'patterns': [
            r'\b(mimikatz|procdump|psexec|netcat|nc\.exe|pwdump|fgdump)\b',
            r'svch0st',  # Misspelled svchost
            r'csrss\s',  # csrss with space (fake)
            r'lsasss',   # lsass misspelled
            r'smss\s',   # smss with space
            r'winl0g0n'  # winlogon misspelled with zeros
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'Malware - Suspicious Process Name',
        'description': 'Known malware tool or process impersonation detected'
    },
    'C2_SUSPICIOUS_CONNECTION': {
        'patterns': [
            r'(\.pdf|\.doc|\.xls|\.jpg|\.png)\.exe.*ESTABLISHED',
            r'powershell.*\d+\.\d+\.\d+\.\d+.*ESTABLISHED',
            r'cmd\.exe.*\d+\.\d+\.\d+\.\d+.*ESTABLISHED'
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'C2 - Suspicious Process Network Activity',
        'description': 'Unusual process making network connections (likely C2)'
    },
    'C2_SUSPICIOUS_PORTS': {
        'patterns': [
            r':(4444|5555|6666|7777|8888|31337|1337)\s+(ESTABLISHED|LISTENING)',
            r'port.*4444',
            r'port.*31337'
        ],
        'score': 8,
        'severity': 'HIGH',
        'category': 'C2 - Known Malicious Ports',
        'description': 'Connection to commonly used C2 framework ports'
    },
    'CODE_INJECTION_RWX': {
        'patterns': [
            r'PAGE_EXECUTE_READWRITE',
            r'\bRWX\b',
            r'VadS.*EXECUTE_READWRITE'
        ],
        'score': 8,
        'severity': 'HIGH',
        'category': 'Code Injection - RWX Memory',
        'description': 'Process contains executable writable memory (code injection)'
    },
    'CODE_INJECTION_HOLLOW': {
        'patterns': [
            r'hollowing',
            r'process.*replaced',
            r'unmapped.*pe',
            r'rebased.*image'
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'Code Injection - Process Hollowing',
        'description': 'Process hollowing detected (malware technique)'
    },
    'CREDENTIAL_THEFT_LSASS': {
        'patterns': [
            r'(procdump|mimikatz|pwdump).*lsass',
            r'lsass\.exe.*dump',
            r'access.*lsass\.exe',
            r'reading.*lsass'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'Credential Theft - LSASS Access',
        'description': 'Credential dumping tool accessing lsass.exe'
    },
    'CREDENTIAL_THEFT_HASHDUMP': {
        'patterns': [
            r'hashdump',
            r'lsadump',
            r'samdump',
            r'secretsdump',
            r'[a-f0-9]{32}:[a-f0-9]{32}'  # NT hash format
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'Credential Theft - Hash Extraction',
        'description': 'Password hash dumping activity detected'
    },
    'PERSISTENCE_REGISTRY': {
        'patterns': [
            r'\\Run\\.*\.exe',
            r'\\RunOnce\\.*\.exe',
            r'CurrentVersion\\Run',
            r'HKLM\\.*\\Run\\',
            r'Startup.*\.exe'
        ],
        'score': 6,
        'severity': 'MEDIUM',
        'category': 'Persistence - Registry Run Keys',
        'description': 'Persistence mechanism via registry run keys'
    },
    'PERSISTENCE_SCHEDULED_TASK': {
        'patterns': [
            r'schtasks.*create',
            r'at.*\d\d:\d\d',
            r'scheduled.*task.*create',
            r'taskschd\.dll'
        ],
        'score': 6,
        'severity': 'MEDIUM',
        'category': 'Persistence - Scheduled Tasks',
        'description': 'Scheduled task creation for persistence'
    },
    'LATERAL_MOVEMENT': {
        'patterns': [
            r'psexec',
            r'wmic.*process.*call.*create',
            r'winrm',
            r'wmiprvse\.exe.*\d+\.\d+\.\d+\.\d+',
            r'net.*use.*\\\\',
            r'net.*share'
        ],
        'score': 8,
        'severity': 'HIGH',
        'category': 'Lateral Movement',
        'description': 'Tools or techniques used for lateral movement'
    },
    'ANTI_FORENSICS': {
        'patterns': [
            r'timestomp',
            r'modify.*timestamp',
            r'clear.*eventlog',
            r'wevtutil.*cl',
            r'del.*\s/f\s/q',
            r'powershell.*-ep\s+bypass'
        ],
        'score': 7,
        'severity': 'HIGH',
        'category': 'Anti-Forensics',
        'description': 'Anti-forensics techniques detected'
    },
    # ===== Linux-Specific Threats =====
    'LINUX_CRYPTO_MINER': {
        'patterns': [
            r'\b(xmrig|cpuminer|minerd|xmr-stak|ethminer)\b',
            r'pool\..*\.(com|net):?\d*',
            r'--url.*pool',
            r'--donate-level',
            r'stratum\+tcp://',
            r'mining.*pool'
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'Linux - Cryptocurrency Miner',
        'description': 'Cryptocurrency mining malware detected'
    },
    'LINUX_SSH_BACKDOOR': {
        'patterns': [
            r'authorized_keys',
            r'ssh-rsa\s+AAAA',
            r'\.ssh/config',
            r'PermitRootLogin\s+yes',
            r'/etc/pam\.d/',
            r'pam_unix\.so.*debug'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'Linux - SSH Backdoor',
        'description': 'SSH backdoor or unauthorized key detected'
    },
    'LINUX_ROOTKIT': {
        'patterns': [
            r'\b(diamorphine|suterusu|reptile|vlany)\b',
            r'insmod.*\.ko',
            r'/tmp/.*\.ko',
            r'/dev/shm/.*\.ko',
            r'LD_PRELOAD.*\.so',
            r'hidden.*module'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'Linux - Rootkit',
        'description': 'Linux rootkit kernel module detected'
    },
    'LINUX_CONTAINER_ESCAPE': {
        'patterns': [
            r'nsenter',
            r'unshare',
            r'docker.*--privileged',
            r'mount.*proc.*host',
            r'/host/root',
            r'CVE-2019-5736',
            r'runc.*exploit'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'Linux - Container Escape',
        'description': 'Container escape attempt detected'
    },
    'LINUX_PERSISTENCE_CRON': {
        'patterns': [
            r'crontab\s+-[le]',
            r'\*/\d+\s+\*\s+\*\s+\*\s+\*',
            r'/etc/cron\.d/',
            r'/var/spool/cron',
            r'@reboot.*(/tmp|/dev/shm)'
        ],
        'score': 7,
        'severity': 'HIGH',
        'category': 'Linux - Cron Persistence',
        'description': 'Malware persistence via cron jobs'
    },
    'LINUX_PERSISTENCE_SYSTEMD': {
        'patterns': [
            r'systemctl\s+enable',
            r'\.service',
            r'/etc/systemd/system/',
            r'/lib/systemd/system/',
            r'WantedBy=multi-user\.target',
            r'ExecStart.*(/tmp|/dev/shm)'
        ],
        'score': 7,
        'severity': 'HIGH',
        'category': 'Linux - Systemd Persistence',
        'description': 'Malware persistence via systemd service'
    },
    'LINUX_WEBSHELL': {
        'patterns': [
            r'(c99|r57|b374k|wso)\.php',
            r'shell\.php',
            r'system\(\$_GET',
            r'eval\(\$_POST',
            r'passthru\(',
            r'base64_decode.*eval'
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'Linux - Web Shell',
        'description': 'PHP/Python web shell detected'
    },
    'LINUX_SUSP_LOCATION': {
        'patterns': [
            r'/tmp/\.[a-zA-Z0-9]+',
            r'/dev/shm/.*',
            r'/var/tmp/\.[a-zA-Z0-9]+',
            r'\.hidden/',
            r'/tmp/.*\.(sh|py|pl|elf)'
        ],
        'score': 8,
        'severity': 'HIGH',
        'category': 'Linux - Suspicious File Location',
        'description': 'Executable in suspicious location (/tmp, /dev/shm, hidden directory)'
    },
    'LINUX_HISTORY_MANIPULATION': {
        'patterns': [
            r'history\s+-c',
            r'unset\s+HISTFILE',
            r'HISTSIZE\s*=\s*0',
            r'rm\s+.*\.bash_history',
            r'ln\s+-sf\s+/dev/null.*history',
            r'export\s+HISTFILE=/dev/null'
        ],
        'score': 8,
        'severity': 'HIGH',
        'category': 'Linux - History Manipulation',
        'description': 'Attacker clearing command history (anti-forensics)'
    },
    # ===== Mac-Specific Threats =====
    'MAC_ADWARE': {
        'patterns': [
            r'\b(shlayer|pirrit|bundlore|adload)\b',
            r'MacKeeper',
            r'Advanced\s+Mac\s+Cleaner',
            r'/Library/Application\s+Support/.*\.app',
            r'Safari.*extension.*inject'
        ],
        'score': 7,
        'severity': 'HIGH',
        'category': 'macOS - Adware',
        'description': 'macOS adware detected'
    },
    'MAC_INFOSTEALER': {
        'patterns': [
            r'security\s+dump-keychain',
            r'Keychain.*password',
            r'(Electrum|Exodus|Coinomi)',
            r'wallet\.dat',
            r'\.safariextension',
            r'Cookies\.binarycookies'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'macOS - Infostealer',
        'description': 'macOS infostealer targeting credentials/wallets'
    },
    'MAC_LAUNCHAGENT_PERSIST': {
        'patterns': [
            r'LaunchAgents/.*\.plist',
            r'LaunchDaemons/.*\.plist',
            r'launchctl\s+load',
            r'RunAtLoad.*true',
            r'KeepAlive.*true',
            r'/Library/LaunchAgents/(?!com\.apple)'
        ],
        'score': 7,
        'severity': 'HIGH',
        'category': 'macOS - LaunchAgent Persistence',
        'description': 'Persistence via LaunchAgent/LaunchDaemon'
    },
    'MAC_LOGINITEM_PERSIST': {
        'patterns': [
            r'loginitems\.plist',
            r'tell\s+application.*System\s+Events.*login\s+item',
            r'SMLoginItemSetEnabled',
            r'StartupItems/',
            r'osascript.*login.*item'
        ],
        'score': 6,
        'severity': 'MEDIUM',
        'category': 'macOS - Login Item Persistence',
        'description': 'Persistence via login items'
    },
    'MAC_DYLIB_HIJACK': {
        'patterns': [
            r'@rpath/.*\.dylib',
            r'@executable_path/.*\.dylib',
            r'DYLD_INSERT_LIBRARIES',
            r'\.dylib.*inject',
            r'/tmp/.*\.dylib',
            r'/Users/Shared/.*\.dylib'
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'macOS - Dylib Hijacking',
        'description': 'Dynamic library hijacking detected'
    },
    'MAC_SUSP_LOCATION': {
        'patterns': [
            r'/tmp/\.[a-zA-Z0-9]+',
            r'/private/tmp/.*\.app',
            r'/Users/Shared/.*\.app',
            r'\.hidden/.*\.app',
            r'/Library/Application\s+Support/\.[a-zA-Z]+'
        ],
        'score': 8,
        'severity': 'HIGH',
        'category': 'macOS - Suspicious Location',
        'description': 'Application in suspicious location'
    },
    'MAC_OSASCRIPT_ABUSE': {
        'patterns': [
            r'osascript\s+-e',
            r'do\s+shell\s+script',
            r'tell\s+application.*Terminal',
            r'JavaScript.*ObjC\.import',
            r'eval\(ObjC\.unwrap'
        ],
        'score': 7,
        'severity': 'HIGH',
        'category': 'macOS - AppleScript Abuse',
        'description': 'Malicious use of osascript/AppleScript'
    },
    # ===== Cross-Platform C2 Frameworks =====
    'C2_COBALT_STRIKE': {
        'patterns': [
            r'\b(beacon|cobaltstrike|cs\.exe)\b',
            r'Mozilla/5\.0.*MSIE\s+\d+\.0',
            r'port\s+(50050|7443)',
            r'malleable.*profile',
            r'powershell.*IEX.*http'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'C2 - Cobalt Strike',
        'description': 'Cobalt Strike C2 beacon detected'
    },
    'C2_METASPLOIT': {
        'patterns': [
            r'\b(meterpreter|msf|metasploit)\b',
            r'reverse_tcp',
            r'reverse_https',
            r'metsrv\.dll',
            r'ReflectiveLoader',
            r'port.*4444'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'C2 - Metasploit',
        'description': 'Metasploit Meterpreter detected'
    },
    'C2_EMPIRE_POWERSHELL': {
        'patterns': [
            r'\b(empire|starkiller)\b',
            r'powershell.*-enc\s+[A-Za-z0-9+/=]{50,}',
            r'System\.Net\.WebClient.*DownloadString',
            r'IEX\s+\(New-Object',
            r'Invoke-Empire',
            r'agent\.ps1'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'C2 - Empire/Starkiller',
        'description': 'PowerShell Empire C2 agent detected'
    },
    'C2_SLIVER': {
        'patterns': [
            r'\b(sliver|sliverC2)\b',
            r'implant.*beacon',
            r'mtls.*C2',
            r'wireguard.*tunnel',
            r'/tmp/sliver'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'C2 - Sliver',
        'description': 'Sliver C2 framework detected'
    },
    'C2_POSHC2': {
        'patterns': [
            r'\bposhc2\b',
            r'PoshC2.*implant',
            r'dropper\.ps1',
            r'SharpSocks',
            r'Invoke-PowerShellTcp'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'C2 - PoshC2',
        'description': 'PoshC2 C2 framework detected'
    },

    # ===== LIVING OFF THE LAND BINARIES (LOLBins) =====
    'LOLBIN_CERTUTIL': {
        'patterns': [
            r'certutil.*-decode',
            r'certutil.*-urlcache',
            r'certutil.*-f.*http',
            r'certutil.*-split',
            r'certutil.*-encode'
        ],
        'score': 8,
        'severity': 'HIGH',
        'category': 'LOLBin - Certutil Abuse',
        'description': 'Certutil abused for file download or encoding (common malware technique)'
    },
    'LOLBIN_BITSADMIN': {
        'patterns': [
            r'bitsadmin.*\/transfer',
            r'bitsadmin.*\/download',
            r'bitsadmin.*\/addfile',
            r'bitsadmin.*http'
        ],
        'score': 8,
        'severity': 'HIGH',
        'category': 'LOLBin - BITSAdmin Abuse',
        'description': 'BITSAdmin used for malicious file download'
    },
    'LOLBIN_MSHTA': {
        'patterns': [
            r'mshta.*http',
            r'mshta.*javascript:',
            r'mshta.*vbscript:',
            r'mshta\.exe.*\.hta'
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'LOLBin - MSHTA Abuse',
        'description': 'MSHTA used to execute malicious HTA/script (fileless malware)'
    },
    'LOLBIN_REGSVR32': {
        'patterns': [
            r'regsvr32.*\/s.*\/u.*\/i:http',
            r'regsvr32.*scrobj\.dll',
            r'regsvr32.*\.sct',
            r'regsvr32.*\/i:.*\.xml'
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'LOLBin - Regsvr32 Abuse',
        'description': 'Regsvr32 used for script execution bypass (Squiblydoo technique)'
    },
    'LOLBIN_WMIC': {
        'patterns': [
            r'wmic.*process.*call.*create',
            r'wmic.*\/node:',
            r'wmic.*\/format:.*http',
            r'wmic.*shadowcopy.*delete'
        ],
        'score': 8,
        'severity': 'HIGH',
        'category': 'LOLBin - WMIC Abuse',
        'description': 'WMIC used for remote execution or malicious operations'
    },
    'LOLBIN_MSIEXEC': {
        'patterns': [
            r'msiexec.*\/q.*http',
            r'msiexec.*\/i.*http',
            r'msiexec.*\/quiet'
        ],
        'score': 7,
        'severity': 'HIGH',
        'category': 'LOLBin - MSIExec Abuse',
        'description': 'MSIExec used to download and execute remote MSI packages'
    },
    'LOLBIN_RUNDLL32_ADVANCED': {
        'patterns': [
            r'rundll32.*javascript:',
            r'rundll32.*comsvcs\.dll.*MiniDump',
            r'rundll32.*ieadvpack\.dll',
            r'rundll32.*pcwutl\.dll'
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'LOLBin - Rundll32 Advanced Abuse',
        'description': 'Rundll32 used for credential dumping or script execution'
    },
    'LOLBIN_FORFILES': {
        'patterns': [
            r'forfiles.*\/c.*cmd',
            r'forfiles.*\/c.*powershell',
            r'forfiles.*\/c.*calc'
        ],
        'score': 6,
        'severity': 'MEDIUM',
        'category': 'LOLBin - Forfiles Abuse',
        'description': 'Forfiles used to execute arbitrary commands'
    },
    'LOLBIN_INSTALLUTIL': {
        'patterns': [
            r'installutil\.exe.*\/logfile=',
            r'installutil\.exe.*\/U'
        ],
        'score': 8,
        'severity': 'HIGH',
        'category': 'LOLBin - InstallUtil Abuse',
        'description': 'InstallUtil used to execute malicious .NET assemblies'
    },

    # ===== CLOUD & SAAS ABUSE =====
    'CLOUD_AZURE_TOKEN_THEFT': {
        'patterns': [
            r'Get-AzureADToken',
            r'\.azure.*credentials',
            r'az\s+account\s+get-access-token',
            r'Invoke-AADIntReconAsOutsider',
            r'AADInternals',
            r'\.azure.*accessTokens\.json'
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'Cloud - Azure AD Token Theft',
        'description': 'Azure AD token theft or enumeration detected'
    },
    'CLOUD_AWS_CREDENTIAL_DUMP': {
        'patterns': [
            r'\.aws.*credentials',
            r'aws\s+configure\s+export-credentials',
            r'AWS_ACCESS_KEY_ID',
            r'AWS_SECRET_ACCESS_KEY',
            r'aws.*sts.*get-session-token',
            r'~/.aws/credentials'
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'Cloud - AWS Credential Theft',
        'description': 'AWS credentials being accessed or exfiltrated'
    },
    'CLOUD_GCP_CREDENTIAL_ACCESS': {
        'patterns': [
            r'gcloud\s+auth\s+list',
            r'gcloud\s+auth\s+print-access-token',
            r'\.config.*gcloud.*credentials',
            r'GOOGLE_APPLICATION_CREDENTIALS',
            r'service-account.*\.json'
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'Cloud - GCP Credential Theft',
        'description': 'Google Cloud credentials being accessed'
    },
    'CLOUD_KUBERNETES_ESCAPE': {
        'patterns': [
            r'kubectl.*--token=',
            r'kubectl.*get\s+secrets',
            r'/var/run/secrets/kubernetes\.io',
            r'kubectl.*exec.*\/bin\/bash',
            r'serviceaccount.*token'
        ],
        'score': 8,
        'severity': 'HIGH',
        'category': 'Cloud - Kubernetes Token Access',
        'description': 'Kubernetes service account token access (potential cluster compromise)'
    },
    'CLOUD_METADATA_ACCESS': {
        'patterns': [
            r'169\.254\.169\.254',
            r'curl.*metadata\.google\.internal',
            r'Invoke-RestMethod.*169\.254\.169\.254',
            r'wget.*169\.254\.169\.254'
        ],
        'score': 8,
        'severity': 'HIGH',
        'category': 'Cloud - Instance Metadata Access',
        'description': 'Cloud instance metadata service accessed (credential harvesting)'
    },

    # ===== CONTAINER ESCAPES =====
    'CONTAINER_DOCKER_ESCAPE': {
        'patterns': [
            r'docker.*--privileged',
            r'/var/run/docker\.sock',
            r'docker.*-v\s+/:/host',
            r'nsenter.*--target.*--mount.*--uts.*--ipc.*--net',
            r'runc.*exec'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'Container - Docker Escape',
        'description': 'Docker container escape attempt detected'
    },
    'CONTAINER_BREAKOUT_CVE': {
        'patterns': [
            r'CVE-2019-5736',
            r'CVE-2022-0492',
            r'dirtycow',
            r'shocker\.c',
            r'runc.*override'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'Container - Known CVE Exploit',
        'description': 'Known container escape vulnerability exploitation'
    },
    'CONTAINER_CAPABILITIES_ABUSE': {
        'patterns': [
            r'capsh.*--print',
            r'setcap.*cap_sys_admin',
            r'CAP_SYS_ADMIN',
            r'CAP_SYS_PTRACE',
            r'getcap.*\/bin\/'
        ],
        'score': 7,
        'severity': 'HIGH',
        'category': 'Container - Capability Abuse',
        'description': 'Linux capabilities being manipulated (privilege escalation)'
    },
    'CONTAINER_CGROUP_ESCAPE': {
        'patterns': [
            r'\/proc\/1\/cgroup',
            r'cgroupv2',
            r'release_agent',
            r'notify_on_release',
            r'\/sys\/fs\/cgroup'
        ],
        'score': 8,
        'severity': 'HIGH',
        'category': 'Container - Cgroup Escape',
        'description': 'Container cgroup manipulation detected (escape attempt)'
    },

    # ===== HARDWARE & FIRMWARE THREATS =====
    'HARDWARE_DMA_ATTACK': {
        'patterns': [
            r'pcileech',
            r'DMA.*attack',
            r'Thunderbolt.*exploit',
            r'FireWire.*attack',
            r'PCIe.*arbiter'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'Hardware - DMA Attack',
        'description': 'Direct Memory Access (DMA) attack detected (physical access)'
    },
    'HARDWARE_UEFI_ROOTKIT': {
        'patterns': [
            r'BootExecute',
            r'UEFI.*rootkit',
            r'EFI.*backdoor',
            r'\\EFI\\.*malware',
            r'SecureBoot.*disable'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'Hardware - UEFI/BIOS Rootkit',
        'description': 'UEFI/BIOS level rootkit detected (persistent firmware malware)'
    },
    'HARDWARE_HYPERVISOR_ROOTKIT': {
        'patterns': [
            r'Blue\s+Pill',
            r'SubVirt',
            r'VMCS.*shadow',
            r'hypervisor.*rootkit',
            r'VT-x.*hijack'
        ],
        'score': 10,
        'severity': 'CRITICAL',
        'category': 'Hardware - Hypervisor Rootkit',
        'description': 'Hypervisor-level rootkit detected (below OS level)'
    },
    'HARDWARE_COLD_BOOT_ATTACK': {
        'patterns': [
            r'cold\s+boot.*attack',
            r'RAM.*freezing',
            r'memory.*remanence',
            r'BitLocker.*key.*extract'
        ],
        'score': 9,
        'severity': 'CRITICAL',
        'category': 'Hardware - Cold Boot Attack',
        'description': 'Cold boot attack indicators (RAM extraction)'
    }
}


def parse_volatility_output(output: str) -> Dict[str, Any]:
    """
    Parse Volatility 3 output and extract structured data

    Detects plugin type and routes to appropriate parser
    """
    output_lower = output.lower()

    # Detect plugin type from output - check for specific patterns and headers
    # Priority order: most specific first

    # Check for process list first (most common) - look for PID PPID ImageFileName pattern
    if ('pslist' in output_lower or 'pstree' in output_lower or 'psscan' in output_lower or
        ('imagefilename' in output_lower and 'ppid' in output_lower) or
        (re.search(r'pid\s+ppid\s+(imagefilename|image|process)', output_lower))):
        return parse_process_list(output)
    elif 'malfind' in output_lower or 'page_execute_readwrite' in output_lower:
        return parse_malfind(output)
    elif ('netscan' in output_lower or 'netstat' in output_lower or
          ('localaddr' in output_lower and 'remoteaddr' in output_lower) or
          ('local address' in output_lower and 'remote address' in output_lower)):
        return parse_network_connections(output)
    elif 'hashdump' in output_lower or 'lsadump' in output_lower or re.search(r':\d+:[a-f0-9]{32}:', output_lower):
        return parse_credentials(output)
    elif 'filescan' in output_lower or (r'\users\\'  in output_lower and 'offset' in output_lower):
        return parse_filescan(output)
    elif 'cmdline' in output_lower and 'command line' in output_lower:
        return parse_cmdline(output)
    elif 'dlllist' in output_lower or 'ldrmodules' in output_lower:
        return parse_dll_list(output)
    elif ('windows.handles' in output_lower or
          (re.search(r'handle\s+(value|type)', output_lower))):  # More specific for handles plugin
        return parse_handles(output)
    else:
        # Generic fallback parser
        return parse_generic(output)


def detect_threats(output: str) -> Tuple[List[Dict[str, Any]], int]:
    """
    Detect threats in Volatility output using pattern matching
    Returns: (threat_list, total_threat_score)

    Similar to Nmap's vulnerability detection
    """
    threats = []
    total_score = 0
    lines = output.split('\n')

    current_pid = None
    current_process = None

    for line in lines:
        # Extract PID and process name for context
        pid_match = re.match(r'(\d+)\s+(\d+)\s+(\S+)', line)
        if pid_match:
            current_pid = pid_match.group(1)
            current_process = pid_match.group(3)

        # Match against ALL threat patterns
        for threat_type, threat_config in THREAT_PATTERNS.items():
            for pattern in threat_config['patterns']:
                if re.search(pattern, line, re.IGNORECASE):
                    threats.append({
                        'type': threat_type,
                        'severity': threat_config['severity'],
                        'score': threat_config['score'],
                        'category': threat_config['category'],
                        'description': threat_config['description'],
                        'pid': current_pid,
                        'process': current_process,
                        'evidence': line.strip(),
                        'matched_pattern': pattern
                    })
                    total_score += threat_config['score']
                    break  # Only match once per line per threat type

    return threats, total_score


def parse_process_list(output: str) -> Dict[str, Any]:
    """Parse ps list/tree/scan output with enhanced threat detection"""
    processes = []
    suspicious_patterns = {
        'no_parent': [],
        'hidden': [],
        'malicious_names': [],
        'double_extension': [],
        'temp_execution': []
    }

    lines = output.split('\n')

    for line in lines:
        # Match typical pslist format: PID PPID ImageName Offset Threads Handles SessionId
        match = re.match(r'(\d+)\s+(\d+)\s+(\S+)\s+(0x[0-9a-f]+)\s+(\d+)\s+(\d+)\s+(\d+)', line, re.IGNORECASE)

        if match:
            pid = match.group(1)
            ppid = match.group(2)
            name = match.group(3)
            offset = match.group(4)
            threads = match.group(5)
            handles = match.group(6)
            session = match.group(7)

            process_entry = {
                'pid': pid,
                'ppid': ppid,
                'name': name,
                'offset': offset,
                'threads': threads,
                'handles': handles,
                'session': session,
                'details': line.strip()
            }

            processes.append(process_entry)

            # Enhanced threat detection
            if ppid == '0' and name.lower() not in ['system', 'idle']:
                suspicious_patterns['no_parent'].append({'pid': pid, 'name': name})

            # Check for double extensions
            if re.search(r'\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(exe|scr|bat)', name.lower()):
                suspicious_patterns['double_extension'].append({'pid': pid, 'name': name})

            # Check for known malware tools
            if any(sus in name.lower() for sus in ['mimikatz', 'procdump', 'psexec', 'netcat', 'nc.exe', 'pwdump']):
                suspicious_patterns['malicious_names'].append({'pid': pid, 'name': name})

    return {
        'plugin': 'pslist',
        'processes': processes,
        'total_count': len(processes),
        'suspicious': suspicious_patterns
    }


def parse_network_connections(output: str) -> Dict[str, Any]:
    """Parse netscan/netstat output with C2 detection"""
    connections = []
    suspicious_connections = []
    c2_indicators = []

    # Common C2 ports
    suspicious_ports = [4444, 5555, 6666, 7777, 8888, 31337, 1337]

    lines = output.split('\n')

    for line in lines:
        # Match various network connection formats
        # Format: Offset Proto LocalAddr LocalPort RemoteAddr RemotePort State PID Process
        match = re.search(r'(TCP|UDP|TCPv4|UDPv4)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(ESTABLISHED|LISTENING|CLOSED)\s+(\d+)\s+(\S+)', line, re.IGNORECASE)

        if match:
            protocol = match.group(1)
            local_ip = match.group(2)
            local_port = match.group(3)
            remote_ip = match.group(4)
            remote_port = match.group(5)
            state = match.group(6)
            pid = match.group(7)
            process = match.group(8)

            conn_entry = {
                'protocol': protocol,
                'local_ip': local_ip,
                'local_port': int(local_port) if local_port and local_port.isdigit() else local_port,
                'remote_ip': remote_ip,
                'remote_port': int(remote_port) if remote_port and remote_port.isdigit() else remote_port,
                'state': state,
                'pid': pid,
                'process': process,
                'details': line.strip()
            }

            connections.append(conn_entry)

            # Check for suspicious ports
            if int(remote_port) in suspicious_ports:
                suspicious_connections.append(conn_entry)

            # Check for suspicious processes making connections
            if re.search(r'\.(pdf|doc|xls|jpg|png)\.exe', process.lower()):
                c2_indicators.append({
                    'reason': 'Document-disguised executable making network connection',
                    'process': process,
                    'remote': f"{remote_ip}:{remote_port}",
                    'details': line.strip()
                })

            # Unusual processes making connections
            if process.lower() in ['cmd.exe', 'powershell.exe', 'wscript.exe'] and state == 'ESTABLISHED':
                c2_indicators.append({
                    'reason': 'Scripting process making network connection',
                    'process': process,
                    'remote': f"{remote_ip}:{remote_port}",
                    'details': line.strip()
                })

    return {
        'plugin': 'netscan',
        'connections': connections,
        'total_count': len(connections),
        'suspicious_connections': suspicious_connections,
        'c2_indicators': c2_indicators
    }


def parse_malfind(output: str) -> Dict[str, Any]:
    """Parse malfind output for code injection indicators"""
    findings = []
    injected_processes = []
    rwx_processes = []

    lines = output.split('\n')
    current_pid = None
    current_process = None

    for line in lines:
        # Match process info
        match = re.search(r'(\d+)\s+(\S+)', line)
        if match:
            current_pid = match.group(1)
            current_process = match.group(2)

        # Detect RWX memory (critical code injection indicator)
        if 'page_execute_readwrite' in line.lower() or 'rwx' in line.lower():
            if current_process:
                injected_processes.append(current_process)
                rwx_processes.append({
                    'pid': current_pid,
                    'process': current_process,
                    'details': line.strip()
                })
                findings.append({
                    'pid': current_pid,
                    'process': current_process,
                    'indicator': 'RWX Memory',
                    'severity': 'HIGH',
                    'details': line.strip()
                })

    return {
        'plugin': 'malfind',
        'findings': findings,
        'total_count': len(findings),
        'injected_processes': list(set(injected_processes)),
        'rwx_processes': rwx_processes
    }


def parse_filescan(output: str) -> Dict[str, Any]:
    """Parse filescan output"""
    files = []
    suspicious_files = []
    double_extension_files = []

    suspicious_extensions = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js']
    suspicious_paths = ['temp', 'appdata', 'programdata', 'public', 'downloads']

    lines = output.split('\n')

    for line in lines:
        # Match file paths
        if '\\' in line or '/' in line:
            # Extract file path
            path_match = re.search(r'([A-Za-z]:\\[^\s]+|/[^\s]+)', line)
            if path_match:
                file_path = path_match.group(1)

                files.append({
                    'path': file_path,
                    'details': line.strip()
                })

                # Check for double extensions
                if re.search(r'\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(exe|scr|bat)', file_path.lower()):
                    double_extension_files.append(file_path)

                # Flag suspicious files
                lower_path = file_path.lower()
                if any(ext in lower_path for ext in suspicious_extensions):
                    if any(sus_path in lower_path for sus_path in suspicious_paths):
                        suspicious_files.append(file_path)

    return {
        'plugin': 'filescan',
        'files': files,
        'total_count': len(files),
        'suspicious_files': suspicious_files,
        'double_extension_files': double_extension_files
    }


def parse_dll_list(output: str) -> Dict[str, Any]:
    """Parse DLL list output"""
    dlls = []
    unsigned_dlls = []

    lines = output.split('\n')

    for line in lines:
        if '.dll' in line.lower():
            dlls.append({'details': line.strip()})

            # Flag unsigned or suspicious DLLs
            if 'unsigned' in line.lower() or 'unknown' in line.lower():
                unsigned_dlls.append(line.strip())

    return {
        'plugin': 'dlllist',
        'dlls': dlls,
        'total_count': len(dlls),
        'unsigned_dlls': unsigned_dlls
    }


def parse_credentials(output: str) -> Dict[str, Any]:
    """Parse hashdump/lsadump output"""
    credentials = []

    lines = output.split('\n')

    for line in lines:
        # Match hash format: username:rid:lm_hash:ntlm_hash
        if ':' in line and len(line.split(':')) >= 4:
            parts = line.split(':')
            if len(parts[2]) == 32 or len(parts[3]) == 32:  # Hash length
                credentials.append({
                    'username': parts[0],
                    'hash': line.strip()
                })

    return {
        'plugin': 'hashdump',
        'credentials': credentials,
        'total_count': len(credentials)
    }


def parse_cmdline(output: str) -> Dict[str, Any]:
    """Parse command line arguments with ransomware detection"""
    commands = []
    suspicious_commands = []
    ransomware_indicators = []

    suspicious_keywords = ['powershell', 'cmd.exe', 'wscript', 'cscript', 'rundll32', 'regsvr32']
    ransomware_keywords = ['vssadmin', 'bcdedit', 'cipher', 'wbadmin', 'shadow', 'delete']

    lines = output.split('\n')

    for line in lines:
        # Check for ransomware command patterns
        if any(keyword in line.lower() for keyword in ransomware_keywords):
            ransomware_indicators.append({
                'severity': 'CRITICAL',
                'command': line.strip()
            })

        # Check for suspicious commands
        if any(keyword in line.lower() for keyword in suspicious_keywords):
            commands.append({'details': line.strip()})
            suspicious_commands.append(line.strip())

    return {
        'plugin': 'cmdline',
        'commands': commands,
        'total_count': len(commands),
        'suspicious_commands': suspicious_commands,
        'ransomware_indicators': ransomware_indicators
    }


def parse_handles(output: str) -> Dict[str, Any]:
    """Parse handles output"""
    handles = []
    mutexes = []

    lines = output.split('\n')
    header_skipped = False

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Skip header/separator lines
        if not header_skipped:
            if re.match(r'^(PID|Offset|---)', stripped) or 'Volatility' in stripped:
                continue
            # First data line seen - headers are done
            if re.match(r'^\d', stripped):
                header_skipped = True

        if 'mutex' in line.lower():
            mutexes.append({'details': stripped})

        if header_skipped and stripped:
            handles.append({'details': stripped})

    return {
        'plugin': 'handles',
        'handles': handles,
        'total_count': len(handles),
        'mutexes': mutexes
    }


def parse_generic(output: str) -> Dict[str, Any]:
    """Generic parser for unknown plugins"""
    lines = output.split('\n')
    entries = [{'details': line.strip()} for line in lines if line.strip()]

    return {
        'plugin': 'generic',
        'processes': entries,  # Use 'processes' key for compatibility
        'total_count': len(entries)
    }


def generate_next_steps(parsed_data: Dict[str, Any], output: str) -> str:
    """
    Generate intelligent forensic next steps based on THREAT DETECTION
    Uses pattern-based threat analysis similar to Nmap vulnerability detection
    """
    plugin_type = parsed_data.get('plugin', 'unknown')

    # CRITICAL: Detect threats using pattern matching
    threats, total_threat_score = detect_threats(output)

    # Detect OS type from output
    is_linux = 'linux.' in output.lower() or 'elf64layer' in output.lower() or '.elf' in output.lower()
    is_windows = 'windows.' in output.lower() or not is_linux
    is_mac = 'mac.' in output.lower()

    # Check for empty banners output
    is_banners = 'banners.banners' in output.lower()
    banners_empty = is_banners and 'Offset    Banner' in output and output.count('\n') < 10

    next_steps = []
    next_steps.append("=" * 80)
    next_steps.append("VOLATILITY THREAT ANALYSIS")
    next_steps.append("=" * 80)
    next_steps.append("")

    # Special handling for empty banners
    if banners_empty:
        next_steps.append("[INFO] BANNERS SCAN COMPLETED - NO RESULTS FOUND")
        next_steps.append("=" * 80)
        next_steps.append("")
        next_steps.append("The banners plugin scanned the memory but found no kernel version strings.")
        next_steps.append("This is common with some memory dumps.")
        next_steps.append("")
        next_steps.append("RECOMMENDED NEXT STEPS:")
        next_steps.append("")
        next_steps.append("1. TRY BASH HISTORY (most useful for forensics):")
        next_steps.append("   python vol.py -f <dump> linux.bash.Bash")
        next_steps.append("   >> Shows commands executed by the user!")
        next_steps.append("")
        next_steps.append("2. TRY PROCESS LIST (slow but works without symbols):")
        next_steps.append("   python vol.py -f <dump> linux.psaux.PsAux")
        next_steps.append("   >> Scans memory for running processes")
        next_steps.append("")
        next_steps.append("3. MANUAL SYMBOL DOWNLOAD:")
        next_steps.append("   If you know the Linux version, download symbols from:")
        next_steps.append("   https://github.com/volatilityfoundation/volatility3")
        next_steps.append("")
        return "\n".join(next_steps)

    # Display threat score
    if total_threat_score > 0:
        threat_level = "CRITICAL" if total_threat_score >= 20 else "HIGH" if total_threat_score >= 10 else "MEDIUM"
        next_steps.append(f"THREAT SCORE: {total_threat_score} ({threat_level})")
        next_steps.append("")

    # Group threats by severity
    critical_threats = [t for t in threats if t['severity'] == 'CRITICAL']
    high_threats = [t for t in threats if t['severity'] == 'HIGH']
    medium_threats = [t for t in threats if t['severity'] == 'MEDIUM']

    # Display CRITICAL threats first
    if critical_threats:
        next_steps.append("[CRITICAL] CRITICAL THREATS DETECTED:")
        next_steps.append("=" * 80)

        # Group by category to avoid duplicates
        seen_categories = set()
        for threat in critical_threats:
            category = threat['category']
            if category not in seen_categories:
                seen_categories.add(category)
                next_steps.append(f"\n[{threat['severity']}] {category}")
                next_steps.append(f"Description: {threat['description']}")
                next_steps.append(f"Score: {threat['score']}/10")

                # Show evidence for this category
                next_steps.append("Evidence:")
                category_threats = [t for t in critical_threats if t['category'] == category]
                for t in category_threats[:3]:  # Limit to 3 pieces of evidence per category
                    if t.get('process'):
                        next_steps.append(f"   PID {t['pid']}: {t['process']}")
                    next_steps.append(f"   {t['evidence']}")
                next_steps.append("")

        next_steps.append("")

    # Display HIGH threats
    if high_threats:
        next_steps.append("[WARNING]  HIGH SEVERITY THREATS:")
        next_steps.append("=" * 80)

        seen_categories = set()
        for threat in high_threats:
            category = threat['category']
            if category not in seen_categories:
                seen_categories.add(category)
                next_steps.append(f"\n[{threat['severity']}] {category}")
                next_steps.append(f"Description: {threat['description']}")
                next_steps.append(f"Score: {threat['score']}/10")

                # Show evidence
                category_threats = [t for t in high_threats if t['category'] == category]
                for t in category_threats[:2]:
                    if t.get('process'):
                        next_steps.append(f"   PID {t['pid']}: {t['process']}")
                    next_steps.append(f"   {t['evidence']}")
                next_steps.append("")

        next_steps.append("")

    # Plugin-specific analysis
    next_steps.append("=" * 80)
    next_steps.append("FORENSIC ANALYSIS BY DATA TYPE")
    next_steps.append("=" * 80)
    next_steps.append("")

    if plugin_type == 'pslist':
        processes = parsed_data.get('processes', [])
        suspicious = parsed_data.get('suspicious', {})

        next_steps.append(f"Total Processes Found: {len(processes)}")
        next_steps.append("")

        # Check for double extension processes
        if suspicious.get('double_extension'):
            next_steps.append("[CRITICAL] MALWARE: Double-extension processes detected:")
            for proc in suspicious['double_extension']:
                next_steps.append(f"   PID {proc['pid']}: {proc['name']}")
            next_steps.append("")
            next_steps.append("   IMMEDIATE ACTION REQUIRED:")
            next_steps.append("   vol3 -f <dump> windows.malfind --pid <PID>")
            next_steps.append("   vol3 -f <dump> windows.netscan  # Check for C2 connections")
            next_steps.append("   vol3 -f <dump> windows.dlllist --pid <PID>")
            next_steps.append("   vol3 -f <dump> windows.memmap --pid <PID> --dump")
            next_steps.append("")

        if suspicious.get('malicious_names'):
            next_steps.append("[CRITICAL] CRITICAL: Known malware tools detected:")
            for proc in suspicious['malicious_names']:
                next_steps.append(f"   PID {proc['pid']}: {proc['name']}")
            next_steps.append("")

        if suspicious.get('no_parent'):
            next_steps.append("[WARNING]  WARNING: Processes with no parent (possible rootkit):")
            for proc in suspicious['no_parent']:
                next_steps.append(f"   PID {proc['pid']}: {proc['name']}")
            next_steps.append("")

    elif plugin_type == 'netscan':
        connections = parsed_data.get('connections', [])
        c2_indicators = parsed_data.get('c2_indicators', [])

        next_steps.append(f"Total Network Connections: {len(connections)}")
        next_steps.append("")

        if c2_indicators:
            next_steps.append("[CRITICAL] C2 ACTIVITY DETECTED:")
            for indicator in c2_indicators:
                next_steps.append(f"   Reason: {indicator['reason']}")
                next_steps.append(f"   Process: {indicator['process']}")
                next_steps.append(f"   Remote: {indicator['remote']}")
                next_steps.append(f"   Evidence: {indicator['details']}")
                next_steps.append("")

            next_steps.append("   IMMEDIATE ACTION:")
            next_steps.append("   1. Isolate the infected system from the network")
            next_steps.append("   2. Block the remote IP addresses at the firewall")
            next_steps.append("   3. Dump the malicious process: vol3 -f <dump> windows.memmap --pid <PID> --dump")
            next_steps.append("   4. Submit dumped executable to VirusTotal for analysis")
            next_steps.append("")

    elif plugin_type == 'malfind':
        rwx_processes = parsed_data.get('rwx_processes', [])

        if rwx_processes:
            next_steps.append("[CRITICAL] CODE INJECTION DETECTED:")
            for proc in rwx_processes:
                next_steps.append(f"   PID {proc['pid']}: {proc['process']}")
                next_steps.append(f"   {proc['details']}")
            next_steps.append("")

            next_steps.append("   RECOMMENDED ACTIONS:")
            next_steps.append("   vol3 -f <dump> windows.memmap --pid <PID> --dump")
            next_steps.append("   vol3 -f <dump> windows.pstree  # Check parent process")
            next_steps.append("   strings <dumped_memory> | grep -E '(http|C:\\\\|cmd|powershell)'")
            next_steps.append("   yara malware_rules.yar <dumped_memory>")
            next_steps.append("")

    elif plugin_type == 'cmdline':
        ransomware_indicators = parsed_data.get('ransomware_indicators', [])

        if ransomware_indicators:
            next_steps.append("[CRITICAL] RANSOMWARE COMMANDS DETECTED:")
            for indicator in ransomware_indicators:
                next_steps.append(f"   {indicator['command']}")
            next_steps.append("")

            next_steps.append("   IMMEDIATE INCIDENT RESPONSE:")
            next_steps.append("   1. DO NOT POWER OFF THE SYSTEM (preserve memory)")
            next_steps.append("   2. Isolate the system from the network immediately")
            next_steps.append("   3. Take a full memory dump and disk image")
            next_steps.append("   4. Check for encrypted files on disk")
            next_steps.append("   5. Identify the ransomware variant:")
            next_steps.append("      vol3 -f <dump> windows.filescan | grep -i ransom")
            next_steps.append("      vol3 -f <dump> windows.pslist  # Identify ransomware process")
            next_steps.append("")

    # INTELLIGENT RECOMMENDATIONS based on detected threats
    next_steps.append("=" * 80)
    next_steps.append("INTELLIGENT NEXT STEPS (THREAT-BASED)")
    next_steps.append("=" * 80)
    next_steps.append("")

    if any('RANSOMWARE' in t['category'] for t in threats):
        next_steps.append("[CRITICAL] RANSOMWARE INCIDENT DETECTED:")
        next_steps.append("   Priority Actions:")
        next_steps.append("   1. Isolate system from network NOW")
        next_steps.append("   2. Acquire full memory and disk forensics")
        next_steps.append("   3. Identify ransomware variant:")
        next_steps.append("      vol3 -f <dump> windows.filescan | grep -iE '(ransom|crypt|lock)'")
        next_steps.append("      vol3 -f <dump> windows.dumpfiles --pid <suspicious_PID>")
        next_steps.append("   4. Check for shadow copies (recovery may be possible):")
        next_steps.append("      Look for vssadmin commands in timeline")
        next_steps.append("   5. Submit sample to ID Ransomware: id-ransomware.malwarehunterteam.com")
        next_steps.append("")

    if any('C2' in t['category'] for t in threats):
        next_steps.append("[CRITICAL] COMMAND & CONTROL DETECTED:")
        next_steps.append("   Priority Actions:")
        next_steps.append("   1. Block all detected C2 IP addresses at firewall")
        next_steps.append("   2. Dump suspicious processes:")
        next_steps.append("      vol3 -f <dump> windows.memmap --pid <PID> --dump")
        next_steps.append("   3. Extract network artifacts:")
        next_steps.append("      vol3 -f <dump> windows.netscan > network_connections.txt")
        next_steps.append("   4. Check for persistence:")
        next_steps.append("      vol3 -f <dump> windows.registry.userassist")
        next_steps.append("      vol3 -f <dump> windows.svcscan")
        next_steps.append("")

    if any('CODE_INJECTION' in t['category'] for t in threats):
        next_steps.append("[CRITICAL] CODE INJECTION DETECTED:")
        next_steps.append("   Priority Actions:")
        next_steps.append("   1. Dump injected memory regions:")
        next_steps.append("      vol3 -f <dump> windows.memmap --pid <PID> --dump")
        next_steps.append("   2. Scan with YARA rules:")
        next_steps.append("      vol3 -f <dump> windows.yarascan --yara-rules malware.yar")
        next_steps.append("   3. Check for process hollowing:")
        next_steps.append("      vol3 -f <dump> windows.ldrmodules --pid <PID>")
        next_steps.append("   4. Extract shellcode and analyze")
        next_steps.append("")

    if any('CREDENTIAL' in t['category'] for t in threats):
        next_steps.append("[CRITICAL] CREDENTIAL THEFT DETECTED:")
        next_steps.append("   Priority Actions:")
        next_steps.append("   1. Force password reset for ALL users")
        next_steps.append("   2. Check for lateral movement:")
        next_steps.append("      vol3 -f <dump> windows.netscan")
        next_steps.append("      Look for connections to other systems")
        next_steps.append("   3. Extract and analyze credentials:")
        next_steps.append("      vol3 -f <dump> windows.hashdump")
        next_steps.append("      vol3 -f <dump> windows.lsadump")
        next_steps.append("   4. Review Active Directory logs for suspicious logons")
        next_steps.append("")

    # Standard forensic workflow - OS-specific
    next_steps.append("=" * 80)
    next_steps.append("STANDARD FORENSIC WORKFLOW")
    next_steps.append("=" * 80)

    if is_linux:
        next_steps.append("Linux Memory Forensics Commands:")
        next_steps.append("   1. Process list: python vol.py -f <dump> linux.psaux.PsAux")
        next_steps.append("   2. Bash history: python vol.py -f <dump> linux.bash.Bash")
        next_steps.append("   3. Open files: python vol.py -f <dump> linux.lsof.Lsof (needs symbols)")
        next_steps.append("   4. Network connections: python vol.py -f <dump> linux.netstat.Netstat (needs symbols)")
        next_steps.append("   5. Find kernel version: python vol.py -f <dump> banners.Banners")
        next_steps.append("")
        next_steps.append("NOTE: Many Linux plugins require kernel symbols!")
        next_steps.append("Download from: https://github.com/volatilityfoundation/volatility3")
    elif is_mac:
        next_steps.append("Mac Memory Forensics Commands:")
        next_steps.append("   1. Process list: python vol.py -f <dump> mac.pslist.PsList")
        next_steps.append("   2. Bash history: python vol.py -f <dump> mac.bash.Bash")
        next_steps.append("   3. Open files: python vol.py -f <dump> mac.lsof.Lsof")
        next_steps.append("   4. Network connections: python vol.py -f <dump> mac.netstat.Netstat")
    else:  # Windows
        next_steps.append("Windows Memory Forensics Commands:")
        next_steps.append("   1. Timeline analysis: python vol.py -f <dump> timeliner.Timeliner")
        next_steps.append("   2. Registry analysis: python vol.py -f <dump> windows.registry.hivelist")
        next_steps.append("   3. Service enumeration: python vol.py -f <dump> windows.svcscan")
        next_steps.append("   4. Driver analysis: python vol.py -f <dump> windows.driverscan")
        next_steps.append("   5. Mutex analysis: python vol.py -f <dump> windows.handles")

    next_steps.append("")

    return "\n".join(next_steps)


def analyze_volatility_output(output: str) -> Dict[str, Any]:
    """Legacy function for compatibility"""
    return parse_volatility_output(output)


# ===== EXPLOIT DATABASE INTEGRATION =====

def extract_software_versions(parsed_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Extract software products and versions from Volatility output
    Returns list of {'vendor', 'product', 'version', 'extra_info'}

    Supports:
    - Process executable paths (chrome.exe, firefox.exe, etc.)
    - DLL versions
    - Service versions
    """
    software_list = []
    seen = set()  # Deduplication

    # Extract from processes
    processes = parsed_data.get('processes', [])
    for proc in processes:
        # Get process name from ImageFileName or Process column
        proc_name = proc.get('name') or proc.get('ImageFileName') or proc.get('Process') or proc.get('Name') or ''
        proc_name = proc_name.strip().lower()

        # Get full path if available
        proc_path = proc.get('path') or proc.get('Path') or proc.get('exe_path') or ''

        # Common software version patterns
        version_patterns = {
            # Web browsers
            r'chrome\.exe': {'vendor': 'google', 'product': 'chrome'},
            r'firefox\.exe': {'vendor': 'mozilla', 'product': 'firefox'},
            r'msedge\.exe': {'vendor': 'microsoft', 'product': 'edge'},
            r'safari\.app': {'vendor': 'apple', 'product': 'safari'},

            # Office suites
            r'winword\.exe': {'vendor': 'microsoft', 'product': 'word'},
            r'excel\.exe': {'vendor': 'microsoft', 'product': 'excel'},
            r'powerpnt\.exe': {'vendor': 'microsoft', 'product': 'powerpoint'},

            # PDF viewers
            r'acrord32\.exe': {'vendor': 'adobe', 'product': 'acrobat_reader'},
            r'acrobat\.exe': {'vendor': 'adobe', 'product': 'acrobat'},

            # Media players
            r'vlc\.exe': {'vendor': 'videolan', 'product': 'vlc'},
            r'wmplayer\.exe': {'vendor': 'microsoft', 'product': 'windows_media_player'},

            # Java
            r'java\.exe': {'vendor': 'oracle', 'product': 'jre'},
            r'javaw\.exe': {'vendor': 'oracle', 'product': 'jre'},

            # Web servers (Linux/Mac)
            r'apache2': {'vendor': 'apache', 'product': 'http_server'},
            r'nginx': {'vendor': 'nginx', 'product': 'nginx'},
            r'httpd': {'vendor': 'apache', 'product': 'http_server'},

            # SSH servers
            r'sshd': {'vendor': 'openbsd', 'product': 'openssh'},

            # Databases
            r'mysqld': {'vendor': 'oracle', 'product': 'mysql'},
            r'postgres': {'vendor': 'postgresql', 'product': 'postgresql'},
        }

        for pattern, software_info in version_patterns.items():
            if re.search(pattern, proc_name) or re.search(pattern, proc_path.lower()):
                # Extract version from path or command line if available
                cmdline = proc.get('CommandLine') or proc.get('CmdLine') or ''
                combined_text = f"{proc_path} {cmdline}"

                # Common version regex patterns
                # Matches: 1.2.3, 10.0.19041, 2024.01.15
                version_match = re.search(r'[/\\](\d+\.[\d\.]+)', combined_text)
                version = version_match.group(1) if version_match else ''

                # Create unique key
                key = f"{software_info['vendor']}:{software_info['product']}:{version}"
                if key not in seen:
                    seen.add(key)
                    software_list.append({
                        'vendor': software_info['vendor'],
                        'product': software_info['product'],
                        'version': version,
                        'extra_info': '',
                        'process': proc_name
                    })
                break

    # Extract from DLLs (if parsed_data contains DLL info)
    dlls = parsed_data.get('dlls', [])
    for dll in dlls:
        dll_name = dll.get('name', '').lower()
        dll_path = dll.get('path', '').lower()

        # Windows DLLs that are often vulnerable
        if 'msvcr' in dll_name or 'msvcp' in dll_name:  # Microsoft Visual C++ Runtime
            version_match = re.search(r'msvcr?(\d+)', dll_name)
            if version_match:
                ver_num = version_match.group(1)
                key = f"microsoft:visual_c++_redistributable:{ver_num}"
                if key not in seen:
                    seen.add(key)
                    software_list.append({
                        'vendor': 'microsoft',
                        'product': 'visual_c++_redistributable',
                        'version': ver_num,
                        'extra_info': '',
                        'process': 'DLL'
                    })

    return software_list


def correlate_exploits(parsed_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Correlate Volatility findings with exploit database
    Returns dict with CVEs and exploits for detected software
    """
    try:
        from rag_engine.cve_query_engine import CVEQueryEngine
    except ImportError:
        return {
            'error': 'CVE Query Engine not available',
            'vulnerable_software': [],
            'total_cves': 0
        }

    # Extract software versions
    software_list = extract_software_versions(parsed_data)

    if not software_list:
        return {
            'vulnerable_software': [],
            'total_cves': 0,
            'message': 'No software versions detected in output'
        }

    # Query CVE database
    try:
        engine = CVEQueryEngine()
    except FileNotFoundError as e:
        return {
            'error': f'CVE database not found: {e}',
            'vulnerable_software': [],
            'total_cves': 0
        }

    vulnerable_software = []
    total_cves = 0

    for software in software_list:
        if not software['version']:
            continue  # Skip if no version detected

        # Query CVEs
        cves = engine.query_cves_for_service(
            vendor=software['vendor'],
            product=software['product'],
            version=software['version'],
            version_extra_info=software['extra_info']
        )

        if cves:
            # Get exploits for top CVE
            top_cve = cves[0]
            exploits = engine.get_exploits_for_cve(top_cve.cve_id)

            vulnerable_software.append({
                'vendor': software['vendor'],
                'product': software['product'],
                'version': software['version'],
                'process': software['process'],
                'cves': [
                    {
                        'cve_id': cve.cve_id,
                        'cvss_score': cve.cvss_score,
                        'severity': cve.severity,
                        'confidence': cve.confidence,
                        'has_exploit': cve.has_exploit,
                        'exploit_count': cve.exploit_count,
                        'description': cve.description
                    }
                    for cve in cves
                ],
                'exploits': [
                    {
                        'edb_id': exploit['edb_id'],
                        'title': exploit['title'],
                        'type': exploit['type'],
                        'verified': exploit['verified'],
                        'url': exploit['url']
                    }
                    for exploit in exploits[:3]  # Top 3 exploits
                ],
                'exploit_summary': f"{len(exploits)} exploit(s) available" if exploits else "No public exploits"
            })
            total_cves += len(cves)

    return {
        'vulnerable_software': vulnerable_software,
        'total_cves': total_cves,
        'total_vulnerable': len(vulnerable_software)
    }


def format_exploit_results(exploit_data: Dict[str, Any]) -> str:
    """
    Format exploit correlation results for display
    """
    if 'error' in exploit_data:
        return f"\n[EXPLOIT DB] {exploit_data['error']}\n"

    if exploit_data['total_vulnerable'] == 0:
        return "\n[EXPLOIT DB] No vulnerable software detected with known CVEs\n"

    output = []
    output.append("")
    output.append("=" * 80)
    output.append("EXPLOIT DATABASE CORRELATION")
    output.append("=" * 80)
    output.append(f"Found {exploit_data['total_vulnerable']} vulnerable software with {exploit_data['total_cves']} CVEs")
    output.append("")

    for software in exploit_data['vulnerable_software']:
        output.append(f"[{software['product'].upper()}] v{software['version']} (Process: {software['process']})")
        output.append(f"  Vendor: {software['vendor']}")
        output.append(f"  CVEs: {len(software['cves'])}")
        output.append("")

        # Show top CVEs
        for cve in software['cves'][:3]:  # Top 3 CVEs
            output.append(f"  [{cve['cve_id']}] CVSS {cve['cvss_score']} ({cve['severity']})")
            output.append(f"    {cve['description']}")
            if cve['has_exploit']:
                output.append(f"    [!] {cve['exploit_count']} PUBLIC EXPLOIT(S) AVAILABLE")
            output.append(f"    Confidence: {cve['confidence']}%")
            output.append("")

        # Show exploits
        if software['exploits']:
            output.append("  Available Exploits:")
            for exploit in software['exploits']:
                verified_str = "[VERIFIED]" if exploit['verified'] else ""
                output.append(f"    - EDB-{exploit['edb_id']}: {exploit['title'][:60]} {verified_str}")
                output.append(f"      URL: {exploit['url']}")
            output.append("")

        output.append("-" * 80)
        output.append("")

    return "\n".join(output)
