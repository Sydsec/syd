#!/usr/bin/env python3
"""
YARA Output Parser with Intelligent Threat Detection
Parses YARA scan output (JSON and raw formats) and provides threat intelligence

Author: Ask Syd Team
Version: 1.0
Date: 2024-01-15
"""

import re
import json
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime


# =============================================================================
# COMPREHENSIVE THREAT PATTERN DATABASE - 200+ Patterns
# =============================================================================

# Helper: Creates a regex pattern that matches a word only as a complete segment
# in underscore/hyphen/dot/space-separated names (e.g., rule names like "RANSOM_Conti_Loader").
# Prevents "conti" from matching inside "continuous" or "context".
def _seg(word):
    """Match word as a complete segment, not a substring of another word."""
    return rf'(?:^|[_.\-\s]){word}(?:$|[_.\-\s])'


# Security-context prefixes used in standard YARA rule naming conventions
_SEC_PFX = r'(?:MALWARE|HKTL|HACK|TOOL|C2|RANSOM|APT|TROJAN|RAT|EXPL|EXPLOIT|WEBSHELL|SUSP|INDICATOR|PUA|ROOTKIT|BACKDOOR|STEALER|LOADER|MINER|BANKER|INJECT)'


def _ctx(word, suffixes):
    """Match word only with a security-context prefix OR a security-related suffix.

    For common English words (empire, maze, lazarus, etc.) that also happen to be
    malware/tool names. Requires either:
    - A security prefix in the rule name/meta (MALWARE_, HKTL_, APT_, etc.)
    - OR a security-related suffix after the word (e.g., empire_agent, maze_ransom)
    """
    suffix_pattern = '|'.join(suffixes)
    return rf'(?:{_SEC_PFX}[\W_].*{word}|{word}[\W_].*(?:{suffix_pattern}))'


YARA_THREAT_PATTERNS = {
    # =========================================================================
    # RANSOMWARE FAMILIES
    # =========================================================================
    'RANSOMWARE_WANNACRY': {
        'patterns': [r'wannacry', r'wcry', r'wncry', r'wana.*crypt', r'wanacrypt0r'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Ransomware - WannaCry',
        'description': 'WannaCry ransomware variant detected',
        'mitre_technique': 'T1486'
    },
    'RANSOMWARE_RYUK': {
        'patterns': [r'ryuk', r'RyukReadMe', r'UNIQUE_ID_DO_NOT_REMOVE'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Ransomware - Ryuk',
        'description': 'Ryuk ransomware variant detected',
        'mitre_technique': 'T1486'
    },
    'RANSOMWARE_LOCKBIT': {
        'patterns': [r'lockbit', r'Restore-My-Files\.txt'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Ransomware - LockBit',
        'description': 'LockBit ransomware variant detected',
        'mitre_technique': 'T1486'
    },
    'RANSOMWARE_REVIL': {
        'patterns': [r'revil', r'sodinokibi', r'REvil'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Ransomware - REvil/Sodinokibi',
        'description': 'REvil/Sodinokibi ransomware detected',
        'mitre_technique': 'T1486'
    },
    'RANSOMWARE_CONTI': {
        # FIXED: "conti" now requires segment boundaries to avoid matching "continuous", "context", etc.
        'patterns': [_seg('conti'), r'CONTI_README'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Ransomware - Conti',
        'description': 'Conti ransomware variant detected',
        'mitre_technique': 'T1486'
    },
    'RANSOMWARE_BLACKCAT': {
        # FIXED: "blackcat" as segment to avoid matching "blackcatfish", etc.
        'patterns': [_seg('blackcat'), r'alphv', r'ALPHV'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Ransomware - BlackCat/ALPHV',
        'description': 'BlackCat/ALPHV ransomware detected',
        'mitre_technique': 'T1486'
    },
    'RANSOMWARE_MAZE': {
        # FIXED: "maze" requires security prefix OR ransom-related suffix
        'patterns': [
            _ctx('maze', ['ransom', 'encrypt', 'lock', 'readme', 'decrypt', 'crypt']),
            r'MAZE_README',
        ],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Ransomware - Maze',
        'description': 'Maze ransomware variant detected',
        'mitre_technique': 'T1486'
    },
    'RANSOMWARE_DHARMA': {
        # FIXED: "dharma" requires security prefix OR ransom-related suffix
        'patterns': [
            _ctx('dharma', ['ransom', 'encrypt', 'crysis', 'crypt']),
            _ctx('crysis', ['ransom', 'encrypt', 'dharma', 'crypt']),
        ],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Ransomware - Dharma/Crysis',
        'description': 'Dharma/Crysis ransomware detected',
        'mitre_technique': 'T1486'
    },
    'RANSOMWARE_GENERIC': {
        'patterns': [_seg('ransom'), r'your files.*encrypted', r'bitcoin.*decrypt', r'pay.*restore'],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'Ransomware - Generic',
        'description': 'Generic ransomware indicators detected',
        'mitre_technique': 'T1486'
    },

    # =========================================================================
    # C2 FRAMEWORKS
    # =========================================================================
    'C2_COBALT_STRIKE': {
        'patterns': [r'cobaltstrike', r'cobalt.strike', r'cobalt_strike',
                     r'ReflectiveLoader', r'%s as %s\\%s: %d'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'C2 - Cobalt Strike',
        'description': 'Cobalt Strike beacon detected',
        'mitre_technique': 'T1071.001'
    },
    'C2_METASPLOIT': {
        'patterns': [r'metasploit', r'meterpreter', r'metsrv', r'reverse_tcp', r'reverse_https'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'C2 - Metasploit',
        'description': 'Metasploit Meterpreter detected',
        'mitre_technique': 'T1071'
    },
    'C2_EMPIRE': {
        # FIXED: "empire" requires security prefix OR security suffix
        'patterns': [
            _ctx('empire', ['agent', 'stager', 'c2', 'beacon', 'implant', 'listener', 'powershell']),
            r'Invoke[\W_]Empire', r'powershell[\W_]empire',
            _seg('starkiller'),
        ],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'C2 - Empire/Starkiller',
        'description': 'PowerShell Empire C2 agent detected',
        'mitre_technique': 'T1059.001'
    },
    'C2_SLIVER': {
        # FIXED: "sliver" requires security prefix OR security suffix
        'patterns': [
            _ctx('sliver', ['c2', 'implant', 'beacon', 'agent', 'stager']),
            r'sliverC2', r'sliver.?implant',
        ],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'C2 - Sliver',
        'description': 'Sliver C2 framework detected',
        'mitre_technique': 'T1071'
    },
    'C2_POSHC2': {
        'patterns': [r'poshc2', r'PoshC2', r'SharpSocks', r'Invoke-PowerShellTcp'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'C2 - PoshC2',
        'description': 'PoshC2 framework detected',
        'mitre_technique': 'T1059.001'
    },
    'C2_COVENANT': {
        # FIXED: "covenant" requires security prefix OR security suffix
        'patterns': [
            _ctx('covenant', ['c2', 'agent', 'beacon', 'implant', 'stager']),
            r'GruntHTTP', r'GruntSMB',
            r'covenant.?c2', r'covenant.?agent',
        ],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'C2 - Covenant',
        'description': 'Covenant C2 framework detected',
        'mitre_technique': 'T1071'
    },
    'C2_MYTHIC': {
        # FIXED: "mythic" requires security prefix OR security suffix
        'patterns': [
            _ctx('mythic', ['c2', 'agent', 'beacon', 'implant', 'framework']),
            r'mythic.?c2', r'mythic.?agent',
            r'apollo.?agent', r'medusa.?agent',
        ],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'C2 - Mythic',
        'description': 'Mythic C2 framework detected',
        'mitre_technique': 'T1071'
    },
    'C2_BRUTE_RATEL': {
        # FIXED: removed bare "badger" (common English word), kept specific patterns
        'patterns': [r'brute.?ratel', r'BRc4', r'bruteratel',
                     r'badger.?payload', r'badger.?c[24]'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'C2 - Brute Ratel',
        'description': 'Brute Ratel C4 detected',
        'mitre_technique': 'T1071'
    },

    # =========================================================================
    # TROJANS AND RATS
    # =========================================================================
    'TROJAN_EMOTET': {
        'patterns': [r'emotet', r'geodo', r'heodo', r'<mcconf>', r'<servs>'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Trojan - Emotet',
        'description': 'Emotet banking trojan detected',
        'mitre_technique': 'T1055'
    },
    'TROJAN_TRICKBOT': {
        'patterns': [r'trickbot', r'trickloader', r'pwgrab', r'systeminfo32', r'injectDll'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Trojan - TrickBot',
        'description': 'TrickBot trojan detected',
        'mitre_technique': 'T1055'
    },
    'TROJAN_QAKBOT': {
        'patterns': [r'qakbot', r'qbot', r'quakbot', r'pinkslipbot'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Trojan - QakBot',
        'description': 'QakBot/QBot trojan detected',
        'mitre_technique': 'T1055'
    },
    'TROJAN_ICEDID': {
        'patterns': [r'icedid', r'bokbot', r'ice.?id'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Trojan - IcedID',
        'description': 'IcedID/BokBot trojan detected',
        'mitre_technique': 'T1055'
    },
    'RAT_NANOCORE': {
        'patterns': [r'nanocore', r'nano.core', r'NanoCore'],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'RAT - NanoCore',
        'description': 'NanoCore RAT detected',
        'mitre_technique': 'T1219'
    },
    'RAT_NJRAT': {
        'patterns': [r'njrat', r'bladabindi', r'njw0rm'],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'RAT - njRAT',
        'description': 'njRAT/Bladabindi detected',
        'mitre_technique': 'T1219'
    },
    'RAT_QUASAR': {
        # FIXED: "quasar" requires security prefix or RAT-related suffix
        'patterns': [
            _ctx('quasar', ['rat', 'remote', 'trojan', 'malware', 'backdoor']),
            r'quasarrat', r'xClient',
        ],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'RAT - QuasarRAT',
        'description': 'QuasarRAT detected',
        'mitre_technique': 'T1219'
    },
    'RAT_DARKCOMET': {
        'patterns': [r'darkcomet', r'dark.comet', r'dc_mutex'],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'RAT - DarkComet',
        'description': 'DarkComet RAT detected',
        'mitre_technique': 'T1219'
    },
    'RAT_REMCOS': {
        'patterns': [r'remcos', r'remcosrat'],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'RAT - Remcos',
        'description': 'Remcos RAT detected',
        'mitre_technique': 'T1219'
    },
    'RAT_ASYNCRAT': {
        'patterns': [r'asyncrat', r'async.?rat', r'AsyncClient'],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'RAT - AsyncRAT',
        'description': 'AsyncRAT detected',
        'mitre_technique': 'T1219'
    },

    # =========================================================================
    # APT GROUPS
    # =========================================================================
    'APT_APT28': {
        'patterns': [r'apt28', r'fancy.?bear', r'sofacy', r'sednit', r'pawn.?storm'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'APT - APT28/Fancy Bear',
        'description': 'APT28/Fancy Bear indicators detected',
        'mitre_technique': 'G0007'
    },
    'APT_APT29': {
        # FIXED: "dukes" requires security prefix or compound pattern
        'patterns': [r'apt29', r'cozy.?bear', r'nobelium', r'yttrium',
                     _ctx('dukes', ['apt', 'backdoor', 'malware', 'group']),
                     r'the.?dukes'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'APT - APT29/Cozy Bear',
        'description': 'APT29/Cozy Bear indicators detected',
        'mitre_technique': 'G0016'
    },
    'APT_LAZARUS': {
        # FIXED: "lazarus" and "zinc" require security prefix or security suffix
        'patterns': [
            _ctx('lazarus', ['group', 'apt', 'loader', 'backdoor', 'dtrack', 'malware']),
            r'hidden.?cobra', r'apt38',
            _ctx('zinc', ['apt', 'malware', 'backdoor', 'group']),
            r'lazarus.?group',
        ],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'APT - Lazarus Group',
        'description': 'Lazarus Group indicators detected',
        'mitre_technique': 'G0032'
    },
    'APT_APT41': {
        'patterns': [r'apt41', r'winnti', r'barium', r'wicked.?panda'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'APT - APT41/Winnti',
        'description': 'APT41/Winnti indicators detected',
        'mitre_technique': 'G0096'
    },
    'APT_TURLA': {
        # FIXED: removed bare "snake" (extremely common word)
        # kept specific compound patterns that are unambiguous
        'patterns': [r'turla', r'venomous.?bear', r'uroburos',
                     r'turla.?snake', r'snake.?rootkit', r'snake.?backdoor'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'APT - Turla',
        'description': 'Turla Group indicators detected',
        'mitre_technique': 'G0010'
    },
    'APT_HAFNIUM': {
        # FIXED: "hafnium" requires security prefix or security suffix
        'patterns': [
            _ctx('hafnium', ['apt', 'exploit', 'exchange', 'malware', 'backdoor']),
            r'silk.?typhoon',
        ],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'APT - HAFNIUM',
        'description': 'HAFNIUM indicators detected',
        'mitre_technique': 'G0125'
    },

    # =========================================================================
    # WEBSHELLS
    # =========================================================================
    'WEBSHELL_GENERIC': {
        'patterns': [r'webshell', r'web.?shell'],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'Webshell - Generic',
        'description': 'Generic webshell detected',
        'mitre_technique': 'T1505.003'
    },
    'WEBSHELL_C99': {
        'patterns': [r'c99shell', r'c99_buff_prepare'],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'Webshell - C99',
        'description': 'C99 webshell detected',
        'mitre_technique': 'T1505.003'
    },
    'WEBSHELL_R57': {
        'patterns': [r'r57shell'],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'Webshell - R57',
        'description': 'R57 webshell detected',
        'mitre_technique': 'T1505.003'
    },
    'WEBSHELL_CHINA_CHOPPER': {
        # FIXED: "chopper" requires security prefix or compound pattern
        'patterns': [r'china.?chopper', r'eval.*\$_POST', r'eval.*\$_GET',
                     _ctx('chopper', ['webshell', 'shell', 'backdoor', 'php', 'asp', 'jsp'])],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'Webshell - China Chopper',
        'description': 'China Chopper webshell detected',
        'mitre_technique': 'T1505.003'
    },
    'WEBSHELL_WSO': {
        'patterns': [r'wso_version', r'wso.?shell'],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'Webshell - WSO',
        'description': 'WSO webshell detected',
        'mitre_technique': 'T1505.003'
    },
    'WEBSHELL_B374K': {
        'patterns': [r'b374k'],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'Webshell - b374k',
        'description': 'b374k webshell detected',
        'mitre_technique': 'T1505.003'
    },

    # =========================================================================
    # PACKERS
    # =========================================================================
    'PACKER_UPX': {
        'patterns': [r'UPX0', r'UPX1', r'UPX!', r'upx.*packed'],
        'score': 4, 'severity': 'MEDIUM',
        'category': 'Packer - UPX',
        'description': 'UPX packer detected',
        'mitre_technique': 'T1027.002'
    },
    'PACKER_THEMIDA': {
        'patterns': [r'themida', r'winlicense'],
        'score': 6, 'severity': 'HIGH',
        'category': 'Packer - Themida',
        'description': 'Themida/WinLicense packer detected',
        'mitre_technique': 'T1027.002'
    },
    'PACKER_VMPROTECT': {
        'patterns': [r'vmprotect'],
        'score': 6, 'severity': 'HIGH',
        'category': 'Packer - VMProtect',
        'description': 'VMProtect packer detected',
        'mitre_technique': 'T1027.002'
    },
    'PACKER_ASPACK': {
        'patterns': [r'aspack'],
        'score': 4, 'severity': 'MEDIUM',
        'category': 'Packer - ASPack',
        'description': 'ASPack packer detected',
        'mitre_technique': 'T1027.002'
    },
    'PACKER_ENIGMA': {
        # FIXED: "enigma" requires security prefix or packer-related suffix
        'patterns': [
            _ctx('enigma', ['pack', 'protect', 'packer', 'packed']),
            r'enigma.?protector',
        ],
        'score': 5, 'severity': 'MEDIUM',
        'category': 'Packer - Enigma',
        'description': 'Enigma Protector detected',
        'mitre_technique': 'T1027.002'
    },
    'PACKER_PETITE': {
        # FIXED: "petite" requires security prefix or packer-related suffix
        'patterns': [
            _ctx('petite', ['pack', 'packer', 'packed', 'compress']),
            r'petite.*packer',
        ],
        'score': 4, 'severity': 'MEDIUM',
        'category': 'Packer - PEtite',
        'description': 'PEtite packer detected',
        'mitre_technique': 'T1027.002'
    },
    'PACKER_MPRESS': {
        'patterns': [r'mpress'],
        'score': 4, 'severity': 'MEDIUM',
        'category': 'Packer - MPRESS',
        'description': 'MPRESS packer detected',
        'mitre_technique': 'T1027.002'
    },

    # =========================================================================
    # CREDENTIAL STEALERS
    # =========================================================================
    'STEALER_MIMIKATZ': {
        'patterns': [r'mimikatz', r'sekurlsa', r'logonpasswords', r'wdigest', r'kerberos::'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Credential Stealer - Mimikatz',
        'description': 'Mimikatz credential dumping tool detected',
        'mitre_technique': 'T1003.001'
    },
    'STEALER_LAZAGNE': {
        'patterns': [r'lazagne', r'LaZagne'],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'Credential Stealer - LaZagne',
        'description': 'LaZagne credential stealer detected',
        'mitre_technique': 'T1555'
    },
    'STEALER_REDLINE': {
        # FIXED: "redline" requires security prefix or stealer-related suffix
        'patterns': [
            r'redline.?stealer', r'RedLine.?Stealer',
            _ctx('redline', ['stealer', 'malware', 'trojan', 'infostealer']),
        ],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'Credential Stealer - RedLine',
        'description': 'RedLine Stealer detected',
        'mitre_technique': 'T1555'
    },
    'STEALER_RACCOON': {
        # FIXED: "raccoon" requires security prefix or stealer-related suffix
        'patterns': [
            r'raccoon.?stealer',
            _ctx('raccoon', ['stealer', 'malware', 'trojan', 'infostealer']),
        ],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'Credential Stealer - Raccoon',
        'description': 'Raccoon Stealer detected',
        'mitre_technique': 'T1555'
    },
    'STEALER_VIDAR': {
        # FIXED: "vidar" requires security prefix or stealer-related suffix
        'patterns': [
            r'vidar.?stealer',
            _ctx('vidar', ['stealer', 'malware', 'trojan', 'infostealer']),
        ],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'Credential Stealer - Vidar',
        'description': 'Vidar Stealer detected',
        'mitre_technique': 'T1555'
    },
    'STEALER_FORMBOOK': {
        'patterns': [r'formbook', r'xloader', r'FormBook'],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'Credential Stealer - FormBook',
        'description': 'FormBook/XLoader stealer detected',
        'mitre_technique': 'T1555'
    },
    'STEALER_AGENT_TESLA': {
        'patterns': [r'agent.?tesla', r'agenttesla'],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'Credential Stealer - Agent Tesla',
        'description': 'Agent Tesla stealer detected',
        'mitre_technique': 'T1555'
    },

    # =========================================================================
    # PROCESS INJECTION
    # =========================================================================
    'INJECTION_PROCESS': {
        'patterns': [r'process.?injection', r'inject.*process', r'CreateRemoteThread',
                     r'VirtualAllocEx', r'WriteProcessMemory', r'NtCreateThreadEx'],
        'score': 8, 'severity': 'HIGH',
        'category': 'Technique - Process Injection',
        'description': 'Process injection technique detected',
        'mitre_technique': 'T1055'
    },
    'INJECTION_HOLLOWING': {
        'patterns': [r'process.?hollowing', r'NtUnmapViewOfSection',
                     _seg('hollowing')],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'Technique - Process Hollowing',
        'description': 'Process hollowing technique detected',
        'mitre_technique': 'T1055.012'
    },
    'INJECTION_DLL': {
        'patterns': [r'dll.?injection', r'inject.*dll', r'reflective.*loader'],
        'score': 8, 'severity': 'HIGH',
        'category': 'Technique - DLL Injection',
        'description': 'DLL injection technique detected',
        'mitre_technique': 'T1055.001'
    },
    'INJECTION_SHELLCODE': {
        'patterns': [r'shellcode', r'shell.?code', r'payload.*inject'],
        'score': 8, 'severity': 'HIGH',
        'category': 'Technique - Shellcode Injection',
        'description': 'Shellcode injection detected',
        'mitre_technique': 'T1055'
    },
    'INJECTION_APC': {
        'patterns': [r'apc.?injection', r'QueueUserAPC', r'NtQueueApcThread'],
        'score': 8, 'severity': 'HIGH',
        'category': 'Technique - APC Injection',
        'description': 'APC injection technique detected',
        'mitre_technique': 'T1055.004'
    },

    # =========================================================================
    # PERSISTENCE
    # =========================================================================
    'PERSISTENCE_REGISTRY': {
        'patterns': [r'registry.*run', r'CurrentVersion\\Run', r'RunOnce'],
        'score': 6, 'severity': 'MEDIUM',
        'category': 'Persistence - Registry',
        'description': 'Registry persistence mechanism detected',
        'mitre_technique': 'T1547.001'
    },
    'PERSISTENCE_SCHEDULED_TASK': {
        'patterns': [r'schtasks', r'scheduled.?task', r'at\.exe.*create'],
        'score': 6, 'severity': 'MEDIUM',
        'category': 'Persistence - Scheduled Task',
        'description': 'Scheduled task persistence detected',
        'mitre_technique': 'T1053.005'
    },
    'PERSISTENCE_SERVICE': {
        'patterns': [r'service.*create', r'sc.*create', r'CreateService'],
        'score': 6, 'severity': 'MEDIUM',
        'category': 'Persistence - Service',
        'description': 'Service-based persistence detected',
        'mitre_technique': 'T1543.003'
    },
    'PERSISTENCE_WMI': {
        'patterns': [r'wmi.*subscription', r'EventSubscription', r'ActiveScriptEventConsumer'],
        'score': 7, 'severity': 'HIGH',
        'category': 'Persistence - WMI',
        'description': 'WMI persistence mechanism detected',
        'mitre_technique': 'T1546.003'
    },

    # =========================================================================
    # LOADERS AND DROPPERS
    # =========================================================================
    'LOADER_BUMBLEBEE': {
        'patterns': [r'bumblebee', r'bumble.?bee'],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'Loader - BumbleBee',
        'description': 'BumbleBee loader detected',
        'mitre_technique': 'T1105'
    },
    'LOADER_BAZARLOADER': {
        'patterns': [r'bazarloader', r'bazar.?loader', r'bazarcall'],
        'score': 9, 'severity': 'CRITICAL',
        'category': 'Loader - BazarLoader',
        'description': 'BazarLoader detected',
        'mitre_technique': 'T1105'
    },
    'LOADER_ISOLOADER': {
        'patterns': [r'iso.?loader', r'iso.*malware'],
        'score': 7, 'severity': 'HIGH',
        'category': 'Loader - ISO Loader',
        'description': 'ISO-based loader technique detected',
        'mitre_technique': 'T1553.005'
    },

    # =========================================================================
    # CRYPTOCURRENCY MINERS
    # =========================================================================
    'MINER_GENERIC': {
        'patterns': [r'xmrig', r'cpuminer', r'minerd', r'stratum\+tcp', r'mining.*pool'],
        'score': 7, 'severity': 'HIGH',
        'category': 'Cryptominer - Generic',
        'description': 'Cryptocurrency miner detected',
        'mitre_technique': 'T1496'
    },
    'MINER_COINHIVE': {
        'patterns': [r'coinhive', r'cryptoloot', r'coin.?hive'],
        'score': 6, 'severity': 'MEDIUM',
        'category': 'Cryptominer - CoinHive',
        'description': 'CoinHive miner detected',
        'mitre_technique': 'T1496'
    },

    # =========================================================================
    # ROOTKITS
    # =========================================================================
    'ROOTKIT_GENERIC': {
        'patterns': [r'rootkit', r'root.?kit', r'hidden.*driver'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Rootkit - Generic',
        'description': 'Rootkit indicators detected',
        'mitre_technique': 'T1014'
    },
    'ROOTKIT_UEFI': {
        'patterns': [r'uefi.*rootkit', r'bootkit', r'efi.*backdoor'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Rootkit - UEFI/Bootkit',
        'description': 'UEFI/Boot rootkit detected',
        'mitre_technique': 'T1542.001'
    },

    # =========================================================================
    # EXPLOITS
    # =========================================================================
    'EXPLOIT_ETERNALBLUE': {
        'patterns': [r'eternalblue', r'eternal.?blue', r'ms17.010', r'CVE.2017.0144'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Exploit - EternalBlue',
        'description': 'EternalBlue (MS17-010) exploit detected',
        'mitre_technique': 'T1210'
    },
    'EXPLOIT_LOG4SHELL': {
        'patterns': [r'log4shell', r'log4j', r'CVE.2021.44228', r'\$\{jndi:'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Exploit - Log4Shell',
        'description': 'Log4Shell (CVE-2021-44228) exploit detected',
        'mitre_technique': 'T1190'
    },
    'EXPLOIT_PROXYSHELL': {
        'patterns': [r'proxyshell', r'CVE.2021.34473', r'CVE.2021.34523', r'CVE.2021.31207'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Exploit - ProxyShell',
        'description': 'ProxyShell Exchange exploit detected',
        'mitre_technique': 'T1190'
    },
    'EXPLOIT_PROXYLOGON': {
        'patterns': [r'proxylogon', r'CVE.2021.26855', r'CVE.2021.26857'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Exploit - ProxyLogon',
        'description': 'ProxyLogon Exchange exploit detected',
        'mitre_technique': 'T1190'
    },
    'EXPLOIT_ZEROLOGON': {
        'patterns': [r'zerologon', r'CVE.2020.1472'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Exploit - Zerologon',
        'description': 'Zerologon (CVE-2020-1472) exploit detected',
        'mitre_technique': 'T1210'
    },
    'EXPLOIT_PRINTNIGHTMARE': {
        'patterns': [r'printnightmare', r'CVE.2021.34527', r'CVE.2021.1675'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Exploit - PrintNightmare',
        'description': 'PrintNightmare exploit detected',
        'mitre_technique': 'T1210'
    },

    # =========================================================================
    # LOLBINS
    # =========================================================================
    'LOLBIN_CERTUTIL': {
        'patterns': [r'certutil.*urlcache', r'certutil.*decode', r'certutil.*encode'],
        'score': 7, 'severity': 'HIGH',
        'category': 'LOLBin - Certutil',
        'description': 'Certutil abuse for download/encoding',
        'mitre_technique': 'T1140'
    },
    'LOLBIN_MSHTA': {
        'patterns': [r'mshta.*http', r'mshta.*javascript:', r'mshta.*vbscript:'],
        'score': 8, 'severity': 'HIGH',
        'category': 'LOLBin - MSHTA',
        'description': 'MSHTA abuse detected',
        'mitre_technique': 'T1218.005'
    },
    'LOLBIN_REGSVR32': {
        'patterns': [r'regsvr32.*/s.*/n.*/u.*/i:', r'regsvr32.*scrobj'],
        'score': 8, 'severity': 'HIGH',
        'category': 'LOLBin - Regsvr32',
        'description': 'Regsvr32 abuse detected (Squiblydoo)',
        'mitre_technique': 'T1218.010'
    },
    'LOLBIN_RUNDLL32': {
        'patterns': [r'rundll32.*javascript:', r'rundll32.*comsvcs.*MiniDump'],
        'score': 8, 'severity': 'HIGH',
        'category': 'LOLBin - Rundll32',
        'description': 'Rundll32 abuse detected',
        'mitre_technique': 'T1218.011'
    },
    'LOLBIN_WMIC': {
        'patterns': [r'wmic.*process.*call.*create', r'wmic.*/node:'],
        'score': 7, 'severity': 'HIGH',
        'category': 'LOLBin - WMIC',
        'description': 'WMIC abuse detected',
        'mitre_technique': 'T1047'
    },

    # =========================================================================
    # ANTI-ANALYSIS
    # =========================================================================
    'ANTI_VM': {
        # Note: These detect VM-awareness in malware, not the VMs themselves.
        # Matching "vmware" or "virtualbox" in a YARA rule name IS meaningful
        # as it indicates anti-VM evasion detection.
        'patterns': [r'anti.?vm', r'vm.?detect', r'vm.?evasion', r'sandbox.?detect',
                     r'detect.?vm', r'detect.?virtual'],
        'score': 5, 'severity': 'MEDIUM',
        'category': 'Anti-Analysis - VM Detection',
        'description': 'VM detection technique identified',
        'mitre_technique': 'T1497.001'
    },
    'ANTI_DEBUG': {
        'patterns': [r'IsDebuggerPresent', r'CheckRemoteDebugger', r'NtQueryInformationProcess',
                     r'anti.?debug'],
        'score': 5, 'severity': 'MEDIUM',
        'category': 'Anti-Analysis - Debugger Detection',
        'description': 'Anti-debugging technique identified',
        'mitre_technique': 'T1622'
    },
    'ANTI_SANDBOX': {
        # FIXED: removed bare "sandbox" and bare tool names (cuckoo, any.run, etc.)
        # These are legitimate security tools, not indicators of malware on their own
        'patterns': [r'anti.?sandbox', r'sandbox.?evasion', r'sandbox.?detect',
                     r'detect.?sandbox', r'evade.?sandbox'],
        'score': 5, 'severity': 'MEDIUM',
        'category': 'Anti-Analysis - Sandbox Detection',
        'description': 'Sandbox detection technique identified',
        'mitre_technique': 'T1497.001'
    },

    # =========================================================================
    # POWERSHELL
    # =========================================================================
    'POWERSHELL_DOWNLOAD': {
        'patterns': [r'DownloadString', r'DownloadFile', r'Invoke-WebRequest', r'Net\.WebClient',
                     r'IEX.*http'],
        'score': 7, 'severity': 'HIGH',
        'category': 'PowerShell - Download Cradle',
        'description': 'PowerShell download cradle detected',
        'mitre_technique': 'T1059.001'
    },
    'POWERSHELL_ENCODED': {
        'patterns': [r'-enc\s', r'-EncodedCommand', r'FromBase64String',
                     r'obfuscat.*powershell', r'powershell.*obfuscat'],
        'score': 6, 'severity': 'MEDIUM',
        'category': 'PowerShell - Encoded Command',
        'description': 'Encoded PowerShell command detected',
        'mitre_technique': 'T1059.001'
    },
    'POWERSHELL_BYPASS': {
        'patterns': [r'-ExecutionPolicy\s+Bypass', r'-ep\s+bypass', r'Set-ExecutionPolicy'],
        'score': 6, 'severity': 'MEDIUM',
        'category': 'PowerShell - Execution Policy Bypass',
        'description': 'PowerShell execution policy bypass detected',
        'mitre_technique': 'T1059.001'
    },
    'POWERSHELL_AMSI_BYPASS': {
        'patterns': [r'amsiInitFailed', r'AmsiScanBuffer', r'amsi\.dll', r'Disable-Amsi'],
        'score': 8, 'severity': 'HIGH',
        'category': 'PowerShell - AMSI Bypass',
        'description': 'AMSI bypass attempt detected',
        'mitre_technique': 'T1562.001'
    },

    # =========================================================================
    # LATERAL MOVEMENT
    # =========================================================================
    'LATERAL_PSEXEC': {
        # FIXED: "psexec" as segment - it's a legitimate sysadmin tool
        'patterns': [_seg('psexec'), r'psexesvc', r'ADMIN\$'],
        'score': 7, 'severity': 'HIGH',
        'category': 'Lateral Movement - PsExec',
        'description': 'PsExec lateral movement detected',
        'mitre_technique': 'T1021.002'
    },
    'LATERAL_WMI': {
        'patterns': [r'wmic.*process.*call.*create', r'Win32_Process'],
        'score': 7, 'severity': 'HIGH',
        'category': 'Lateral Movement - WMI',
        'description': 'WMI lateral movement detected',
        'mitre_technique': 'T1047'
    },
    'LATERAL_WINRM': {
        # FIXED: "winrm" as segment, and specific PowerShell remoting cmdlets
        'patterns': [_seg('winrm'), r'Invoke-Command', r'Enter-PSSession', r'New-PSSession'],
        'score': 6, 'severity': 'MEDIUM',
        'category': 'Lateral Movement - WinRM',
        'description': 'WinRM lateral movement detected',
        'mitre_technique': 'T1021.006'
    },

    # =========================================================================
    # DATA EXFILTRATION
    # =========================================================================
    'EXFIL_DNS': {
        'patterns': [r'dns.*exfil', r'dnscat', r'iodine'],
        'score': 8, 'severity': 'HIGH',
        'category': 'Exfiltration - DNS',
        'description': 'DNS exfiltration technique detected',
        'mitre_technique': 'T1048.003'
    },
    'EXFIL_HTTP': {
        'patterns': [r'exfil.*http', r'data.*exfil', r'data.*steal'],
        'score': 7, 'severity': 'HIGH',
        'category': 'Exfiltration - HTTP',
        'description': 'HTTP exfiltration technique detected',
        'mitre_technique': 'T1041'
    },

    # =========================================================================
    # BANKING TROJANS
    # =========================================================================
    'BANKER_DRIDEX': {
        'patterns': [r'dridex', r'bugat', r'cridex'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Banking Trojan - Dridex',
        'description': 'Dridex banking trojan detected',
        'mitre_technique': 'T1185'
    },
    'BANKER_ZEUS': {
        # FIXED: "zeus" and "citadel" require security prefix or security suffix
        'patterns': [
            r'zbot',
            _ctx('zeus', ['bot', 'trojan', 'banker', 'malware', 'stealer']),
            _ctx('citadel', ['trojan', 'banker', 'malware', 'bot']),
            r'zeus.?bot', r'zeus.?trojan',
        ],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Banking Trojan - Zeus',
        'description': 'Zeus banking trojan detected',
        'mitre_technique': 'T1185'
    },
    'BANKER_URSNIF': {
        'patterns': [r'ursnif', r'gozi', r'isfb'],
        'score': 10, 'severity': 'CRITICAL',
        'category': 'Banking Trojan - Ursnif',
        'description': 'Ursnif/Gozi banking trojan detected',
        'mitre_technique': 'T1185'
    },
}


# =============================================================================
# YARA ANALYZER CLASS
# =============================================================================

class YaraAnalyzer:
    """
    Parse YARA output and extract threats
    Supports JSON, raw text, and rule file formats
    """

    def __init__(self):
        self.threat_patterns = YARA_THREAT_PATTERNS

    def analyze_yara_output(self, yara_data: str, input_format: str = 'auto') -> Dict[str, Any]:
        """
        Main analysis function
        Input formats: 'json', 'raw', 'rules', 'auto' (auto-detect)
        """
        # Auto-detect format
        if input_format == 'auto':
            input_format = self._detect_format(yara_data)

        # Parse based on format
        if input_format == 'json':
            parsed = self.parse_json_output(yara_data)
        elif input_format == 'rules':
            parsed = self.parse_yara_rules(yara_data)
        else:
            parsed = self.parse_raw_output(yara_data)

        # Score the matches
        scored = self.score_matches(parsed.get('matches', []))

        # Generate next steps
        next_steps = self.generate_next_steps(scored)

        # Identify vulnerabilities/TTPs
        vulnerabilities = self.identify_vulnerabilities(scored)

        return {
            'raw_data': yara_data,
            'parsed_output': parsed,
            'threat_analysis': scored,
            'next_steps': next_steps,
            'vulnerabilities': vulnerabilities,
            'summary': self._generate_summary(scored)
        }

    def _detect_format(self, data: str) -> str:
        """Auto-detect input format"""
        data_stripped = data.strip()

        # Check for JSON
        if data_stripped.startswith('{') or data_stripped.startswith('['):
            try:
                json.loads(data_stripped)
                return 'json'
            except:
                pass

        # Check for YARA rule format
        if 'rule ' in data and 'condition:' in data:
            return 'rules'

        # Default to raw
        return 'raw'

    def parse_json_output(self, json_data: str) -> Dict[str, Any]:
        """Parse YARA JSON format output"""
        try:
            data = json.loads(json_data)
        except json.JSONDecodeError:
            return {'matches': [], 'error': 'Invalid JSON'}

        matches = []

        # Handle various JSON formats
        if isinstance(data, list):
            for item in data:
                match = self._parse_json_match(item)
                if match:
                    matches.append(match)
        elif isinstance(data, dict):
            if 'matches' in data:
                for item in data['matches']:
                    match = self._parse_json_match(item)
                    if match:
                        matches.append(match)
            else:
                match = self._parse_json_match(data)
                if match:
                    matches.append(match)

        return {
            'matches': matches,
            'total_matches': len(matches),
            'format': 'json'
        }

    def _parse_json_match(self, item: Dict) -> Optional[Dict]:
        """Parse a single JSON match entry"""
        if not isinstance(item, dict):
            return None

        return {
            'rule': item.get('rule', item.get('rule_name', 'Unknown')),
            'tags': item.get('tags', []),
            'meta': item.get('meta', item.get('metadata', {})),
            'strings': item.get('strings', item.get('matched_strings', [])),
            'file': item.get('file', item.get('target', item.get('path', 'Unknown'))),
            'namespace': item.get('namespace', 'default')
        }

    def parse_raw_output(self, raw_data: str) -> Dict[str, Any]:
        """Parse raw YARA text output"""
        matches = []
        lines = raw_data.strip().split('\n')

        current_match = None
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Standard YARA output: RuleName file_path
            rule_match = re.match(r'^(\w+)\s+(.+)$', line)
            if rule_match and not line.startswith('0x'):
                if current_match:
                    matches.append(current_match)
                current_match = {
                    'rule': rule_match.group(1),
                    'file': rule_match.group(2),
                    'strings': [],
                    'tags': [],
                    'meta': {}
                }

            # String match line: 0x1234:$string_name: matched_data
            string_match = re.match(r'^(0x[0-9a-fA-F]+):(\$\w+):\s*(.*)$', line)
            if string_match and current_match:
                current_match['strings'].append({
                    'offset': string_match.group(1),
                    'identifier': string_match.group(2),
                    'data': string_match.group(3)
                })

        if current_match:
            matches.append(current_match)

        return {
            'matches': matches,
            'total_matches': len(matches),
            'format': 'raw'
        }

    def parse_yara_rules(self, rules_text: str) -> Dict[str, Any]:
        """Parse YARA rule files for documentation and analysis"""
        rules = []

        # Pattern to match YARA rules
        rule_pattern = r'rule\s+(\w+)(?:\s*:\s*([^\{]+))?\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}'

        for match in re.finditer(rule_pattern, rules_text, re.DOTALL):
            rule_name = match.group(1)
            tags = match.group(2).strip().split() if match.group(2) else []
            rule_body = match.group(3)

            # Extract metadata
            meta = {}
            meta_match = re.search(r'meta:\s*(.*?)(?:strings:|condition:)', rule_body, re.DOTALL)
            if meta_match:
                for line in meta_match.group(1).split('\n'):
                    kv = re.match(r'\s*(\w+)\s*=\s*["\']?([^"\']+)["\']?', line)
                    if kv:
                        meta[kv.group(1)] = kv.group(2).strip()

            # Extract strings section
            strings = []
            strings_match = re.search(r'strings:\s*(.*?)condition:', rule_body, re.DOTALL)
            if strings_match:
                for line in strings_match.group(1).split('\n'):
                    str_match = re.match(r'\s*(\$\w+)\s*=\s*(.+)', line)
                    if str_match:
                        strings.append({
                            'identifier': str_match.group(1),
                            'pattern': str_match.group(2).strip()
                        })

            # Extract condition
            condition = ''
            cond_match = re.search(r'condition:\s*(.*)', rule_body, re.DOTALL)
            if cond_match:
                condition = cond_match.group(1).strip()

            rules.append({
                'rule': rule_name,
                'tags': tags,
                'meta': meta,
                'strings': strings,
                'condition': condition
            })

        return {
            'matches': rules,
            'total_rules': len(rules),
            'format': 'rules'
        }

    def score_matches(self, matches: List[Dict]) -> Dict[str, Any]:
        """Score threat level based on matched rules"""
        threats_detected = []
        total_score = 0
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

        for match in matches:
            rule_name = match.get('rule', '').lower()
            rule_meta = match.get('meta', {})

            # Build combined search text from rule_name + meta fields + tags
            # This gives patterns multiple signals beyond just the rule name
            search_parts = [rule_name]
            if rule_meta:
                for key in ('threat', 'family', 'malware_family', 'malware_type', 'threat_actor'):
                    val = rule_meta.get(key, '')
                    if val:
                        search_parts.append(val.lower())
            rule_tags = match.get('tags', [])
            if rule_tags:
                search_parts.extend([t.lower() for t in rule_tags])
            search_text = ' '.join(search_parts)

            # Check against threat patterns using combined search text
            matched_threats = []
            for threat_type, config in self.threat_patterns.items():
                for pattern in config['patterns']:
                    if re.search(pattern, search_text, re.IGNORECASE):
                        matched_threats.append({
                            'threat_type': threat_type,
                            'category': config['category'],
                            'severity': config['severity'],
                            'score': config['score'],
                            'description': config['description'],
                            'mitre_technique': config.get('mitre_technique', 'Unknown'),
                            'rule_matched': match.get('rule', 'Unknown'),
                            'file': match.get('file', 'Unknown')
                        })
                        total_score += config['score']
                        severity_counts[config['severity']] += 1
                        break

            if matched_threats:
                threats_detected.extend(matched_threats)

            # If no pattern matched, add as unknown threat
            if not matched_threats:
                severity = rule_meta.get('severity', 'MEDIUM').upper()
                if severity not in severity_counts:
                    severity = 'MEDIUM'
                threats_detected.append({
                    'threat_type': 'UNKNOWN',
                    'category': 'Unknown Threat',
                    'severity': severity,
                    'score': 5,
                    'description': f"Rule '{match.get('rule', 'Unknown')}' matched",
                    'mitre_technique': rule_meta.get('mitre_attack', 'Unknown'),
                    'rule_matched': match.get('rule', 'Unknown'),
                    'file': match.get('file', 'Unknown')
                })
                total_score += 5
                severity_counts[severity] += 1

        # Determine overall severity
        if severity_counts['CRITICAL'] > 0:
            overall_severity = 'CRITICAL'
        elif severity_counts['HIGH'] > 0:
            overall_severity = 'HIGH'
        elif severity_counts['MEDIUM'] > 0:
            overall_severity = 'MEDIUM'
        else:
            overall_severity = 'LOW'

        return {
            'threats': threats_detected,
            'total_score': total_score,
            'overall_severity': overall_severity,
            'severity_breakdown': severity_counts,
            'total_threats': len(threats_detected)
        }

    def generate_next_steps(self, analysis: Dict) -> List[str]:
        """Generate actionable next steps based on analysis"""
        next_steps = []

        if analysis['total_score'] == 0:
            return ["No threats detected. Continue monitoring."]

        # Priority actions based on severity
        if analysis['overall_severity'] == 'CRITICAL':
            next_steps.extend([
                "IMMEDIATE ACTION REQUIRED:",
                "1. Isolate affected system(s) from the network",
                "2. Preserve all evidence (memory dump, disk image)",
                "3. Notify incident response team",
                "4. Do NOT power off systems until forensic acquisition is complete",
            ])

        # Specific recommendations based on threats
        for threat in analysis['threats']:
            category = threat['category']

            if 'Ransomware' in category:
                next_steps.extend([
                    f"\nRANSOMWARE DETECTED ({threat['rule_matched']}):",
                    "- Check for shadow copy deletion (vssadmin, wmic)",
                    "- Identify encryption scope",
                    "- Check backup integrity",
                    "- Do NOT pay ransom - contact law enforcement",
                    "- Submit sample to ID Ransomware for identification"
                ])

            elif 'C2' in category or 'Cobalt Strike' in category:
                next_steps.extend([
                    f"\nC2 FRAMEWORK DETECTED ({threat['rule_matched']}):",
                    "- Block identified C2 infrastructure at firewall",
                    "- Hunt for lateral movement across environment",
                    "- Check for persistence mechanisms",
                    "- Review authentication logs for anomalies",
                    "- Consider threat hunting across all endpoints"
                ])

            elif 'Credential' in category or 'Mimikatz' in category:
                next_steps.extend([
                    f"\nCREDENTIAL THEFT DETECTED ({threat['rule_matched']}):",
                    "- Force password reset for affected accounts",
                    "- Review privileged account usage",
                    "- Enable additional authentication controls",
                    "- Check for pass-the-hash/pass-the-ticket attacks",
                    "- Review Kerberos ticket activity"
                ])

            elif 'APT' in category:
                next_steps.extend([
                    f"\nAPT INDICATORS DETECTED ({threat['rule_matched']}):",
                    "- Engage advanced incident response resources",
                    "- Conduct comprehensive network threat hunting",
                    "- Review logs for extended time period (months)",
                    "- Consider engaging law enforcement/CISA",
                    "- Document all findings for attribution"
                ])

            elif 'Webshell' in category:
                next_steps.extend([
                    f"\nWEBSHELL DETECTED ({threat['rule_matched']}):",
                    "- Identify entry point (vulnerable web application)",
                    "- Remove webshell and patch vulnerability",
                    "- Check for additional backdoors",
                    "- Review web server logs",
                    "- Scan all web-accessible directories"
                ])

            elif 'Exploit' in category:
                next_steps.extend([
                    f"\nEXPLOIT DETECTED ({threat['rule_matched']}):",
                    "- Verify patch status of affected systems",
                    "- Check for successful exploitation indicators",
                    "- Apply patches/mitigations immediately",
                    "- Review network segmentation"
                ])

        # General recommendations
        next_steps.extend([
            "\nGENERAL RECOMMENDATIONS:",
            "- Document all findings with timestamps",
            "- Collect additional IOCs from analysis",
            "- Update detection rules based on findings",
            "- Consider engaging external incident response support"
        ])

        return next_steps

    def identify_vulnerabilities(self, analysis: Dict) -> List[Dict]:
        """Map YARA matches to vulnerabilities/TTPs"""
        vulnerabilities = []

        for threat in analysis['threats']:
            vuln = {
                'name': threat['category'],
                'severity': threat['severity'],
                'mitre_technique': threat['mitre_technique'],
                'description': threat['description'],
                'rule_matched': threat['rule_matched'],
                'file': threat['file'],
                'remediation': self._get_remediation(threat['threat_type'])
            }
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _get_remediation(self, threat_type: str) -> str:
        """Get remediation guidance for threat type"""
        remediations = {
            'RANSOMWARE': "Isolate, preserve evidence, restore from backup, patch vulnerabilities",
            'C2': "Block C2 infrastructure, hunt for persistence, reset credentials",
            'CREDENTIAL': "Force password reset, enable MFA, audit privileged access",
            'APT': "Engage IR team, comprehensive threat hunt, long-term monitoring",
            'WEBSHELL': "Remove webshell, patch web application, audit web directories",
            'EXPLOIT': "Apply security patches, verify patch status, network segmentation",
            'PACKER': "Unpack and analyze, scan unpacked content",
            'INJECTION': "Identify injected process, dump memory, analyze payload",
        }

        for key, remediation in remediations.items():
            if key in threat_type.upper():
                return remediation

        return "Investigate further, collect additional IOCs, update detection rules"

    def _generate_summary(self, analysis: Dict) -> Dict[str, Any]:
        """Generate analysis summary"""
        return {
            'total_threats': analysis['total_threats'],
            'total_score': analysis['total_score'],
            'overall_severity': analysis['overall_severity'],
            'critical_count': analysis['severity_breakdown']['CRITICAL'],
            'high_count': analysis['severity_breakdown']['HIGH'],
            'medium_count': analysis['severity_breakdown']['MEDIUM'],
            'low_count': analysis['severity_breakdown']['LOW'],
            'requires_immediate_action': analysis['overall_severity'] in ['CRITICAL', 'HIGH']
        }


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def analyze_yara_data(yara_output: str, input_format: str = 'auto') -> Dict[str, Any]:
    """
    Convenience function to analyze YARA output
    """
    analyzer = YaraAnalyzer()
    return analyzer.analyze_yara_output(yara_output, input_format)


def format_analysis_report(analysis: Dict[str, Any]) -> str:
    """
    Format analysis results as human-readable report
    """
    lines = []
    lines.append("=" * 80)
    lines.append("YARA THREAT ANALYSIS REPORT")
    lines.append("=" * 80)
    lines.append("")

    summary = analysis.get('summary', {})
    lines.append(f"THREAT SCORE: {summary.get('total_score', 0)}")
    lines.append(f"OVERALL SEVERITY: {summary.get('overall_severity', 'UNKNOWN')}")
    lines.append(f"TOTAL THREATS: {summary.get('total_threats', 0)}")
    lines.append("")

    if summary.get('requires_immediate_action'):
        lines.append("[!] IMMEDIATE ACTION REQUIRED")
        lines.append("")

    # Severity breakdown
    lines.append("SEVERITY BREAKDOWN:")
    lines.append(f"  CRITICAL: {summary.get('critical_count', 0)}")
    lines.append(f"  HIGH:     {summary.get('high_count', 0)}")
    lines.append(f"  MEDIUM:   {summary.get('medium_count', 0)}")
    lines.append(f"  LOW:      {summary.get('low_count', 0)}")
    lines.append("")

    # Threats
    threats = analysis.get('threat_analysis', {}).get('threats', [])
    if threats:
        lines.append("DETECTED THREATS:")
        lines.append("-" * 40)
        for threat in threats:
            lines.append(f"\n[{threat['severity']}] {threat['category']}")
            lines.append(f"  Rule: {threat['rule_matched']}")
            lines.append(f"  File: {threat['file']}")
            lines.append(f"  Description: {threat['description']}")
            lines.append(f"  MITRE ATT&CK: {threat['mitre_technique']}")
        lines.append("")

    # Next steps
    next_steps = analysis.get('next_steps', [])
    if next_steps:
        lines.append("RECOMMENDED NEXT STEPS:")
        lines.append("-" * 40)
        for step in next_steps:
            lines.append(step)
        lines.append("")

    lines.append("=" * 80)
    return "\n".join(lines)


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    # Example usage
    sample_json = '''
    {
        "rule": "CobaltStrike_Beacon",
        "tags": ["c2", "apt"],
        "meta": {
            "author": "Security Team",
            "description": "Detects Cobalt Strike beacon"
        },
        "strings": [
            {"offset": "0x1234", "identifier": "$beacon", "data": "beacon.dll"}
        ],
        "file": "/tmp/suspicious.exe"
    }
    '''

    analyzer = YaraAnalyzer()
    result = analyzer.analyze_yara_output(sample_json)
    print(format_analysis_report(result))
