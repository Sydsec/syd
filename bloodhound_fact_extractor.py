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
        }

    def extract_facts(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main extraction method - deterministically extracts ALL facts from BloodHound JSON.

        Args:
            json_data: Parsed BloodHound JSON (dict)

        Returns:
            Dictionary containing all extracted facts
        """
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

        # Post-processing: Identify critical findings
        self._identify_critical_findings()

        # Build attack path chains (multi-hop)
        self._build_attack_chains()

        return self.facts

    def _normalize_json_format(self, json_data: Dict[str, Any]) -> List[Dict]:
        """
        Handle multiple BloodHound JSON formats and return normalized object list.

        Formats supported:
        1. Old format: {"data": [{...}, {...}]}
        2. New format: {"users": [...], "computers": [...], "groups": [...]}
        3. Mixed format
        """
        objects = []

        # New format: separate arrays
        if any(key in json_data for key in ['users', 'computers', 'groups', 'ous', 'gpos', 'domains']):
            objects.extend(json_data.get('users', []))
            objects.extend(json_data.get('computers', []))
            objects.extend(json_data.get('groups', []))
            objects.extend(json_data.get('ous', []))
            objects.extend(json_data.get('gpos', []))
            objects.extend(json_data.get('domains', []))

        # Old format: single data array
        if 'data' in json_data and isinstance(json_data['data'], list):
            objects.extend(json_data['data'])

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
        # Try explicit type fields
        obj_type = (obj.get('Kind') or
                   obj.get('Type') or
                   obj.get('ObjectType') or
                   obj.get('Properties', {}).get('objecttype'))

        if obj_type:
            return obj_type

        # Infer from properties
        props = obj.get('Properties', {})
        if 'samaccountname' in props and 'lastlogon' in props:
            return 'User'
        if 'operatingsystem' in props or 'dnshostname' in props:
            return 'Computer'
        if 'members' in obj or 'Members' in obj:
            return 'Group'
        if 'gpcfilesyspath' in props:
            return 'GPO'
        if props.get('distinguishedname', '').startswith('OU='):
            return 'OU'
        if 'trusts' in obj or props.get('name', '').endswith('.local'):
            return 'Domain'

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
            if props.get('hasspn'):
                spns = props.get('serviceprincipalnames', [])
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

        # Domain Controller identification
        is_dc = (props.get('isdc') or
                'domain controller' in props.get('operatingsystem', '').lower() or
                'domain controllers' in props.get('distinguishedname', '').lower())

        if is_dc:
            self.facts['domain_controllers'].append(name)

        # High-value
        if props.get('highvalue'):
            self.facts['high_value_targets'].append(name)

        # Unconstrained delegation (critical on non-DCs)
        if props.get('unconstraineddelegation') and not is_dc:
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

            # ... (add other specific categories as needed)

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
            is_da = any(da_pattern in user_lower for da_pattern in ['domain admins', 'enterprise admins', 'administrator'])
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
        """Build multi-hop attack path chains (future enhancement)"""
        # This would implement graph traversal to find chains like:
        # User A -> GenericAll -> Group B -> AddMember -> Group C -> AdminTo -> Computer D
        # For v1.0, we're focusing on single-hop paths
        pass

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
        else:
            lines.append(f"A: NO - No users with dontreqpreauth=true were found")
        lines.append("")

        # 7. UNCONSTRAINED DELEGATION
        lines.append("--- UNCONSTRAINED DELEGATION ---")
        lines.append(f"Q: Are there any accounts with Unconstrained Delegation?")
        if facts['unconstrained_delegation']:
            non_dc = [acc for acc in facts['unconstrained_delegation'] if acc not in facts['domain_controllers']]
            if non_dc:
                lines.append(f"A: CRITICAL - {len(non_dc)} non-DC accounts with Unconstrained Delegation:")
                lines.append(f"   {', '.join(non_dc[:10])}")
            else:
                lines.append(f"A: Only Domain Controllers have Unconstrained Delegation (expected)")
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
        else:
            lines.append(f"A: NO - No explicit DCSync rights found in this data")
        lines.append("")

        # 11. GENERICALL PATHS
        if facts['genericall_paths']:
            lines.append("--- GENERICALL (FULL CONTROL) PERMISSIONS ---")
            lines.append(f"Q: Which principals have GenericAll (full control) over other objects?")
            lines.append(f"A: {len(facts['genericall_paths'])} GenericAll relationships found:")
            for i, path in enumerate(facts['genericall_paths'][:10]):
                lines.append(f"   {i+1}. {path['source']} has GenericAll on {path['target']}")
            if len(facts['genericall_paths']) > 10:
                lines.append(f"   ... and {len(facts['genericall_paths']) - 10} more")
            lines.append("")

        # 12. WRITEDACL PATHS
        if facts['writedacl_paths']:
            lines.append("--- WRITEDACL PERMISSIONS ---")
            lines.append(f"Q: Which principals can modify permissions (WriteDacl)?")
            lines.append(f"A: {len(facts['writedacl_paths'])} WriteDacl relationships:")
            for i, path in enumerate(facts['writedacl_paths'][:10]):
                lines.append(f"   {i+1}. {path['source']} can modify permissions on {path['target']}")
            if len(facts['writedacl_paths']) > 10:
                lines.append(f"   ... and {len(facts['writedacl_paths']) - 10} more")
            lines.append("")

        # 13. FORCECHANGEPASSWORD PATHS
        if facts['forcechangepassword_paths']:
            lines.append("--- FORCECHANGEPASSWORD RIGHTS ---")
            lines.append(f"Q: Which principals can force password resets?")
            lines.append(f"A: {len(facts['forcechangepassword_paths'])} ForceChangePassword relationships:")
            for i, path in enumerate(facts['forcechangepassword_paths'][:10]):
                lines.append(f"   {i+1}. {path['source']} can reset password for {path['target']}")
            if len(facts['forcechangepassword_paths']) > 10:
                lines.append(f"   ... and {len(facts['forcechangepassword_paths']) - 10} more")
            lines.append("")

        # 14. ADDMEMBER PATHS
        if facts['addmember_paths']:
            lines.append("--- ADDMEMBER RIGHTS ---")
            lines.append(f"Q: Which principals can add members to groups?")
            lines.append(f"A: {len(facts['addmember_paths'])} AddMember relationships:")
            for i, path in enumerate(facts['addmember_paths'][:10]):
                lines.append(f"   {i+1}. {path['source']} can add members to {path['target']}")
            if len(facts['addmember_paths']) > 10:
                lines.append(f"   ... and {len(facts['addmember_paths']) - 10} more")
            lines.append("")

        # 15. SHADOW CREDENTIALS
        if facts['shadow_credentials_paths']:
            lines.append("--- SHADOW CREDENTIALS ATTACK PATHS ---")
            lines.append(f"Q: Which principals can perform Shadow Credentials attacks?")
            lines.append(f"A: CRITICAL - {len(facts['shadow_credentials_paths'])} AddKeyCredentialLink relationships:")
            for i, path in enumerate(facts['shadow_credentials_paths'][:10]):
                lines.append(f"   {i+1}. {path['source']} can add key credential to {path['target']}")
            lines.append("")

        # 16. LAPS READERS
        if facts['laps_readers']:
            lines.append("--- LAPS PASSWORD READERS ---")
            lines.append(f"Q: Which principals can read LAPS passwords?")
            unique_laps = list(set(facts['laps_readers']))
            lines.append(f"A: {len(unique_laps)} principals:")
            lines.append(f"   {', '.join(unique_laps[:10])}")
            lines.append("")

        # 17. ADMINTO PATHS
        if facts['adminto_paths']:
            lines.append("--- LOCAL ADMINISTRATOR RIGHTS ---")
            lines.append(f"Q: Which principals have local admin rights on computers?")
            lines.append(f"A: {len(facts['adminto_paths'])} AdminTo relationships:")
            for i, path in enumerate(facts['adminto_paths'][:10]):
                lines.append(f"   {i+1}. {path['source']} is local admin on {path['target']}")
            if len(facts['adminto_paths']) > 10:
                lines.append(f"   ... and {len(facts['adminto_paths']) - 10} more")
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

        # 21. ATTACK PATH SUMMARY
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

        # Extract potential usernames from answer (simple pattern matching)
        # Look for common patterns: user@domain, DOMAIN\user, or standalone usernames
        potential_users = re.findall(r'([a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+)', answer)
        potential_users += re.findall(r'([A-Z]+\\[a-zA-Z0-9_\-\.]+)', answer)

        # Check if mentioned users exist
        all_users_lower = [u.lower() for u in facts['all_users']]
        all_groups_lower = [g.lower() for g in facts['all_groups']]
        all_computers_lower = [c.lower() for c in facts['all_computers']]

        for user in potential_users:
            # Strip trailing punctuation (e.g., "IT_ADMIN@CORP.LOCAL." -> "IT_ADMIN@CORP.LOCAL")
            user_clean = user.lower().strip().rstrip('.,;:!?')

            # Extract username part (before @) for flexible matching
            username_part = user_clean.split('@')[0] if '@' in user_clean else user_clean.split('\\')[-1]

            # Check in users, groups, AND computers (since they all use @domain format)
            found_in_users = any(user_clean == existing or user_clean in existing for existing in all_users_lower)
            found_in_groups = any(user_clean == existing or user_clean in existing for existing in all_groups_lower)
            found_in_computers = any(user_clean == existing or user_clean in existing for existing in all_computers_lower)

            # If not found with exact domain, try matching just username (handles domain typos/variations)
            if not (found_in_users or found_in_groups or found_in_computers):
                found_in_users = any(username_part in existing.split('@')[0] if '@' in existing else False for existing in all_users_lower)
                found_in_groups = any(username_part in existing.split('@')[0] if '@' in existing else False for existing in all_groups_lower)
                found_in_computers = any(username_part in existing.split('@')[0] if '@' in existing else False for existing in all_computers_lower)

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
