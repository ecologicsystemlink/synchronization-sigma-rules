"""
Sigma Rule Parser

Parses Sigma YAML detection rules and extracts metadata, detection logic, and technology mappings.
Handles MITRE ATT&CK technique extraction and automatic categorization.
"""

import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple


class SigmaParser:
    """
    Parses Sigma rules and extracts detection components.
    """
    
    def __init__(self):
        self.supported_modifiers = {
            'contains': 'contains',
            'startswith': 'startsWith', 
            'endswith': 'endsWith',
            'all': 'all',
            'base64': 'base64',
            'base64offset': 'base64offset',
            'utf16le': 'utf16le',
            'utf16be': 'utf16be',
            'wide': 'wide',
            're': 'regex'
        }
    
    def validate_sigma_file(self, file_path: Path) -> bool:
        """
        Validate Sigma YAML file.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                yaml.safe_load(f)
            return True
        except yaml.YAMLError:
            return False
        except Exception:
            return False
    
    def parse_sigma_rule(self, file_path: Path) -> Dict[str, Any]:
        """
        Parse a Sigma rule file and extract all components.
        
        Returns:
            Dictionary with parsed rule components
        """
        if not self.validate_sigma_file(file_path):
            raise ValueError(f"Invalid Sigma YAML file: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            rule_data = yaml.safe_load(f)
        
        return {
            'title': rule_data.get('title', ''),
            'id': rule_data.get('id', ''),
            'status': rule_data.get('status', 'experimental'),
            'description': rule_data.get('description', ''),
            'author': rule_data.get('author', ''),
            'date': rule_data.get('date', ''),
            'references': rule_data.get('references', []),
            'tags': rule_data.get('tags', []),
            'logsource': rule_data.get('logsource', {}),
            'detection': rule_data.get('detection', {}),
            'falsepositives': rule_data.get('falsepositives', []),
            'level': rule_data.get('level', 'medium'),
            'filename': file_path.name,
            'filepath': str(file_path)
        }
    
    def extract_detection_logic(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract and normalize detection logic from Sigma detection block.
        
        Args:
            detection: The detection block from Sigma rule
            
        Returns:
            Normalized detection components
        """
        if not detection:
            return {}
        
        condition = detection.get('condition', 'selection')
        selections = {}
        filters = {}
        
        for key, value in detection.items():
            if key == 'condition':
                continue
            elif key.startswith('filter'):
                filters[key] = value
            else:
                selections[key] = value
        
        return {
            'condition': condition,
            'selections': selections,
            'filters': filters,
            'raw_detection': detection
        }
    
    def parse_field_with_modifiers(self, field_name: str) -> Tuple[str, List[str]]:
        """
        Parse field name and extract modifiers.
        
        Example: 'ProcessName|endswith' → ('ProcessName', ['endswith'])
        """
        if '|' not in field_name:
            return field_name, []
        
        parts = field_name.split('|')
        base_field = parts[0]
        modifiers = parts[1:]
        
        return base_field, modifiers
    
    def get_sigma_files_from_directory(self, directory: Path) -> List[Path]:
        """
        Get all Sigma rule files from directory.
        """
        all_files = []
        if directory.exists():
            for file_path in directory.rglob("*.yml"):
                if self._is_sigma_rule(file_path):
                    all_files.append(file_path)
            for file_path in directory.rglob("*.yaml"):
                if self._is_sigma_rule(file_path):
                    all_files.append(file_path)
        
        return sorted(all_files)
    
    def _is_sigma_rule(self, file_path: Path) -> bool:
        """
        Determine if a YAML file is a Sigma rule.
        Optimized to check essential Sigma rule structure.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Read line by line for efficiency and better detection
                has_detection = False
                has_identifier = False
                
                for line_num, line in enumerate(f):
                    line_stripped = line.strip().lower()
                    
                    # Check for required fields
                    if line_stripped.startswith('detection:'):
                        has_detection = True
                    elif line_stripped.startswith(('title:', 'logsource:')):
                        has_identifier = True
                    
                    # Early return if both conditions met
                    if has_detection and has_identifier:
                        return True
                    
                    # Limit search to first 50 lines for performance
                    if line_num > 50:
                        break
                
                return False
        except:
            return False
    
    def extract_mitre_techniques(self, tags: List[str]) -> List[str]:
        """
        Extract MITRE ATT&CK technique IDs from tags.
        """
        techniques = []
        for tag in tags:
            if tag.startswith('attack.t') and len(tag) >= 9:  # attack.t1234
                technique_id = tag.replace('attack.t', 'T').upper()
                techniques.append(technique_id)
        return techniques
    
    def determine_technology_from_logsource(self, logsource: Dict[str, Any]) -> Tuple[str, str]:
        """
        Determine technology category and name from Sigma logsource.
        
        Returns:
            Tuple of (category, technology_name)
        """
        product = logsource.get('product', '').lower()
        service = logsource.get('service', '').lower()
        category = logsource.get('category', '').lower()
        
        # Technology mapping based on Sigma logsource to CorrelationRules structure
        tech_mappings = {
            'windows': ('windows', 'wineventlog'),
            'linux': ('linux', 'linux'),
            'macos': ('macos', 'macos'),
            'aws': ('aws', 'aws'),
            'azure': ('cloud/azure', 'azure'),
            'gcp': ('cloud/google', 'google'),
            'm365': ('office365', 'o365'),
            'office365': ('office365', 'o365'),
            'github': ('github/github', 'github'),
            'cisco': ('cisco/asa', 'firewall-cisco-asa'),
            'fortinet': ('fortinet/fortinet', 'firewall-fortigate-traffic'),
            'paloalto': ('paloalto/pa_firewall', 'firewall-paloalto'),
            'apache': ('filebeat/apache_module', 'apache'),
            'nginx': ('filebeat/nginx_module', 'nginx'),
            'iis': ('filebeat/iis_module', 'iis'),
            'auditd': ('filebeat/auditd_module', 'auditd'),
            'syslog': ('syslog/cef', 'syslog'),
            'mikrotik': ('mikrotik/mikrotik_fw', 'firewall-mikrotik'),
            'sonicwall': ('sonicwall/sonicwall_firewall', 'firewall-sonicwall'),
            'sophos': ('sophos/sophos_xg_firewall', 'firewall-sophos-xg'),
            'vmware': ('vmware/vmware-esxi', 'vmware-esxi'),
            'esxi': ('vmware/vmware-esxi', 'vmware-esxi'),
        }
        
        # Service-specific mappings
        service_mappings = {
            'security': ('windows', 'wineventlog'),
            'system': ('windows', 'wineventlog'),
            'application': ('windows', 'wineventlog'),
            'sysmon': ('windows', 'wineventlog'),
            'powershell': ('windows', 'wineventlog'),
            'taskscheduler': ('windows', 'wineventlog'),
            'terminalservices-localsessionmanager': ('windows', 'wineventlog'),
            'windefend': ('windows', 'wineventlog'),
        }
        
        # Try product first
        if product in tech_mappings:
            return tech_mappings[product]
        
        # Try service with both mappings
        if service in tech_mappings:
            return tech_mappings[service]
        
        if service in service_mappings:
            return service_mappings[service]
        
        # Try category-based mapping
        if category == 'firewall':
            return ('generic/generic', 'generic')
        elif category == 'antivirus':
            return ('antivirus/kaspersky', 'antivirus-kaspersky')
        elif category == 'proxy':
            return ('generic/generic', 'generic')
        
        # Default fallback
        return ('generic/generic', 'generic')
    
    def extract_rule_metadata(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract metadata from parsed Sigma rule.
        """
        # Map Sigma levels to impact scores
        level_to_impact = {
            'informational': {'confidentiality': 1, 'integrity': 1, 'availability': 1},
            'low': {'confidentiality': 1, 'integrity': 1, 'availability': 2},
            'medium': {'confidentiality': 2, 'integrity': 2, 'availability': 2},
            'high': {'confidentiality': 3, 'integrity': 3, 'availability': 3},
            'critical': {'confidentiality': 3, 'integrity': 3, 'availability': 3}
        }
        
        level = rule_data.get('level', 'medium').lower()
        impact = level_to_impact.get(level, level_to_impact['medium'])
        
        # Extract MITRE techniques
        techniques = self.extract_mitre_techniques(rule_data.get('tags', []))
        
        # Determine technology
        tech_category, tech_name = self.determine_technology_from_logsource(rule_data.get('logsource', {}))
        
        return {
            'name': rule_data.get('title', ''),
            'description': rule_data.get('description', ''),
            'impact': impact,
            'category': self._determine_category_from_tags(rule_data.get('tags', [])),
            'technique': ', '.join(techniques) if techniques else 'Unknown',
            'references': rule_data.get('references', []),
            'technology_category': tech_category,
            'technology_name': tech_name,
            'sigma_level': level,
            'sigma_id': rule_data.get('id', ''),
            'author': rule_data.get('author', ''),
            'date': rule_data.get('date', '')
        }
    
    def _determine_category_from_tags(self, tags: List[str]) -> str:
        """
        Determine rule category from Sigma tags.
        """
        # Map common Sigma tactics to categories
        tactic_mappings = {
            'attack.initial_access': 'Initial Access',
            'attack.execution': 'Execution',
            'attack.persistence': 'Persistence',
            'attack.privilege_escalation': 'Privilege Escalation',
            'attack.defense_evasion': 'Defense Evasion',
            'attack.credential_access': 'Credential Access',
            'attack.discovery': 'Discovery',
            'attack.lateral_movement': 'Lateral Movement',
            'attack.collection': 'Collection',
            'attack.command_and_control': 'Command and Control',
            'attack.exfiltration': 'Exfiltration',
            'attack.impact': 'Impact'
        }
        
        for tag in tags:
            if tag in tactic_mappings:
                return tactic_mappings[tag]
        
        # Fallback based on technique tags
        for tag in tags:
            if tag.startswith('attack.t'):
                return 'Security Detection'
        
        return 'General Security'