"""
Sigma Rule Converter

Converts individual Sigma detection rules to UTMStack correlation rule format.
Integrates sigma-cli conversion with UTMStack-specific post-processing and metadata handling.
"""

import logging
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from ..core.sigma_parser import SigmaParser
from ..core.sigma_cli_integration import SigmaCLIIntegration
from ..core.field_mapper import FieldMapper


class RuleConverter:
    """
    Converts Sigma rules to UTMStack SIEM format.
    """
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.sigma_parser = SigmaParser()
        self.sigma_cli = SigmaCLIIntegration()
        self.field_mapper = FieldMapper(base_dir)
        self.next_rule_id = 3000  # Starting ID for converted rules
    
    def convert_sigma_rule(self, sigma_file: Path, output_dir: Optional[Path] = None) -> Dict[str, Any]:
        """
        Convert a single Sigma rule to UTMStack format.
        
        Args:
            sigma_file: Path to Sigma rule file
            output_dir: Directory to save converted rule (optional)
            
        Returns:
            Dictionary with conversion results
        """
        try:
            # Parse the Sigma rule
            sigma_data = self.sigma_parser.parse_sigma_rule(sigma_file)
            
            # Extract metadata
            metadata = self.sigma_parser.extract_rule_metadata(sigma_data)
            
            # Extract detection logic
            detection_logic = self.sigma_parser.extract_detection_logic(sigma_data['detection'])
            
            # Generate CEL expression using sigma-cli
            cel_expression = self.sigma_cli.convert_sigma_rule(sigma_file)
            
            # Get technology information
            tech_category = metadata['technology_category']
            tech_name = metadata['technology_name']
            
            # Get filter fields if available
            filter_file, filter_fields = self.field_mapper.get_filter_fields(tech_category, tech_name)
            
            # Build UTMStack rule
            utmstack_rule = self._build_utmstack_rule(
                sigma_data, metadata, cel_expression, tech_category, tech_name, filter_fields
            )
            
            # Save rule if output directory specified
            saved_file = None
            if output_dir:
                saved_file = self._save_rule(utmstack_rule, output_dir, tech_category, tech_name, metadata['name'])
            
            return {
                'status': 'success',
                'sigma_file': str(sigma_file),
                'output_file': str(saved_file) if saved_file else None,
                'rule_data': utmstack_rule,
                'technology': f"{tech_category}/{tech_name}",
                'cel_expression': cel_expression,
                'filter_fields_count': len(filter_fields) if filter_fields else 0
            }
            
        except Exception as e:
            logging.error(f"Error converting Sigma rule {sigma_file}: {str(e)}")
            return {
                'status': 'error',
                'sigma_file': str(sigma_file),
                'error': str(e)
            }

    def _build_utmstack_rule(self, sigma_data: Dict[str, Any], metadata: Dict[str, Any], 
                           cel_expression: str, tech_category: str, tech_name: str, 
                           filter_fields: List[str]) -> Dict[str, Any]:
        """
        Build UTMStack rule structure from Sigma data.
        
        Args:
            sigma_data: Parsed Sigma rule data
            metadata: Extracted metadata
            cel_expression: Generated CEL expression
            tech_category: Technology category
            tech_name: Technology name
            filter_fields: Available filter fields
            
        Returns:
            UTMStack rule dictionary
        """
        # Determine data types
        data_types = self._determine_data_types(tech_category, tech_name)
        
        # Build the UTMStack rule structure
        utmstack_rule = {
            'dataTypes': data_types,
            'name': metadata['name'],
            'impact': metadata['impact'],
            'category': metadata['category'],
            'technique': metadata['technique'],
            'adversary': "UNKNOWN",
            'description': ' '.join(metadata['description'].split()),
            'references': metadata['references'],
            'where': cel_expression
        }
        
        return utmstack_rule

    def _determine_data_types(self, tech_category: str, tech_name: str) -> List[str]:
        """
        Determine appropriate dataTypes for the technology.
        Uses the exact 50 dataTypes from CorrelationRules structure.
        """
        # Map technology path to correct dataTypes
        tech_to_datatypes = {
            ('windows', 'wineventlog'): ['wineventlog'],
            ('linux', 'linux'): ['linux'],
            ('macos', 'macos'): ['macos'],
            ('aws', 'aws'): ['aws'],
            ('cloud/azure', 'azure'): ['azure'],
            ('cloud/google', 'google'): ['google'],
            ('office365', 'o365'): ['o365'],
            ('antivirus/bitdefender_gz', 'antivirus-bitdefender-gz'): ['antivirus-bitdefender-gz'],
            ('antivirus/deceptive-bytes', 'deceptive-bytes'): ['deceptive-bytes'],
            ('antivirus/esmc-eset', 'antivirus-esmc-eset'): ['antivirus-esmc-eset'],
            ('antivirus/kaspersky', 'antivirus-kaspersky'): ['antivirus-kaspersky'],
            ('antivirus/sentinel-one', 'antivirus-sentinel-one'): ['antivirus-sentinel-one'],
            ('cisco/asa', 'firewall-cisco-asa'): ['firewall-cisco-asa'],
            ('cisco/cs_switch', 'cisco-switch'): ['cisco-switch'],
            ('cisco/firepower', 'firewall-cisco-firepower'): ['firewall-cisco-firepower'],
            ('cisco/meraki', 'firewall-meraki'): ['firewall-meraki'],
            ('fortinet/fortinet', 'firewall-fortigate-traffic'): ['firewall-fortigate-traffic'],
            ('fortinet/fortiweb', 'firewall-fortiweb'): ['firewall-fortiweb'],
            ('paloalto/pa_firewall', 'firewall-paloalto'): ['firewall-paloalto'],
            ('github/github', 'github'): ['github'],
            ('generic/generic', 'generic'): ['generic'],
            ('filebeat/apache_module', 'apache'): ['apache'],
            ('filebeat/auditd_module', 'auditd'): ['auditd'],
            ('filebeat/elasticsearch_module', 'elasticsearch'): ['elasticsearch'],
            ('filebeat/haproxy_module', 'haproxy'): ['haproxy'],
            ('filebeat/iis_module', 'iis'): ['iis'],
            ('filebeat/kafka_module', 'kafka'): ['kafka'],
            ('filebeat/kibana_module', 'kibana'): ['kibana'],
            ('filebeat/logstash_module', 'logstash'): ['logstash'],
            ('filebeat/mongodb_module', 'mongodb'): ['mongodb'],
            ('filebeat/mysql_module', 'mysql'): ['mysql'],
            ('filebeat/nats_module', 'nats'): ['nats'],
            ('filebeat/nginx_module', 'nginx'): ['nginx'],
            ('filebeat/osquery_module', 'osquery'): ['osquery'],
            ('filebeat/postgresql_module', 'postgresql'): ['postgresql'],
            ('filebeat/redis_module', 'redis'): ['redis'],
            ('filebeat/system_linux_module', 'linux'): ['linux'],
            ('filebeat/traefik_module', 'traefik'): ['traefik'],
            ('mikrotik/mikrotik_fw', 'firewall-mikrotik'): ['firewall-mikrotik'],
            ('sonicwall/sonicwall_firewall', 'firewall-sonicwall'): ['firewall-sonicwall'],
            ('sophos/sophos_central', 'sophos-central'): ['sophos-central'],
            ('sophos/sophos_xg_firewall', 'firewall-sophos-xg'): ['firewall-sophos-xg'],
            ('vmware/vmware-esxi', 'vmware-esxi'): ['vmware-esxi'],
            ('syslog/cef', 'syslog'): ['syslog'],
            ('syslog/rfc-5424', 'syslog'): ['syslog'],
            ('syslog/rfc-5425', 'syslog'): ['syslog'],
            ('syslog/rfc-6587', 'syslog'): ['syslog']
        }

        # Return the mapped dataType or default based on tech_name
        return tech_to_datatypes.get((tech_category, tech_name), [tech_name])
    
    def _save_rule(self, rule_data: Dict[str, Any], output_dir: Path, 
                  tech_category: str, tech_name: str, rule_name: str) -> Path:
        """
        Save converted rule to appropriate technology directory.
        Maps directly to CorrelationRules folder structure.
        """
        # Create output directory structure using tech_category path directly
        tech_dir = output_dir / tech_category
        tech_dir.mkdir(parents=True, exist_ok=True)
        
        # Create filename from rule name
        safe_name = rule_name.lower().replace(' ', '_').replace('-', '_')
        safe_name = ''.join(c for c in safe_name if c.isalnum() or c == '_')
        filename = f"{safe_name}.yml"
        
        # Save as YAML
        output_file = tech_dir / filename
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump([rule_data], f, default_flow_style=False, 
                     allow_unicode=True, sort_keys=False, width=None, indent=2)
        
        logging.info(f"Saved converted rule to: {output_file}")
        return output_file