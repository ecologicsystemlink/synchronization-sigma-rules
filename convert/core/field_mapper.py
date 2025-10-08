"""
Technology Mapping Module

Copied functions from existing project utilities for technology mapping.
Contains functions from generate_correlation_rules.py and import_utmstack_rules.py
"""

import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional


def get_technology_mappings() -> Dict[str, List[Tuple[str, str]]]:
    """
    COPIED FROM: generate_correlation_rules.py
    Returns a mapping of technology folders to their subdirectories and corresponding filters
    """
    return {
        "antivirus": [
            ("bitdefender_gz", "filters_from_github/antivirus/bitdefender_gz.yml"),
            ("sentinel-one", "filters_from_github/antivirus/sentinel-one.yml"),
            ("kaspersky", "filters_from_github/antivirus/kaspersky.yml"),
            ("esmc-eset", "filters_from_github/antivirus/esmc-eset.yml"),
            (
                "deceptive-bytes",
                "filters_from_github/deceptivebytes/deceptive-bytes.yml",
            ),
        ],
        "aws": [("aws", "filters_from_github/aws/aws.yml")],
        "cisco": [
            ("asa", None),  # No filter file found
            ("cs_switch", None),  # No filter file found
            ("firepower", None),  # No filter file found
            ("meraki", None),  # No filter file found
        ],
        "cloud": [
            ("azure", "filters_from_github/azure/azure-eventhub.yml"),
            ("google", "filters_from_github/google/gcp.yml"),
        ],
        "filebeat": [
            ("apache_module", "filters_from_github/filebeat/apache_module.yml"),
            ("auditd_module", "filters_from_github/filebeat/auditd_module.yml"),
            (
                "elasticsearch_module",
                "filters_from_github/filebeat/elasticsearch_module.yml",
            ),
            ("haproxy_module", "filters_from_github/filebeat/haproxy_module.yml"),
            ("iis_module", "filters_from_github/filebeat/iis_module.yml"),
            ("kafka_module", "filters_from_github/filebeat/kafka_module.yml"),
            ("kibana_module", "filters_from_github/filebeat/kibana_module.yml"),
            ("logstash_module", "filters_from_github/filebeat/logstash_module.yml"),
            ("mongodb_module", "filters_from_github/filebeat/mongodb_module.yml"),
            ("mysql_module", "filters_from_github/filebeat/mysql_module.yml"),
            ("nats_module", "filters_from_github/filebeat/nats_module.yml"),
            ("nginx_module", "filters_from_github/filebeat/nginx_module.yml"),
            ("osquery_module", "filters_from_github/filebeat/osquery_module.yml"),
            ("postgresql_module", "filters_from_github/filebeat/postgresql_module.yml"),
            ("redis_module", "filters_from_github/filebeat/redis_module.yml"),
            (
                "system_linux_module",
                "filters_from_github/filebeat/system_linux_module.yml",
            ),
            ("traefik_module", "filters_from_github/filebeat/traefik_module.yml"),
        ],
        "fortinet": [
            ("fortinet", "filters_from_github/fortinet/fortinet.yml"),
            ("fortiweb", "filters_from_github/fortinet/fortiweb.yml"),
        ],
        "generic": [("generic", "filters_from_github/generic/generic.yml")],
        "github": [("github", "filters_from_github/github/github.yml")],
        "ibm": [
            ("ibm_aix", "filters_from_github/ibm/ibm_aix.yml"),
            ("ibm_as_400", "filters_from_github/ibm/ibm_as_400.yml"),
        ],
        "json": [("json-input", "filters_from_github/json/json-input.yml")],
        "linux": [
            ("debian_family", None),  # No specific filter, will use system_linux_module
            ("rhel_family", None),  # No specific filter, will use system_linux_module
        ],
        "macos": [("macos", "filters_from_github/macos/macos.yml")],
        "mikrotik": [("mikrotik_fw", "filters_from_github/mikrotik/mikrotik-fw.yml")],
        "netflow": [("netflow", "filters_from_github/netflow/netflow.yml")],
        "office365": [("office365", "filters_from_github/office365/o365.yml")],
        "paloalto": [("pa_firewall", "filters_from_github/paloalto/pa_firewall.yml")],
        "pfsense": [("pfsense", "filters_from_github/pfsense/pfsense_fw.yml")],
        "sonicwall": [
            ("sonicwall_firewall", "filters_from_github/sonicwall/sonic_wall.yml")
        ],
        "sophos": [
            ("sophos_central", "filters_from_github/sophos/sophos_central.yml"),
            ("sophos_xg_firewall", "filters_from_github/sophos/sophos_xg_firewall.yml"),
        ],
        "syslog": [
            ("cef", None),  # Will use generic syslog
            ("rfc-5424", None),  # Will use generic syslog
            ("rfc-5425", None),  # Will use generic syslog
            ("rfc-6587", None),  # Will use generic syslog
        ],
        "vmware": [("vmware-esxi", "filters_from_github/vmware/vmware-esxi.yml")],
        "windows": [("windows", "filters_from_github/windows/windows-events.yml")],
        "hids": [("hids", None)],  # No specific filter file
        "nids": [("nids", None)],  # No specific filter file
    }


def get_filter_fields_for_technology(tech_category: str, tech_name: str, base_dir: Path) -> Tuple[Optional[str], List[str]]:
    """
    COPIED FROM: verify_correlation_rules.py
    Get the filter fields for a given technology from the filter_fields_output.txt file
    Returns: (filter_file_name, list_of_fields)
    """
    tech_mappings = get_technology_mappings()
    filter_file_name = None
    
    # Find the filter path for this technology
    if tech_category in tech_mappings:
        for tech, filter_path in tech_mappings[tech_category]:
            if tech == tech_name and filter_path:
                filter_file_name = filter_path
                break
    
    # Fallback to manual mappings for any missing ones
    if not filter_file_name:
        filter_mappings = {
            ("antivirus", "bitdefender_gz"): "filters_from_github/antivirus/bitdefender_gz.yml",
            ("antivirus", "sentinel-one"): "filters_from_github/antivirus/sentinel-one.yml",
            ("antivirus", "kaspersky"): "filters_from_github/antivirus/kaspersky.yml",
            ("antivirus", "esmc-eset"): "filters_from_github/antivirus/esmc-eset.yml",
            ("antivirus", "deceptive-bytes"): "filters_from_github/deceptivebytes/deceptive-bytes.yml",
            ("aws", "aws"): "filters_from_github/aws/aws.yml",
            ("cloud", "azure"): "filters_from_github/azure/azure-eventhub.yml",
            ("cloud", "google"): "filters_from_github/google/gcp.yml",
        }
        filter_file_name = filter_mappings.get((tech_category, tech_name))
    
    if not filter_file_name:
        return None, []
    
    # Extract just the relative path from filters_from_github
    if 'filters_from_github/' in filter_file_name:
        search_name = filter_file_name.split('filters_from_github/')[-1]
    else:
        search_name = filter_file_name
    
    # Remove ./ prefix if present
    if search_name.startswith('./'):
        search_name = search_name[2:]
    
    # Read the filter fields from the output file
    fields = []
    filter_fields_file = base_dir / "filter_fields_output.txt"
    
    if not filter_fields_file.exists():
        logging.warning(f"Filter fields output file not found: {filter_fields_file}")
        return filter_file_name, []
    
    try:
        with open(filter_fields_file, 'r') as f:
            content = f.read()
        
        # Find the section for this filter file by looking for the exact file line
        file_marker = f"File: {search_name}"
        if file_marker in content:
            # Find the position of this file marker
            start_pos = content.find(file_marker)
            # Find the next file marker (or end of file)
            next_file_pos = content.find("\nFile:", start_pos + 1)
            if next_file_pos == -1:
                section = content[start_pos:]
            else:
                section = content[start_pos:next_file_pos]
            
            # Extract fields from this section
            lines = section.split('\n')
            in_fields_section = False
            for line in lines:
                if line.strip() == "Fields created:":
                    in_fields_section = True
                elif line.strip() == "Dynamic fields from JSON parsing:":
                    # We'll continue collecting fields but skip dynamic indicators
                    continue
                elif line.strip().startswith("=") and in_fields_section:
                    # End of section
                    break
                elif in_fields_section and line.strip().startswith("- "):
                    field = line.strip()[2:]  # Remove "- " prefix
                    if not field.startswith("*"):  # Skip dynamic field indicators
                        fields.append(field)
                
    except Exception as e:
        logging.error(f"Error reading filter fields: {e}")
        
    return filter_file_name, fields


def map_repo_tech_to_local(repo_tech: str) -> Tuple[str, str]:
    """
    COPIED FROM: import_utmstack_rules.py
    Map repository technology name to local category and technology
    """
    # Mapping from repo names to local structure
    tech_mappings = {
        # Direct mappings
        'aws': ('aws', 'aws'),
        'azure': ('cloud', 'azure'),
        'gcp': ('cloud', 'google'),
        'windows': ('windows', 'windows'),
        'linux': ('linux', 'debian_family'),
        'macos': ('macos', 'macos'),
        'office365': ('office365', 'office365'),
        'github': ('github', 'github'),
        
        # Network devices
        'cisco': ('cisco', 'asa'),
        'cisco-asa': ('cisco', 'asa'),
        'cisco-firepower': ('cisco', 'firepower'),
        'fortinet': ('fortinet', 'fortinet'),
        'paloalto': ('paloalto', 'pa_firewall'),
        'sonicwall': ('sonicwall', 'sonicwall_firewall'),
        'pfsense': ('pfsense', 'pfsense'),
        
        # Antivirus
        'bitdefender': ('antivirus', 'bitdefender_gz'),
        'kaspersky': ('antivirus', 'kaspersky'),
        'eset': ('antivirus', 'esmc-eset'),
        'sentinelone': ('antivirus', 'sentinel-one'),
        
        # Security tools
        'wazuh': ('hids', 'hids'),
        'suricata': ('nids', 'nids'),
        'snort': ('nids', 'nids'),
    }
    
    # Try exact match first
    if repo_tech.lower() in tech_mappings:
        return tech_mappings[repo_tech.lower()]
    
    # Try partial matches
    for key, value in tech_mappings.items():
        if key in repo_tech.lower() or repo_tech.lower() in key:
            return value
    
    # Default to generic
    return ('generic', 'generic')


def extract_technology_from_path(file_path: Path, base_dir: Path) -> Tuple[str, str]:
    """
    COPIED FROM: verify_correlation_rules.py
    Extract technology category and name from file path
    """
    parts = file_path.relative_to(base_dir).parts
    if len(parts) >= 2:
        return parts[0], parts[1]
    return "unknown", "unknown"


class FieldMapper:
    """
    Field mapping utilities copied from existing project functions.
    """
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.tech_mappings = get_technology_mappings()
    
    def get_technology_mapping(self) -> Dict[str, List[Tuple[str, str]]]:
        """Get technology mappings"""
        return self.tech_mappings
    
    def get_filter_fields(self, tech_category: str, tech_name: str) -> Tuple[Optional[str], List[str]]:
        """Get filter fields for technology"""
        return get_filter_fields_for_technology(tech_category, tech_name, self.base_dir)
    
    def map_repository_tech(self, repo_tech: str) -> Tuple[str, str]:
        """Map repository technology to local structure"""
        return map_repo_tech_to_local(repo_tech)
    
    def extract_tech_from_path(self, file_path: Path) -> Tuple[str, str]:
        """Extract technology from file path"""
        return extract_technology_from_path(file_path, self.base_dir)