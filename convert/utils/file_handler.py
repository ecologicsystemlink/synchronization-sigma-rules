"""
File Handler Module

Copied functions from existing project utilities for file operations.
Contains functions from fix_rules.py and import_utmstack_rules.py
"""

import os
import logging
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import yaml
import json
import re


def get_all_rule_files(base_dir: Path) -> List[Path]:
    """
    COPIED FROM: fix_rules.py
    Finds all .yml rule files in a directory, respecting skip lists.
    """
    rule_files = []
    skip_dirs = {"venv", ".git", "__pycache__", "filters_from_github"}
    logging.info(f"Searching for .yml files in {base_dir}, skipping {skip_dirs}...")
    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for file in files:
            if file.endswith(".yml") and not file.startswith("."):
                rule_files.append(Path(root) / file)
    logging.info(f"Found {len(rule_files)} total .yml files.")
    return sorted(rule_files)


def clone_or_update_repo(repo_url: str, local_path: Path) -> bool:
    """
    COPIED FROM: import_utmstack_rules.py
    Clone or update the UTMStack correlation rules repository
    """
    try:
        if local_path.exists():
            # Update existing repo
            logging.info(f"Updating repository at {local_path}")
            os.system(f"cd {local_path} && git pull")
        else:
            # Clone repo
            logging.info(f"Cloning repository from {repo_url}")
            os.system(f"git clone {repo_url} {local_path}")
        return True
    except Exception as e:
        logging.error(f"Failed to clone/update repository: {str(e)}")
        return False


def explore_utmstack_repo(repo_path: Path, output_file: Path) -> Dict[str, List[Path]]:
    """
    COPIED FROM: import_utmstack_rules.py
    Explore UTMStack repository structure and organize rules by technology
    """
    tech_rules = {}
    structure_lines = []
    
    # Common rule file patterns for UTMStack
    rule_extensions = {'.yml', '.yaml'}
    skip_dirs = {'.git', '__pycache__', 'docs', 'scripts', 'tests'}
    skip_files = {'README.md', '.gitignore', 'LICENSE'}
    
    structure_lines.append(f"UTMStack Repository Structure: {repo_path}")
    structure_lines.append("=" * 80)
    structure_lines.append("")
    
    # Look for technology folders in the repo
    for tech_dir in repo_path.iterdir():
        if tech_dir.is_dir() and tech_dir.name not in skip_dirs:
            tech_name = tech_dir.name
            tech_rules[tech_name] = []
            structure_lines.append(f"{tech_name}/")
            
            # Find rule files in technology directory
            for rule_file in tech_dir.rglob("*.yml"):
                if rule_file.name not in skip_files:
                    tech_rules[tech_name].append(rule_file)
                    structure_lines.append(f"  - {rule_file.relative_to(tech_dir)}")
    
    # Write structure to file
    total_rules = sum(len(rules) for rules in tech_rules.values())
    with open(output_file, 'w') as f:
        f.write('\n'.join(structure_lines))
        f.write(f"\n\nTotal technologies: {len(tech_rules)}\n")
        f.write(f"Total rule files: {total_rules}\n\n")
        
        for tech, rules in tech_rules.items():
            f.write(f"\n{tech}: {len(rules)} rules\n")
    
    logging.info(f"Repository structure saved to: {output_file}")
    logging.info(f"Found {len(tech_rules)} technologies with {total_rules} total rules")
    
    return tech_rules


def detect_rule_format(file_path: Path) -> str:
    """
    COPIED FROM: import_utmstack_rules.py
    Try to detect the format of a rule file
    """
    content = file_path.read_text(encoding='utf-8', errors='ignore')
    
    # Check for various rule formats
    if file_path.suffix in ['.yml', '.yaml']:
        if 'detection:' in content or 'logsource:' in content:
            return "sigma"
        elif 'rule:' in content or 'alert:' in content:
            return "suricata"
        else:
            return "yaml_generic"
    elif file_path.suffix == '.json':
        return "json_generic"
    elif 'alert' in content and 'msg:' in content:
        return "snort"
    elif '<rule' in content.lower() and '</rule>' in content.lower():
        return "xml_wazuh"
    else:
        return "unknown"


def get_technology_from_path(file_path: Path) -> Tuple[str, str]:
    """
    COPIED FROM: import_utmstack_rules.py
    Try to determine technology from file path and content
    """
    parts = file_path.parts
    file_name = file_path.stem.lower()
    
    # Read first few lines to look for technology hints
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content_preview = f.read(1000).lower()
    except:
        content_preview = ""
    
    # Comprehensive technology mapping
    tech_mappings = {
        # Antivirus
        ('bitdefender', 'antivirus', 'bitdefender_gz'),
        ('kaspersky', 'antivirus', 'kaspersky'),
        ('eset', 'antivirus', 'esmc-eset'),
        ('sentinel', 'antivirus', 'sentinel-one'),
        ('crowdstrike', 'antivirus', 'crowdstrike'),
        ('defender', 'antivirus', 'windows-defender'),
        
        # Cloud
        ('aws', 'aws', 'aws'),
        ('cloudtrail', 'aws', 'aws'),
        ('azure', 'cloud', 'azure'),
        ('gcp', 'cloud', 'google'),
        ('google cloud', 'cloud', 'google'),
        
        # Network devices
        ('cisco', 'cisco', 'asa'),
        ('asa', 'cisco', 'asa'),
        ('firepower', 'cisco', 'firepower'),
        ('meraki', 'cisco', 'meraki'),
        ('fortinet', 'fortinet', 'fortinet'),
        ('fortigate', 'fortinet', 'fortinet'),
        ('paloalto', 'paloalto', 'pa_firewall'),
        ('pan-os', 'paloalto', 'pa_firewall'),
        
        # Operating systems
        ('windows', 'windows', 'windows'),
        ('event id', 'windows', 'windows'),
        ('linux', 'linux', 'debian_family'),
        ('ubuntu', 'linux', 'debian_family'),
        ('centos', 'linux', 'rhel_family'),
        ('redhat', 'linux', 'rhel_family'),
        ('macos', 'macos', 'macos'),
        
        # Security tools
        ('suricata', 'nids', 'nids'),
        ('snort', 'nids', 'nids'),
        ('wazuh', 'hids', 'hids'),
        ('ossec', 'hids', 'hids'),
        
        # Applications
        ('apache', 'filebeat', 'apache_module'),
        ('nginx', 'filebeat', 'nginx_module'),
        ('mysql', 'filebeat', 'mysql_module'),
        ('postgresql', 'filebeat', 'postgresql_module'),
        ('elasticsearch', 'filebeat', 'elasticsearch_module'),
    }
    
    # Check file path and content for technology indicators
    combined_text = ' '.join(parts).lower() + ' ' + file_name + ' ' + content_preview
    
    for indicator, category, tech_name in tech_mappings:
        if indicator in combined_text:
            return category, tech_name
    
    # Fallback to path-based detection
    for i, part in enumerate(parts):
        part_lower = part.lower()
        if part_lower in ['antivirus', 'firewall', 'ids', 'siem', 'windows', 'linux', 'network']:
            if i + 1 < len(parts):
                return part_lower, parts[i + 1]
            else:
                return part_lower, "generic"
    
    return "generic", "generic"


def get_existing_rules_for_technology(tech_category: str, tech_name: str, base_dir: Path) -> List[Path]:
    """
    COPIED FROM: import_utmstack_rules.py
    Get all existing rules for a technology in the local project
    """
    local_tech_path = base_dir / tech_category / tech_name
    if local_tech_path.exists():
        return list(local_tech_path.glob("*.yml"))
    return []


def get_file_hash(file_path: Path) -> str:
    """
    COPIED FROM: verify_correlation_rules.py
    Calculate SHA256 hash of a file
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def get_file_content(file_path: Path) -> str:
    """
    COPIED FROM: verify_correlation_rules.py
    Read file content
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()


class FileHandler:
    """
    File handling utilities copied from existing project functions.
    """
    
    @staticmethod
    def get_rule_files(directory: Path) -> List[Path]:
        """Wrapper for get_all_rule_files"""
        return get_all_rule_files(directory)
    
    @staticmethod
    def detect_format(file_path: Path) -> str:
        """Wrapper for detect_rule_format"""
        return detect_rule_format(file_path)
    
    @staticmethod
    def get_technology_info(file_path: Path) -> Tuple[str, str]:
        """Wrapper for get_technology_from_path"""
        return get_technology_from_path(file_path)
    
    @staticmethod
    def calculate_hash(file_path: Path) -> str:
        """Wrapper for get_file_hash"""
        return get_file_hash(file_path)
    
    @staticmethod
    def read_content(file_path: Path) -> str:
        """Wrapper for get_file_content"""
        return get_file_content(file_path)

    @staticmethod
    def create_analysis_prompt(rule_file: Path, tech_name: str, existing_rules: List[Path]) -> str:
        """
        Create a detailed prompt for analyzing and potentially importing a Sigma rule
        for conversion to UTMStack format
        """
        prompt = f"""You are tasked with analyzing a Sigma rule and determining if it should be converted to UTMStack format.

IMPORTANT: Follow these analysis steps EXACTLY:

1. Read the Sigma rule file: {rule_file}

2. Analyze the rule to understand:
   - What threat/attack it detects
   - The core detection logic in the 'detection' section
   - Key fields and conditions used
   - MITRE ATT&CK techniques referenced

3. Check if a similar rule already exists locally by:
   - Reading each existing converted rule file for this technology
   - Comparing the detection logic and purpose
   - Looking for rules that detect the same threat/pattern
   
   Existing rules for {tech_name}:
   {chr(10).join(f'   - {r.name}' for r in existing_rules) if existing_rules else '   - No existing rules'}

4. DECISION POINT:
   - If a rule with the same functionality exists: STOP and report "DUPLICATE: [existing_rule_name]"
   - If no similar rule exists: PROCEED to convert the rule

5. If converting (no duplicate exists), follow these standards:
   - Map Sigma detection logic to CEL expressions
   - Use field mappings from filter_fields_output.txt
   - Follow patterns from standarConversion.txt
   - Generate appropriate UTMStack rule structure

6. For the conversion:
   - Convert 'selection' blocks to CEL where clauses
   - Map field names to UTMStack log structure
   - Preserve detection logic accuracy
   - Add appropriate metadata (category, technique, impact scores)

Return your analysis and conversion recommendation."""
        
        return prompt