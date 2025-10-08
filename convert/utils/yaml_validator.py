"""
YAML Validator Module

Copied functions from existing project utilities for YAML validation.
Contains functions from validate_yaml.py and fix_rules.py
"""

import argparse
import os
import yaml


def find_incorrect_yaml(root_path):
    """
    COPIED FROM: validate_yaml.py
    Find YAML files with incorrect mappings/syntax in a local directory.
    """
    print(f"Scanning for incorrect YAML mappings in: {root_path}\n")
    error_count = 0
    yaml_file_count = 0

    for subdir, _, files in os.walk(root_path):
        for file in files:
            if file.endswith((".yml", ".yaml")):
                yaml_file_count += 1
                file_path = os.path.join(subdir, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        list(yaml.safe_load_all(f))
                except yaml.YAMLError as e:
                    print(f"[ERROR] Invalid YAML file found: {file_path}")
                    print(f"  └── {e}\n")
                    error_count += 1
                except Exception as e:
                    print(f"[ERROR] Could not read or parse file: {file_path}")
                    print(f"  └── {e}\n")
                    error_count += 1

    print(
        f"Scan complete. Found {error_count} error(s) in {yaml_file_count} YAML file(s)."
    )


def fix_common_yaml_issues(content: str) -> str:
    """
    COPIED FROM: verify_correlation_rules.py
    Try to fix common YAML formatting issues
    """
    lines = content.split('\n')
    fixed_lines = []
    
    for line in lines:
        # Fix unquoted strings with colons in field values
        if ':' in line and not line.strip().startswith('-'):
            # Check if this looks like a field: value line
            parts = line.split(':', 1)
            if len(parts) == 2:
                field = parts[0]
                value = parts[1].strip()
                # If value contains a colon and isn't already quoted
                if ':' in value and not (value.startswith('"') and value.endswith('"')):
                    # Check if it's not a time or URL (those are usually ok)
                    if not value.startswith('http') and 'now-' not in value:
                        line = f'{field}: "{value}"'
        
        fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)


class YAMLValidator:
    """
    YAML validation utilities copied from existing project functions.
    """
    
    @staticmethod
    def validate_directory(directory_path: str) -> bool:
        """
        Wrapper for find_incorrect_yaml function
        """
        try:
            find_incorrect_yaml(directory_path)
            return True
        except Exception:
            return False
    
    @staticmethod
    def fix_yaml_content(content: str) -> str:
        """
        Wrapper for fix_common_yaml_issues function
        """
        return fix_common_yaml_issues(content)
    
    @staticmethod
    def validate_yaml_content(content: str) -> bool:
        """
        Validate YAML content string
        """
        try:
            yaml.safe_load(content)
            return True
        except yaml.YAMLError:
            return False
        except Exception:
            return False