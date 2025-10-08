"""
YAML Validation Utilities

Provides validation functions for YAML content to ensure
proper syntax before processing Sigma rules.
"""

import yaml


class YAMLValidator:
    """
    Provides YAML content validation utilities.
    """
    
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