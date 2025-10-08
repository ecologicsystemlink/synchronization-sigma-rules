"""
Sigma to UTMStack SIEM Rule Converter

This package converts Sigma detection rules to UTMStack SIEM correlation rules.
It uses sigma-cli for initial conversion and applies UTMStack-specific post-processing
to ensure compatibility with the UTMStack Event structure and CEL expressions.
"""

__version__ = "1.0.0"
__author__ = "JocLRojas"

from .core.sigma_parser import SigmaParser
from .core.field_mapper import FieldMapper
from .processors.rule_converter import RuleConverter
from .processors.batch_processor import BatchProcessor
from .utils.yaml_validator import YAMLValidator
from .utils.file_handler import FileHandler

__all__ = [
    'SigmaParser',
    'FieldMapper',
    'RuleConverter',
    'BatchProcessor',
    'YAMLValidator',
    'FileHandler'
]