"""
Sigma to UTMStack SIEM Rule Converter Package

This package provides functionality to convert Sigma rules to UTMStack SIEM format.
Organized following professional software architecture patterns.
"""

__version__ = "1.0.0"
__author__ = "UTMStack Team"

from .core.sigma_parser import SigmaParser
from .core.cel_generator import CELExpressionGenerator
from .core.field_mapper import FieldMapper
from .processors.rule_converter import RuleConverter
from .processors.batch_processor import BatchProcessor
from .utils.yaml_validator import YAMLValidator
from .utils.file_handler import FileHandler

__all__ = [
    'SigmaParser',
    'CELExpressionGenerator', 
    'FieldMapper',
    'RuleConverter',
    'BatchProcessor',
    'YAMLValidator',
    'FileHandler'
]