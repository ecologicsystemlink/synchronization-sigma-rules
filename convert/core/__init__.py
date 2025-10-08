"""
Core components for Sigma rule conversion.

Contains the main parsing and conversion logic.
"""

from .sigma_parser import SigmaParser
from .sigma_cli_integration import SigmaCLIIntegration
from .field_mapper import FieldMapper

__all__ = ['SigmaParser', 'SigmaCLIIntegration', 'FieldMapper']