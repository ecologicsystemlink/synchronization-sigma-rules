"""
File Handling Utilities

Provides file discovery and validation functions for rule processing.
Handles YAML file enumeration while respecting exclusion patterns.
"""

import os
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import yaml
import json
import re


def get_all_rule_files(base_dir: Path) -> List[Path]:
    """
    Find all YAML rule files in a directory tree.
    
    Args:
        base_dir: Base directory to search
        
    Returns:
        Sorted list of YAML file paths
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


class FileHandler:
    """
    Provides file discovery and validation utilities for rule processing.
    """
    
    @staticmethod
    def get_rule_files(directory: Path) -> List[Path]:
        """Wrapper for get_all_rule_files"""
        return get_all_rule_files(directory)