"""
Batch Rule Processor

Handles batch conversion of multiple Sigma rules with progress tracking,
error handling, and resume capabilities for large-scale processing operations.
"""

import asyncio
import logging
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from ..core.sigma_parser import SigmaParser
from ..processors.rule_converter import RuleConverter
from ..utils.file_handler import FileHandler
from ..utils.yaml_validator import YAMLValidator


def save_execution_state(state_file: Path, tech_name: str, status: str, files_created: int = 0):
    """
    Save execution state for progress tracking and issue detection.
    
    Args:
        state_file: Path to state file
        tech_name: Technology name being processed
        status: Current status ('success', 'error', etc.)
        files_created: Number of files created
    """
    state = {}
    if state_file.exists():
        try:
            with open(state_file, "r") as f:
                state = json.load(f)
        except:
            state = {}

    if tech_name not in state:
        state[tech_name] = []

    state[tech_name].append(
        {
            "timestamp": datetime.now().isoformat(),
            "status": status,
            "files_created": files_created,
        }
    )

    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)


def load_progress(progress_file: Path) -> tuple[List[str], Optional[str]]:
    """
    Load conversion progress from JSON file.
    
    Args:
        progress_file: Path to progress tracking file
        
    Returns:
        Tuple of (completed_files, last_current_file)
    """
    if progress_file.exists():
        try:
            with open(progress_file, 'r') as f:
                data = json.load(f)
            return data.get('completed_files', []), data.get('current_file')
        except Exception as e:
            logging.warning(f"Could not load progress file: {e}")
    return [], None


def save_progress(progress_file: Path, completed_files: List[str], current_file: str = None):
    """
    Save conversion progress to JSON file.
    
    Args:
        progress_file: Path to progress tracking file
        completed_files: List of completed file paths
        current_file: Currently processing file path
    """
    progress_data = {
        'timestamp': datetime.now().isoformat(),
        'completed_files': completed_files,
        'current_file': current_file,
        'total_completed': len(completed_files)
    }
    with open(progress_file, 'w') as f:
        json.dump(progress_data, f, indent=2)
    logging.debug(f"Progress saved: {len(completed_files)} files completed")


class BatchProcessor:
    """
    Processes multiple Sigma rules in batch operations.
    Uses existing project utilities for progress tracking and file handling.
    """
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.sigma_parser = SigmaParser()
        self.rule_converter = RuleConverter(base_dir)
        self.file_handler = FileHandler()
        self.yaml_validator = YAMLValidator()
        
        # Progress tracking
        self.progress_file = base_dir / "conversion_progress.json"
        self.state_file = base_dir / "conversion_state.json"
    
    async def process_sigma_directory(self, sigma_dir: Path, output_dir: Path, 
                                    resume: bool = False, limit: int = 0) -> Dict[str, Any]:
        """
        Process all Sigma rules in a directory.
        
        Args:
            sigma_dir: Directory containing Sigma rule files
            output_dir: Directory to save converted rules
            resume: Whether to resume from previous progress
            limit: Maximum number of rules to process (0 = no limit)
            
        Returns:
            Dictionary with processing results
        """
        logging.info(f"Starting batch processing of Sigma rules from: {sigma_dir}")
        
        # Get all Sigma rule files
        sigma_files = self.sigma_parser.get_sigma_files_from_directory(sigma_dir)
        total_files = len(sigma_files)
        
        if total_files == 0:
            logging.warning(f"No Sigma rule files found in: {sigma_dir}")
            return {'status': 'error', 'message': 'No Sigma files found'}
        
        logging.info(f"Found {total_files} Sigma rule files")
        
        # Apply limit if specified
        if limit > 0:
            sigma_files = sigma_files[:limit]
            logging.info(f"Processing limited to {limit} files")
        
        # Load progress if resuming
        completed_files = []
        if resume:
            completed_files, last_file = load_progress(self.progress_file)
            if completed_files:
                logging.info(f"Resuming from previous run. Already completed: {len(completed_files)} files")
                # Filter out completed files
                completed_set = set(completed_files)
                sigma_files = [f for f in sigma_files if str(f.relative_to(sigma_dir)) not in completed_set]
                logging.info(f"Remaining files to process: {len(sigma_files)}")
        
        # Process files
        results = {
            'total_found': total_files,
            'processed': 0,
            'successful': 0,
            'failed': 0,
            'skipped': 0,
            'conversions': [],
            'errors': []
        }
        
        for idx, sigma_file in enumerate(sigma_files, 1):
            logging.info(f"Processing {idx}/{len(sigma_files)}: {sigma_file.name}")
            
            try:
                # Save current progress
                save_progress(self.progress_file, completed_files, str(sigma_file.relative_to(sigma_dir)))
                
                # Convert the rule
                conversion_result = self.rule_converter.convert_sigma_rule(sigma_file, output_dir)
                
                results['processed'] += 1
                
                if conversion_result['status'] == 'success':
                    results['successful'] += 1
                    logging.info(f"✓ Successfully converted: {sigma_file.name}")
                else:
                    results['failed'] += 1
                    logging.error(f"✗ Failed to convert: {sigma_file.name}")
                    results['errors'].append(conversion_result)
                
                results['conversions'].append(conversion_result)
                
                # Add to completed files
                completed_files.append(str(sigma_file.relative_to(sigma_dir)))
                
                # Save state
                if conversion_result['status'] == 'success':
                    save_execution_state(self.state_file, conversion_result.get('technology', 'unknown'), 
                                       'success', 1)
                else:
                    save_execution_state(self.state_file, 'unknown', 'error', 0)
                
                # Progress update every 10 files
                if idx % 10 == 0:
                    save_progress(self.progress_file, completed_files)
                    logging.info(f"Progress: {idx}/{len(sigma_files)} files processed")
                
                # Small delay to avoid overwhelming the system
                await asyncio.sleep(0.1)
                
            except Exception as e:
                logging.error(f"Exception processing {sigma_file}: {str(e)}")
                results['failed'] += 1
                results['errors'].append({
                    'file': str(sigma_file),
                    'error': str(e)
                })
        
        # Final progress save
        save_progress(self.progress_file, completed_files)
        
        # Generate summary
        results['completion_time'] = datetime.now().isoformat()
        results['success_rate'] = (results['successful'] / results['processed']) * 100 if results['processed'] > 0 else 0
        
        logging.info(f"Batch processing completed:")
        logging.info(f"  Total processed: {results['processed']}")
        logging.info(f"  Successful: {results['successful']}")
        logging.info(f"  Failed: {results['failed']}")
        logging.info(f"  Success rate: {results['success_rate']:.1f}%")
        
        return results
    
    def process_single_file(self, sigma_file: Path, output_dir: Path) -> Dict[str, Any]:
        """
        Process a single Sigma rule file.
        
        Args:
            sigma_file: Path to Sigma rule file
            output_dir: Directory to save converted rule
            
        Returns:
            Dictionary with processing results
        """
        logging.info(f"Processing single file: {sigma_file}")
        
        try:
            # Validate the file first
            if not self.yaml_validator.validate_yaml_content(sigma_file.read_text()):
                return {
                    'status': 'error',
                    'file': str(sigma_file),
                    'error': 'Invalid YAML content'
                }
            
            # Convert the rule
            result = self.rule_converter.convert_sigma_rule(sigma_file, output_dir)
            
            if result['status'] == 'success':
                logging.info(f"✓ Successfully converted: {sigma_file.name}")
            else:
                logging.error(f"✗ Failed to convert: {sigma_file.name}")
            
            return result
            
        except Exception as e:
            logging.error(f"Exception processing {sigma_file}: {str(e)}")
            return {
                'status': 'error',
                'file': str(sigma_file),
                'error': str(e)
            }
    
    def validate_conversions(self, output_dir: Path) -> Dict[str, Any]:
        """
        Validate all converted rules in the output directory.
        
        Args:
            output_dir: Directory containing converted rules
            
        Returns:
            Dictionary with validation results
        """
        logging.info(f"Validating converted rules in: {output_dir}")
        
        # Get all converted rule files
        rule_files = self.file_handler.get_rule_files(output_dir)
        
        results = {
            'total_files': len(rule_files),
            'valid': 0,
            'invalid': 0,
            'errors': []
        }
        
        for rule_file in rule_files:
            try:
                # Validate YAML syntax
                if self.yaml_validator.validate_yaml_content(rule_file.read_text()):
                    results['valid'] += 1
                else:
                    results['invalid'] += 1
                    results['errors'].append({
                        'file': str(rule_file),
                        'error': 'Invalid YAML syntax'
                    })
            except Exception as e:
                results['invalid'] += 1
                results['errors'].append({
                    'file': str(rule_file),
                    'error': str(e)
                })
        
        logging.info(f"Validation completed: {results['valid']}/{results['total_files']} files valid")
        
        return results
    
    def clear_progress(self):
        """
        Clear progress and state files.
        """
        for file_path in [self.progress_file, self.state_file]:
            if file_path.exists():
                file_path.unlink()
                logging.info(f"Cleared: {file_path}")
    
    def get_progress_info(self) -> Dict[str, Any]:
        """
        Get current progress information.
        """
        progress_info = {'has_progress': False}
        
        if self.progress_file.exists():
            completed_files, current_file = load_progress(self.progress_file)
            progress_info.update({
                'has_progress': True,
                'completed_count': len(completed_files),
                'current_file': current_file,
                'completed_files': completed_files
            })
        
        return progress_info