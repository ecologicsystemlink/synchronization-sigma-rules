#!/usr/bin/env python3
"""
Conversion Entry Point Script

This script is called by the GitHub Actions workflow to convert modified Sigma rules.
"""

import sys
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Add the convert module to the path
sys.path.insert(0, str(Path(__file__).parent))

from convert.convert import convert_rules_batch


def main():
    """
    Main entry point for the conversion script.
    """
    if len(sys.argv) != 2:
        print("Usage: python convert.py <modified_files_list>")
        sys.exit(1)
    
    modified_files_path = Path(sys.argv[1])
    base_dir = Path(__file__).parent
    
    if not modified_files_path.exists():
        logging.error(f"Modified files list not found: {modified_files_path}")
        sys.exit(1)
    
    # Read the list of modified files
    try:
        with open(modified_files_path, 'r') as f:
            modified_files = [line.strip() for line in f if line.strip()]
    except Exception as e:
        logging.error(f"Error reading modified files list: {e}")
        sys.exit(1)
    
    if not modified_files:
        logging.info("No files to process")
        return
    
    # Convert the rules
    try:
        # Set output directory to base directory (CorrelationRules repo root)
        output_dir = base_dir
        
        logging.info(f"Processing {len(modified_files)} modified files")
        
        # Call the batch conversion
        results = convert_rules_batch(
            sigma_files=modified_files,
            output_dir=output_dir,
            base_dir=base_dir
        )
        
        successful_results = [r for r in results if r['status'] == 'success']
        
        successful = len(successful_results)
        failed = len(results) - successful
        
        print(f"\nSummary: {successful} successful, {failed} failed out of {len(modified_files)} files processed")
        logging.info(f"Conversion completed: {successful} successful, {failed} failed")
        
        if failed > 0:
            logging.warning("Some conversions failed:")
            for result in results:
                if result['status'] == 'error':
                    logging.warning(f"  - {result['sigma_file']}: {result['error']}")
    
    except Exception as e:
        logging.error(f"Conversion process failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()