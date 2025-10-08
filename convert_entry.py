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
        
        # Show first 5 converted rules for debugging
        successful_results = [r for r in results if r['status'] == 'success']
        if successful_results:
            print("\n" + "="*80)
            print("PRIMERAS 5 REGLAS CONVERTIDAS")
            print("="*80)
            
            for i, result in enumerate(successful_results[:5], 1):
                print(f"\n[{i}] {result['sigma_file']}")
                print(f"    Tecnología: {result.get('technology', 'N/A')}")
                print(f"    CEL: {result.get('cel_expression', 'N/A')[:100]}...")
                
                if 'rule_data' in result:
                    import yaml
                    yaml_output = yaml.dump([result['rule_data']], 
                                          default_flow_style=False, 
                                          allow_unicode=True, 
                                          sort_keys=False, 
                                          width=120, 
                                          indent=2)
                    print("    Contenido:")
                    for line in yaml_output.split('\n')[:20]:  # Limit to first 20 lines
                        print(f"      {line}")
                    if len(yaml_output.split('\n')) > 20:
                        print("      ... (contenido truncado)")
            
            print("="*80)
        
        # Log results
        successful = len(successful_results)
        failed = len(results) - successful
        
        print(f"\nRESUMEN: {successful} exitosas, {failed} fallidas de {len(modified_files)} archivos procesados")
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