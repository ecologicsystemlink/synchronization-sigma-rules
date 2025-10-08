#!/usr/bin/env python3
"""
Sigma to UTMStack SIEM Rule Converter

Command-line interface for converting Sigma detection rules to UTMStack SIEM format.
Supports single file conversion, batch processing, and validation operations.

Usage:
    python convert.py --input sigma_rules/ --output converted_rules/
    python convert.py --file sigma_rule.yml --output converted_rules/
    python convert.py --batch sigma_rules/ --output converted_rules/ --resume
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# Import the conversion components
from .core.sigma_parser import SigmaParser
from .core.sigma_cli_integration import SigmaCLIIntegration
from .core.field_mapper import FieldMapper
from .processors.rule_converter import RuleConverter
from .processors.batch_processor import BatchProcessor
from .utils.yaml_validator import YAMLValidator
from .utils.file_handler import FileHandler


def setup_logging(verbose: bool = False):
    """
    Configure logging for the converter.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('sigma_conversion.log')
        ]
    )


async def main():
    """
    Main entry point for the Sigma rule converter.
    """
    parser = argparse.ArgumentParser(
        description='Convert Sigma rules to UTMStack SIEM format',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Input options
    parser.add_argument('--input', '-i', type=str, help='Input directory containing Sigma rules')
    parser.add_argument('--file', '-f', type=str, help='Single Sigma rule file to convert')
    parser.add_argument('--output', '-o', type=str, required=True, help='Output directory for converted rules')
    
    # Processing options
    parser.add_argument('--batch', action='store_true', help='Process all files in batch mode')
    parser.add_argument('--resume', '-r', action='store_true', help='Resume from previous progress')
    parser.add_argument('--limit', '-l', type=int, default=0, help='Limit number of files to process (0 = no limit)')
    
    # Utility options
    parser.add_argument('--validate', action='store_true', help='Validate converted rules')
    parser.add_argument('--clear-progress', action='store_true', help='Clear previous progress')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    # Test options
    parser.add_argument('--test-cel', type=str, help='Test CEL generation with a simple expression')
    parser.add_argument('--dry-run', action='store_true', help='Perform dry run without saving files')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    logger.info("="*80)
    logger.info("Sigma to UTMStack SIEM Rule Converter")
    logger.info("="*80)
    
    # Validate arguments
    if not args.file and not args.input and not args.test_cel and not args.validate:
        logger.error("Must specify either --input directory, --file, --test-cel, or --validate")
        return 1
    
    # Get base directory (project root)
    base_dir = Path(__file__).parent.parent
    output_dir = Path(args.output)
    
    # Initialize components
    batch_processor = BatchProcessor(base_dir)
    rule_converter = RuleConverter(base_dir)
    sigma_cli = SigmaCLIIntegration()
    yaml_validator = YAMLValidator()
    
    try:
        # Handle different operation modes
        if args.test_cel:
            # Test CEL generation
            logger.info(f"Testing Sigma-CLI integration: {args.test_cel}")
            # Create a temporary test rule for sigma-cli
            test_rule_content = f"""
title: Test Rule
status: experimental
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: {args.test_cel}
    condition: selection
"""
            # Save test rule temporarily
            test_file = base_dir / "test_rule.yml"
            try:
                with open(test_file, 'w') as f:
                    f.write(test_rule_content)
                
                # Test sigma-cli integration
                test_expression = sigma_cli.convert_sigma_rule(test_file)
                logger.info(f"Generated CEL: {test_expression}")
                
                # Clean up
                test_file.unlink()
                
            except Exception as e:
                logger.error(f"Test failed: {e}")
                if test_file.exists():
                    test_file.unlink()
                return 1
            
            return 0
        
        elif args.validate:
            # Validate converted rules
            logger.info("Validating converted rules...")
            results = batch_processor.validate_conversions(output_dir)
            logger.info(f"Validation results: {results['valid']}/{results['total_files']} files valid")
            if results['errors']:
                logger.error("Validation errors found:")
                for error in results['errors']:
                    logger.error(f"  {error['file']}: {error['error']}")
            return 0 if results['invalid'] == 0 else 1
        
        elif args.clear_progress:
            # Clear progress
            batch_processor.clear_progress()
            logger.info("Progress cleared")
            return 0
        
        elif args.file:
            # Convert single file
            sigma_file = Path(args.file)
            if not sigma_file.exists():
                logger.error(f"Sigma file not found: {sigma_file}")
                return 1
            
            logger.info(f"Converting single file: {sigma_file}")
            
            if args.dry_run:
                # Dry run - don't save files
                result = rule_converter.convert_sigma_rule(sigma_file, None)
            else:
                result = batch_processor.process_single_file(sigma_file, output_dir)
            
            if result['status'] == 'success':
                logger.info("✓ Conversion successful")
                if not args.dry_run:
                    logger.info(f"Output file: {result.get('output_file', 'N/A')}")
                logger.info(f"Technology: {result.get('technology', 'N/A')}")
                logger.info(f"CEL Expression: {result.get('cel_expression', 'N/A')}")
                return 0
            else:
                logger.error(f"✗ Conversion failed: {result.get('error', 'Unknown error')}")
                return 1
        
        elif args.input:
            # Batch processing
            input_dir = Path(args.input)
            if not input_dir.exists():
                logger.error(f"Input directory not found: {input_dir}")
                return 1
            
            # Check progress info
            progress_info = batch_processor.get_progress_info()
            if progress_info['has_progress'] and not args.resume:
                logger.info(f"Previous progress found: {progress_info['completed_count']} files completed")
                logger.info("Use --resume to continue or --clear-progress to start fresh")
            
            logger.info(f"Starting batch processing: {input_dir}")
            
            if args.dry_run:
                logger.info("DRY RUN MODE - No files will be saved")
            
            # Process all Sigma rules in the directory
            results = await batch_processor.process_sigma_directory(
                input_dir, output_dir, args.resume, args.limit
            )
            
            # Display results
            logger.info("="*80)
            logger.info("BATCH PROCESSING RESULTS")
            logger.info("="*80)
            logger.info(f"Total files found: {results['total_found']}")
            logger.info(f"Files processed: {results['processed']}")
            logger.info(f"Successful conversions: {results['successful']}")
            logger.info(f"Failed conversions: {results['failed']}")
            logger.info(f"Success rate: {results['success_rate']:.1f}%")
            
            if results['errors']:
                logger.error(f"\nErrors encountered ({len(results['errors'])}):")
                for error in results['errors'][:5]:  # Show first 5 errors
                    logger.error(f"  {error.get('sigma_file', error.get('file', 'unknown'))}: {error.get('error', 'unknown')}")
                if len(results['errors']) > 5:
                    logger.error(f"  ... and {len(results['errors']) - 5} more errors")
            
            logger.info(f"\nConversion completed at: {results['completion_time']}")
            
            return 0 if results['failed'] == 0 else 1
    
    except KeyboardInterrupt:
        logger.info("\nConversion interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def convert_rules_batch(sigma_files: list, output_dir: Path, base_dir: Path) -> list:
    """
    Convert a batch of Sigma rules.
    
    Args:
        sigma_files: List of Sigma rule file paths (relative to source-repo)
        output_dir: Output directory for converted rules
        base_dir: Base directory of the project
        
    Returns:
        List of conversion results
    """
    logger = logging.getLogger(__name__)
    
    # Initialize the rule converter
    rule_converter = RuleConverter(base_dir)
    results = []
    
    for sigma_file_path in sigma_files:
        try:
            clean_path = sigma_file_path.lstrip('./')
        
            # Construct full path (assuming files are relative to source-repo)
            full_path = base_dir / "source-repo" / clean_path
            
            if not full_path.exists():
                logger.warning(f"File not found: {full_path}")
                results.append({
                    'status': 'error',
                    'sigma_file': sigma_file_path,
                    'error': 'File not found'
                })
                continue
            
            # Skip non-YAML files
            if not full_path.suffix.lower() in ['.yml', '.yaml']:
                logger.debug(f"Skipping non-YAML file: {full_path}")
                continue
            
            # Convert the rule
            logger.info(f"Converting: {sigma_file_path}")
            result = rule_converter.convert_sigma_rule(full_path, output_dir)
            result['sigma_file'] = sigma_file_path
            results.append(result)
            
        except Exception as e:
            logger.error(f"Error processing {sigma_file_path}: {e}")
            results.append({
                'status': 'error',
                'sigma_file': sigma_file_path,
                'error': str(e)
            })
    
    return results


if __name__ == "__main__":
    # Run the async main function
    sys.exit(asyncio.run(main()))