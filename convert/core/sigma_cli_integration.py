"""
Sigma-CLI Integration

Executes sigma-cli for rule conversion and post-processes CEL expressions
to conform to UTMStack Event structure and field mapping standards.
"""

import subprocess
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class SigmaCLIIntegration:
    """
    Manages sigma-cli execution and post-processing of CEL expressions.
    """
    
    def __init__(self):
        self.field_mappings = self._load_field_mappings()
        self.numeric_fields = {
            'EventID', 'eventid', 'event_id', 'eventCode', 'event_code'
        }
    
    def convert_sigma_rule(self, sigma_file_path: Path) -> str:
        """
        Convert Sigma rule to UTMStack CEL expression.
        
        Args:
            sigma_file_path: Path to the Sigma rule file
            
        Returns:
            CEL expression in UTMStack format
            
        Raises:
            Exception: If sigma-cli execution fails
        """
        # Execute sigma-cli
        raw_cel = self._execute_sigma_cli(sigma_file_path)
        
        # Post-process to UTMStack standard
        utmstack_cel = self._post_process_cel_expression(raw_cel)
        
        return utmstack_cel
    
    def _execute_sigma_cli(self, sigma_file_path: Path) -> str:
        """
        Execute sigma-cli with the specified rule file.
        
        Args:
            sigma_file_path: Path to the Sigma rule file
            
        Returns:
            Raw CEL expression from sigma-cli
            
        Raises:
            Exception: If sigma-cli execution fails
        """
        cmd = [
            "sigma", "convert", 
            "--without-pipeline", 
            "-t", "golang_expr", 
            "-f", "default", 
            str(sigma_file_path)
        ]
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                check=True,
                timeout=30
            )
            
            cel_expression = result.stdout.strip()
            if not cel_expression:
                raise Exception("Sigma-CLI returned empty expression")
                
            logging.info(f"Sigma-CLI generated: {cel_expression}")
            return cel_expression
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Sigma-CLI failed: {e.stderr}"
            logging.error(error_msg)
            raise Exception(error_msg)
        except subprocess.TimeoutExpired:
            error_msg = "Sigma-CLI execution timed out"
            logging.error(error_msg)
            raise Exception(error_msg)
    
    def _post_process_cel_expression(self, raw_cel: str) -> str:
        """
        Post-process sigma-cli output to UTMStack standard format.
        
        Based on standarConversion.txt patterns:
        1. Replace field names with safe() wrappers
        2. Convert operators (and -> &&, or -> ||, not -> !)
        3. Remove lower() function calls
        4. Handle numeric fields with proper defaults
        5. Handle double-quoted literal strings without base fields
        
        Args:
            raw_cel: Raw CEL expression from sigma-cli
            
        Returns:
            UTMStack formatted CEL expression
        """
        processed_cel = raw_cel
        
        # Step 1: Replace logical operators
        processed_cel = self._replace_logical_operators(processed_cel)
        
        # Step 2: FIRST remove lower() function calls to avoid conflicts
        processed_cel = self._remove_lower_functions(processed_cel)
        
        # Step 3: Handle double-quoted literal strings (""value"") before field conversion
        processed_cel = self._handle_double_quoted_literals(processed_cel)
        
        # Step 4: Convert field references to safe() format
        processed_cel = self._convert_field_references(processed_cel)
        
        # Step 5: Final cleanup and fix syntax
        processed_cel = self._final_cleanup(processed_cel)
        
        logging.info(f"Post-processed CEL: {processed_cel}")
        return processed_cel
    
    def _replace_logical_operators(self, expression: str) -> str:
        """
        Replace logical operators with CEL equivalents.
        
        and -> &&
        or -> ||
        not -> !
        """
        # Replace with word boundaries to avoid replacing within strings
        expression = re.sub(r'\band\b', '&&', expression)
        expression = re.sub(r'\bor\b', '||', expression)
        expression = re.sub(r'\bnot\b', '!', expression)
        
        return expression
    
    def _remove_lower_functions(self, expression: str) -> str:
        """
        Remove lower() function calls before processing field references.
        This prevents conflicts when processing fields inside lower() calls.
        
        Examples:
        lower(FieldName) -> FieldName
        lower("string") -> "string"
        lower(safe("log.field", "")) -> safe("log.field", "")
        """
        # Remove lower() calls with already mapped safe() calls inside
        expression = re.sub(r'lower\s*\(\s*(safe\([^)]+\))\s*\)', r'\1', expression)
        
        # Remove lower() calls with field names inside
        expression = re.sub(r'lower\s*\(\s*([A-Za-z_][A-Za-z0-9_.-]*(?:\?\.[A-Za-z_][A-Za-z0-9_.-]*)*)\s*\)', r'\1', expression)
        
        # Remove lower() calls with string literals inside
        expression = re.sub(r'lower\s*\(\s*("([^"\\]|\\.)*")\s*\)', r'\1', expression)
        
        return expression
    
    def _handle_double_quoted_literals(self, expression: str) -> str:
        """
        Handle double-quoted literal strings (""value"") that appear without a base field.
        Convert them to proper field comparisons using the predominant field and operator in the expression.
        
        Examples:
        lower(type) == lower("EXECVE") and (""truncate"" and ""-s"" or ""dd"" and ""if="" and not (""of=""))
        ->
        type == "EXECVE" && ("truncate" && "-s" || "dd" && "if=" && !"of=")
        
        ProcessName contains "cmd.exe" and (""powershell"" or ""wscript"")
        ->
        ProcessName contains "cmd.exe" && (ProcessName contains "powershell" || ProcessName contains "wscript")
        
        This handles any operator or function: ==, !=, contains, matches, startsWith, endsWith, etc.
        
        Args:
            expression: CEL expression that may contain double-quoted literals
            
        Returns:
            Expression with double-quoted literals converted to proper field comparisons
        """
        # Pattern to find double-quoted literals: ""value""
        double_quote_pattern = r'""([^"]*?)""'
        
        # Check if there are any double-quoted literals
        if not re.search(double_quote_pattern, expression):
            return expression
        
        # Find the predominant field and operator in the expression
        base_field, predominant_operator = self._extract_predominant_field_and_operator(expression)
        
        if not base_field:
            # If no base field found, just clean up the double quotes
            return re.sub(double_quote_pattern, r'"\1"', expression)
        
        # Convert double-quoted literals to field comparisons
        def replace_double_quoted_literal(match):
            literal_value = match.group(1)
            
            # Get the context around this literal to determine the operation
            start_pos = match.start()
            end_pos = match.end()
            
            # Look for context around the literal
            before_context = expression[:start_pos].rstrip()
            after_context = expression[end_pos:].lstrip()
            
            # Check if this literal is in a standalone logical context
            logical_contexts = ['&&', '||', '(', ')', 'and', 'or', 'not', '!']
            
            # Check what comes before and after this literal
            is_standalone = False
            
            # If it starts the expression or follows logical operators/parentheses
            if (not before_context or 
                any(before_context.endswith(ctx) for ctx in logical_contexts) or
                before_context.endswith(' ')):
                is_standalone = True
            
            # If it's followed by logical operators/parentheses
            if (not after_context or 
                any(after_context.startswith(ctx) for ctx in logical_contexts) or
                after_context.startswith(' ')):
                is_standalone = True
            
            # If it's a standalone literal, convert to field comparison using predominant operator
            if is_standalone:
                if predominant_operator == 'contains':
                    return f'{base_field}.contains("{literal_value}")'
                elif predominant_operator == 'startsWith':
                    return f'{base_field}.startsWith("{literal_value}")'
                elif predominant_operator == 'endsWith':
                    return f'{base_field}.endsWith("{literal_value}")'
                elif predominant_operator == 'matches':
                    return f'{base_field}.matches("{literal_value}")'
                else:
                    # Default to equality comparison
                    return f'{base_field} == "{literal_value}"'
            else:
                # Just clean the quotes (it might be part of a function call)
                return f'"{literal_value}"'
        
        # Apply the replacement
        result = re.sub(double_quote_pattern, replace_double_quoted_literal, expression)
        
        logging.debug(f"Double-quoted literals handling: {expression} -> {result}")
        return result
    
    def _extract_predominant_field_and_operator(self, expression: str) -> Tuple[str, str]:
        """
        Extract the most frequently used field and operator in the expression to use as base 
        for double-quoted literal conversions.
        
        Args:
            expression: CEL expression
            
        Returns:
            Tuple of (predominant_field_name, predominant_operator)
        """
        # Pattern to find field references with their operators/functions
        field_operator_patterns = [
            # Equality and comparison operators
            (r'\b([A-Za-z_][A-Za-z0-9_.-]*)\s*(==|!=|>|<|>=|<=)', 'comparison'),
            # lower() function calls with comparison
            (r'lower\s*\(\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*\)\s*(==|!=|>|<|>=|<=)', 'comparison'),
            # Method calls (contains, startsWith, etc.)
            (r'\b([A-Za-z_][A-Za-z0-9_.-]*)\s*\.\s*(contains|startsWith|endsWith|matches)', 'method'),
            (r'\b([A-Za-z_][A-Za-z0-9_.-]*)\s+(contains|startsWith|endsWith|matches)', 'method'),
            # safe() calls with operators
            (r'safe\s*\(\s*"([^"]+)"\s*,\s*[^)]+\)\s*(==|!=|>|<|>=|<=)', 'comparison'),
            (r'safe\s*\(\s*"([^"]+)"\s*,\s*[^)]+\)\s*\.\s*(contains|startsWith|endsWith|matches)', 'method'),
        ]
        
        field_counts = {}
        operator_counts = {}
        
        for pattern, pattern_type in field_operator_patterns:
            matches = re.findall(pattern, expression)
            for match in matches:
                field = match[0].strip()
                operator = match[1].strip()
                
                # Clean field name (remove log. prefix for counting)
                clean_field = field.replace('log.', '') if field.startswith('log.') else field
                field_counts[clean_field] = field_counts.get(clean_field, 0) + 1
                
                # Count operators/methods
                if pattern_type == 'method':
                    operator_counts[operator] = operator_counts.get(operator, 0) + 1
                elif pattern_type == 'comparison':
                    # Group all comparison operators as 'comparison'
                    operator_counts['comparison'] = operator_counts.get('comparison', 0) + 1
        
        # Get predominant field
        predominant_field = ""
        if field_counts:
            predominant_field = max(field_counts, key=field_counts.get)
        
        # Get predominant operator
        predominant_operator = "=="  # Default
        if operator_counts:
            most_frequent_op_type = max(operator_counts, key=operator_counts.get)
            
            if most_frequent_op_type == 'comparison':
                predominant_operator = "=="
            else:
                # It's a method like contains, startsWith, etc.
                predominant_operator = most_frequent_op_type
        
        return predominant_field, predominant_operator
    
    def _extract_predominant_field(self, expression: str) -> str:
        """
        Extract the most frequently used field in the expression to use as base field
        for double-quoted literal conversions.
        
        Args:
            expression: CEL expression
            
        Returns:
            The predominant field name (without safe() wrapper if present)
        """
        # Pattern to find field references (both raw fields and safe() wrapped)
        field_patterns = [
            r'\b([A-Za-z_][A-Za-z0-9_.-]*)\s*(?:==|!=|>|<|>=|<=)',  # field == value
            r'lower\s*\(\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*\)',         # lower(field)
            r'safe\s*\(\s*"([^"]+)"\s*,',                             # safe("field", ...)
            r'\b([A-Za-z_][A-Za-z0-9_.-]*)\s*\.(?:contains|startsWith|endsWith|matches)'  # field.method
        ]
        
        field_counts = {}
        
        for pattern in field_patterns:
            matches = re.findall(pattern, expression)
            for match in matches:
                field = match.strip()
                # Remove log. prefix if present for counting
                clean_field = field.replace('log.', '') if field.startswith('log.') else field
                field_counts[clean_field] = field_counts.get(clean_field, 0) + 1
        
        if not field_counts:
            return ""
        
        # Return the most frequent field
        predominant_field = max(field_counts, key=field_counts.get)
        
        # If it's a simple field name, return as is for now (will be converted later)
        # If it already has log. prefix, return as is
        return predominant_field
    
    def _convert_field_references(self, expression: str) -> str:
        """
        Convert field references to safe() wrapper format.
        Since lower() functions have been removed, we can now safely process fields.
        
        Examples:
        TargetFilename -> safe("log.targetFileName", "")
        EventID -> safe("log.eventCode", 0.0)
        debugContext?.debugData?.requestUri -> safe("log.debugContextDebugDataRequestUri", "")
        """
        # Pattern to match field references, but exclude:
        # - String literals (content between quotes)
        # - Already wrapped safe() calls
        # - Function names
        
        # Split by quotes to separate strings from code
        parts = expression.split('"')
        result_parts = []
        
        for i, part in enumerate(parts):
            if i % 2 == 0:  # Even index = code part
                # Process field references in code parts only
                result_parts.append(self._process_field_references_in_segment(part))
            else:  # Odd index = string literal
                # Keep string literals unchanged
                result_parts.append(part)
        
        # Reassemble with quotes
        result = '"'.join(result_parts)
        
        return result
    
    def _final_cleanup(self, expression: str) -> str:
        """
        Final cleanup of the expression: add double() wrappers, fix method syntax, fix negation.
        """
        # Add double() wrapper for numeric comparisons
        expression = self._add_double_wrappers(expression)
        
        # Fix method syntax (add dots before methods)
        expression = self._fix_method_syntax(expression)
        
        # Fix negation operator spacing
        expression = self._fix_negation_syntax(expression)
        
        # Clean up extra spaces
        expression = re.sub(r'\s+', ' ', expression)
        expression = expression.strip()
        
        return expression
    
    def _split_preserving_strings(self, expression: str) -> list:
        """
        Split expression into segments, preserving string literals.
        
        Returns:
            List of tuples (segment, is_string_literal)
        """
        segments = []
        current_segment = ""
        in_string = False
        i = 0
        
        while i < len(expression):
            char = expression[i]
            
            # Check for escaped quotes
            if char == '"' and (i == 0 or expression[i-1] != '\\'):
                if in_string:
                    # End of string literal
                    current_segment += char
                    segments.append((current_segment, True))
                    current_segment = ""
                    in_string = False
                else:
                    # Start of string literal
                    if current_segment:
                        segments.append((current_segment, False))
                    current_segment = char
                    in_string = True
            else:
                current_segment += char
            
            i += 1
        
        # Add remaining segment if any
        if current_segment:
            segments.append((current_segment, in_string))
        
        return segments
    
    def _process_field_references_in_segment(self, segment: str) -> str:
        """
        Process field references in a non-string segment.
        
        Args:
            segment: Text segment outside of string literals
            
        Returns:
            Processed segment with field references converted to safe() format
        """
        # First, identify and protect existing method calls (field.method format)
        method_calls = []
        method_pattern = r'\b([A-Za-z_][A-Za-z0-9_-]*)\.(contains|startsWith|endsWith|matches)\s*\('
        
        # Find all method calls and replace them with placeholders
        def protect_method_call(match):
            field_name = match.group(1)
            method_name = match.group(2)
            placeholder = f"__METHOD_CALL_{len(method_calls)}__"
            
            # Convert field to safe() format but preserve the method call
            utmstack_field = self._map_field_to_utmstack(field_name)
            safe_call = f'safe("{utmstack_field}", "").{method_name}('
            method_calls.append(safe_call)
            
            return placeholder
        
        protected_segment = re.sub(method_pattern, protect_method_call, segment)
        
        # Now process remaining field references (simple fields without methods)
        field_pattern = r'\b([A-Za-z_][A-Za-z0-9_-]*(?:\??\.[A-Za-z_][A-Za-z0-9_-]*)*)\b'
        
        def replace_field(match):
            field_name = match.group(1)
            
            # Skip if it's already a function call or reserved word
            if field_name in ['lower', 'upper', 'contains', 'startsWith', 'endsWith', 'matches', 'safe', 'double', 'and', 'or', 'not']:
                return field_name
            
            # Skip if it's a placeholder
            if field_name.startswith('__METHOD_CALL_'):
                return field_name
            
            # Skip if it's already wrapped in safe() (avoid double wrapping)
            if 'safe(' in protected_segment and field_name in protected_segment:
                # Check if this field is already inside a safe() call
                safe_pattern = rf'safe\s*\(\s*"[^"]*{re.escape(field_name)}[^"]*"\s*,'
                if re.search(safe_pattern, protected_segment):
                    return field_name
            
            # Map to UTMStack field
            utmstack_field = self._map_field_to_utmstack(field_name)
            
            # Determine default value based on field type
            if self._is_numeric_field(field_name):
                return f'safe("{utmstack_field}", 0.0)'
            else:
                return f'safe("{utmstack_field}", "")'
        
        # Replace field references
        result = re.sub(field_pattern, replace_field, protected_segment)
        
        # Restore method calls
        for i, method_call in enumerate(method_calls):
            placeholder = f"__METHOD_CALL_{i}__"
            result = result.replace(placeholder, method_call)
        
        return result
    
    def _clean_expression(self, expression: str) -> str:
        """
        Clean up the expression by removing lower() calls and fixing syntax.
        
        Examples:
        lower(safe("log.field", "")) -> safe("log.field", "")
        lower("string") -> "string"
        safe("log.eventCode", 0.0) == 325 -> safe("log.eventCode", 0.0) == double(325)
        """
        # Remove lower() function calls
        expression = re.sub(r'lower\((safe\("[^"]*",\s*"[^"]*")\)', r'\1', expression)
        expression = re.sub(r'lower\("([^"]*)"\)', r'"\1"', expression)
        expression = re.sub(r'lower\(([^)]+)\)', r'\1', expression)
        
        # Add double() wrapper for numeric comparisons
        expression = self._add_double_wrappers(expression)
        
        # Fix method syntax (add dots before methods)
        expression = self._fix_method_syntax(expression)
        
        # Fix negation operator spacing
        expression = self._fix_negation_syntax(expression)
        
        # Clean up extra spaces
        expression = re.sub(r'\s+', ' ', expression)
        expression = expression.strip()
        
        return expression
    
    def _add_double_wrappers(self, expression: str) -> str:
        """
        Add double() wrappers for numeric comparisons.
        
        Example: safe("log.eventCode", 0.0) == 325 -> safe("log.eventCode", 0.0) == double(325)
        """
        # Pattern to match numeric comparisons with safe() fields that have 0.0 default
        numeric_pattern = r'(safe\("[^"]*",\s*0\.0\))\s*(==|!=|>|<|>=|<=)\s*(\d+)'
        
        def add_double(match):
            field_expr = match.group(1)
            operator = match.group(2)
            number = match.group(3)
            return f'{field_expr} {operator} double({number})'
        
        return re.sub(numeric_pattern, add_double, expression)
    
    def _fix_method_syntax(self, expression: str) -> str:
        """
        Fix method syntax by adding dots before method names when they follow safe() calls.
        
        Examples:
        safe("log.field", "") contains "value" -> safe("log.field", "").contains("value")
        safe("log.field", "") endsWith "value" -> safe("log.field", "").endsWith("value")
        """
        # Pattern to match safe() calls followed by method names without dots
        # Capture: safe("field", "value") + space + method + space + "argument"
        method_pattern = r'(safe\("[^"]*",\s*(?:"[^"]*"|\d+(?:\.\d+)?)\))\s+(contains|startsWith|endsWith|matches)\s+("([^"]*)")'
        
        def fix_method(match):
            safe_call = match.group(1)  # safe("log.field", "")
            method_name = match.group(2)  # contains, endsWith, etc.
            argument = match.group(3)  # "value"
            return f'{safe_call}.{method_name}({argument})'
        
        # Apply the fix
        result = re.sub(method_pattern, fix_method, expression)
        
        return result
    
    def _fix_negation_syntax(self, expression: str) -> str:
        """
        Fix negation operator syntax by removing spaces between ! and the following expression.
        
        Examples:
        ! (expression) -> !(expression)
        ! safe("field", "") -> !safe("field", "")
        !  (expression) -> !(expression)
        ! \t(expression) -> !(expression)
        """
        # Pattern to match ! followed by one or more whitespace characters
        # and then either opening parenthesis or function calls like safe()
        negation_pattern = r'!\s+(?=[\(a-zA-Z])'
        
        # Replace with ! directly followed by the expression (no space)
        result = re.sub(negation_pattern, '!', expression)
        
        return result
    
    def _map_field_to_utmstack(self, sigma_field: str) -> str:
        """
        Map Sigma field names to UTMStack field names.
        
        Args:
            sigma_field: Original Sigma field name
            
        Returns:
            UTMStack field name
        """
        # Check direct mappings first
        if sigma_field in self.field_mappings:
            return self.field_mappings[sigma_field]
        
        # Handle nested fields with dots or question marks
        if '.' in sigma_field or '?' in sigma_field:
            return self._convert_nested_field(sigma_field)
        
        # Check if this field might be a Side struct field (origin/target related)
        side_field = self._check_side_field_mapping(sigma_field)
        if side_field:
            return side_field
        
        # Default: convert to camelCase and add log prefix
        return self._convert_to_camel_case(sigma_field)
    
    def _check_side_field_mapping(self, field: str) -> str:
        """
        Check if a field should be mapped to a Side struct field.
        Side fields MUST have origin. or target. prefix, never standalone.
        
        Args:
            field: Field name to check
            
        Returns:
            Mapped field name if it's a Side field with proper prefix, empty string otherwise
        """
        # Convert to lowercase for checking
        field_lower = field.lower()
        
        # List of fields that typically belong to Side struct
        side_fields = {
            'bytessent', 'bytesreceived', 'packagessent', 'packagesreceived',
            'ip', 'host', 'user', 'group', 'port', 'domain', 'mac', 'url', 'cidr',
            'certificatefingerprint', 'ja3fingerprint', 'jarmfingerprint', 
            'sshbanner', 'sshfingerprint', 'cookie', 'jabberid',
            'email', 'dkim', 'dkimsignature', 'emailaddress', 'emailbody',
            'emaildisplayname', 'emailsubject', 'emailthreadindex', 'emailxmailer',
            'whoisregistrant', 'whoisregistrar', 'process', 'processstate',
            'command', 'windowsscheduledtask', 'windowsservicedisplayname', 'windowsservicename',
            'file', 'path', 'filename', 'sizeinbytes', 'mimetype',
            'hash', 'authentihash', 'cdhash', 'md5', 'sha1', 'sha224', 'sha256',
            'sha384', 'sha3224', 'sha3256', 'sha3384', 'sha3512', 'sha512',
            'sha512224', 'sha512256', 'hex', 'base64',
            'operatingsystem', 'chromeextension', 'mobileappid',
            'cpe', 'cve', 'malware', 'malwarefamily', 'malwaretype',
            'pgpprivatekey', 'pgppublickey', 'connections',
            'usedcpupercent', 'usedmempercent', 'totalcpuunits', 'totalmem', 'disks'
        }
        
        # Check for prefixes that indicate origin/target context
        origin_prefixes = ['src', 'source', 'origin', 'client']
        target_prefixes = ['dst', 'dest', 'destination', 'target', 'server']
        
        for prefix in origin_prefixes:
            if field_lower.startswith(prefix):
                base_field = field[len(prefix):].lstrip('_-')
                if base_field.lower() in side_fields:
                    return f'origin.{self._convert_to_camel_case_side_field(base_field)}'
        
        for prefix in target_prefixes:
            if field_lower.startswith(prefix):
                base_field = field[len(prefix):].lstrip('_-')
                if base_field.lower() in side_fields:
                    return f'target.{self._convert_to_camel_case_side_field(base_field)}'
        
        return ""
    
    def _convert_to_camel_case_side_field(self, field: str) -> str:
        """
        Convert field name to camelCase for Side struct fields (no prefix).
        
        Args:
            field: Field name to convert
            
        Returns:
            CamelCase field name
        """
        # Handle special cases (all uppercase abbreviations)
        special_cases = {
            'IP': 'ip',
            'MAC': 'mac',
            'URL': 'url',
            'CIDR': 'cidr',
            'CPE': 'cpe',
            'CVE': 'cve',
            'MD5': 'md5',
            'SHA1': 'sha1',
            'SHA256': 'sha256',
            'SHA384': 'sha384',
            'SHA512': 'sha512',
            'HEX': 'hex',
            'BASE64': 'base64',
            'JA3': 'ja3Fingerprint',
            'JARM': 'jarmFingerprint',
            'DKIM': 'dkim',
        }
        
        if field in special_cases:
            return special_cases[field]
        
        # Handle fields with hyphens
        if '-' in field:
            parts = field.split('-')
            camel_case = parts[0].lower() + ''.join(word.capitalize() for word in parts[1:])
            return camel_case
        
        # Handle snake_case
        if '_' in field:
            parts = field.split('_')
            camel_case = parts[0].lower() + ''.join(word.capitalize() for word in parts[1:])
            return camel_case
        
        # Handle PascalCase -> camelCase
        if field and field[0].isupper():
            camel_case = field[0].lower() + field[1:]
            return camel_case
        
        # Default
        return field.lower()
    
    def _convert_nested_field(self, field: str) -> str:
        """
        Convert nested field names to UTMStack format.
        
        Example: debugContext?.debugData?.requestUri -> log.debugContextDebugDataRequestUri
        """
        # Remove question marks and split by dots
        clean_field = field.replace('?', '')
        parts = [part for part in clean_field.split('.') if part]
        
        if len(parts) > 1:
            # Convert to camelCase
            camel_case = parts[0] + ''.join(word.capitalize() for word in parts[1:])
            return f'log.{camel_case}'
        else:
            return f'log.{parts[0].lower()}'
    
    def _convert_to_camel_case(self, field: str) -> str:
        """
        Convert field name to camelCase and add log prefix.
        
        Examples:
        TargetFilename -> log.targetFileName
        Provider_Name -> log.providerName
        c-uri -> log.cUri
        """
        # Handle fields with hyphens (convert to camelCase)
        if '-' in field:
            parts = field.split('-')
            camel_case = parts[0].lower() + ''.join(word.capitalize() for word in parts[1:])
            return f'log.{camel_case}'
        
        # Handle snake_case
        if '_' in field:
            parts = field.split('_')
            camel_case = parts[0].lower() + ''.join(word.capitalize() for word in parts[1:])
            return f'log.{camel_case}'
        
        # Handle PascalCase -> camelCase
        if field and field[0].isupper():
            camel_case = field[0].lower() + field[1:]
            return f'log.{camel_case}'
        
        # Default
        return f'log.{field.lower()}'
    
    def _is_numeric_field(self, field_name: str) -> bool:
        """
        Check if a field should be treated as numeric.
        
        Args:
            field_name: Field name to check
            
        Returns:
            True if field should use numeric default (0.0)
        """
        field_lower = field_name.lower()
        return any(numeric_field.lower() in field_lower for numeric_field in self.numeric_fields)
    
    def _load_field_mappings(self) -> Dict[str, str]:
        """
        Load field mappings from standarConversion.txt patterns and UTMStack Event/Side structures.
        
        Returns:
            Dictionary mapping Sigma fields to UTMStack fields
        """
        return {
            # === Event struct fields (direct mapping without log prefix) ===
            'id': 'id',
            'Id': 'id',
            'timestamp': 'timestamp',
            'Timestamp': 'timestamp',
            'deviceTime': 'deviceTime',
            'DeviceTime': 'deviceTime',
            'dataType': 'dataType',
            'DataType': 'dataType',
            'dataSource': 'dataSource',
            'DataSource': 'dataSource',
            'tenantId': 'tenantId',
            'TenantId': 'tenantId',
            'tenantName': 'tenantName',
            'TenantName': 'tenantName',
            'protocol': 'protocol',
            'Protocol': 'protocol',
            'connectionStatus': 'connectionStatus',
            'ConnectionStatus': 'connectionStatus',
            'statusCode': 'statusCode',
            'StatusCode': 'statusCode',
            'actionResult': 'actionResult',
            'ActionResult': 'actionResult',
            'action': 'action',
            'Action': 'action',
            'severity': 'severity',
            'Severity': 'severity',
            'errors': 'errors',
            'Errors': 'errors',
            
            # === Compatibility mappings for common Sigma fields (mapped to log.*) ===
            # Azure/Office365 fields
            'Operation': 'log.operation',
            'ApplicationId': 'log.applicationId',
            'ResultStatus': 'resultStatus',  # Special case - no log prefix
            'RequestType': 'log.requestType',
            'ObjectId': 'log.objectId',
            'OperationProperties': 'log.operationProperties',
            'Parameters': 'log.parameters',
            
            # Windows fields
            'TargetFilename': 'log.targetFileName',
            'Image': 'log.image',
            'OriginalFileName': 'log.originalFileName',
            'CommandLine': 'log.commandLine',
            'ParentCommandLine': 'log.parentCommandLine',
            'Provider_Name': 'log.providerName',
            'EventID': 'log.eventCode',
            'Data': 'log.data',
            'SourceImage': 'log.sourceImage',
            'TargetImage': 'log.targetImage',
            
            # Common fields that don't match Event/Side structure (use log prefix)
            'ProcessName': 'log.processName',
            'ComputerName': 'log.computerName',
            'Hostname': 'log.hostname',
            
            # Fields with hyphens
            'c-uri': 'log.cUri',
            'user-agent': 'log.userAgent',
        }


