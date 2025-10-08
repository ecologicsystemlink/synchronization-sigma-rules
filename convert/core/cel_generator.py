"""
CEL Expression Generator Module

Functions to generate CEL expressions from Sigma detection logic.
Based on the patterns from standarConversion.txt examples.
"""

from typing import Dict, List, Any, Union, Tuple


class CELExpressionGenerator:
    """
    Generates CEL (Common Expression Language) expressions from Sigma detection logic.
    Based on the conversion patterns shown in standarConversion.txt
    """
    
    def __init__(self):
        self.operator_mappings = {
            'contains': 'contains',
            'startswith': 'startsWith',
            'endswith': 'endsWith',
            'equals': '==',
            'not_equals': '!=',
            'greater_than': '>',
            'less_than': '<',
            'greater_equal': '>=',
            'less_equal': '<=',
            'in': 'in'
        }
    
    def generate_cel_from_detection(self, detection: Dict[str, Any]) -> str:
        """
        Generate CEL expression from Sigma detection block.
        
        Based on examples from standarConversion.txt:
        - Lists become OR conditions
        - Different selections can be combined with AND/OR
        - Modifiers are converted to appropriate CEL functions
        """
        if not detection:
            return ""
        
        condition = detection.get('condition', 'selection')
        selections = {}
        filters = {}
        
        # Separate selections and filters
        for key, value in detection.items():
            if key == 'condition':
                continue
            elif key.startswith('filter'):
                filters[key] = value
            else:
                selections[key] = value
        
        # Generate expressions for each selection
        selection_expressions = []
        for sel_name, sel_data in selections.items():
            expr = self._generate_selection_expression(sel_data)
            if expr:
                selection_expressions.append(expr)
        
        # Generate expressions for filters (NOT conditions)
        filter_expressions = []
        for filter_name, filter_data in filters.items():
            expr = self._generate_selection_expression(filter_data)
            if expr:
                filter_expressions.append(f"!({expr})")
        
        # Combine according to condition
        return self._combine_expressions(selection_expressions, filter_expressions, condition)
    
    def _generate_selection_expression(self, selection_data: Dict[str, Any]) -> str:
        """
        Generate expression for a single selection.
        
        Example from standarConversion.txt:
        gcp.audit.method_name:
            - storage.buckets.delete
            - storage.buckets.insert
        
        Becomes:
        lower(gcp?.audit?.method_name) == lower(\"storage.buckets.delete\") or 
        lower(gcp?.audit?.method_name) == lower(\"storage.buckets.insert\")
        """
        field_expressions = []
        
        for field_name, field_values in selection_data.items():
            field_expr = self._generate_field_expression(field_name, field_values)
            if field_expr:
                field_expressions.append(field_expr)
        
        # Combine field expressions with AND
        if len(field_expressions) == 1:
            return field_expressions[0]
        elif len(field_expressions) > 1:
            return " && ".join([f"({expr})" for expr in field_expressions])
        
        return ""
    
    def _generate_field_expression(self, field_name: str, field_values: Union[str, List[str], Any]) -> str:
        """
        Generate expression for a single field with its values.
        
        Handles:
        - Single values: field == value
        - Lists: field == value1 or field == value2 or ...
        - Modifiers: field|contains, field|endswith, etc.
        """
        # Parse field name and modifiers
        base_field, modifiers = self._parse_field_modifiers(field_name)
        
        # Convert field name to CEL format (add safe wrapper and proper path)
        cel_field = self._convert_field_to_cel(base_field)
        
        # Handle different value types
        if isinstance(field_values, str):
            # Single string value
            return self._create_field_comparison(cel_field, field_values, modifiers)
        elif isinstance(field_values, list):
            # Multiple values - create OR condition
            value_expressions = []
            for value in field_values:
                expr = self._create_field_comparison(cel_field, str(value), modifiers)
                value_expressions.append(expr)
            
            if len(value_expressions) == 1:
                return value_expressions[0]
            else:
                return " || ".join([f"({expr})" for expr in value_expressions])
        else:
            # Convert other types to string
            return self._create_field_comparison(cel_field, str(field_values), modifiers)
    
    def _parse_field_modifiers(self, field_name: str) -> Tuple[str, List[str]]:
        """
        Parse field name and extract modifiers.
        
        Example: 'ProcessName|endswith' → ('ProcessName', ['endswith'])
        """
        if '|' not in field_name:
            return field_name, []
        
        parts = field_name.split('|')
        base_field = parts[0]
        modifiers = parts[1:]
        
        return base_field, modifiers
    
    def _convert_field_to_cel(self, field_name: str) -> str:
        """
        Convert Sigma field name to CEL format following UTMStack standard.
        
        Examples from standarConversion.txt:
        - properties.message → safe("log.propertiesMessage", "")
        - Operation → safe("log.operation", "")
        - TargetFilename → safe("log.targetFileName", "")
        - debugContext?.debugData?.requestUri → safe("log.debugContextDebugDataRequestUri", "")
        """
        # Apply UTMStack field mapping
        utmstack_field = self._map_sigma_field_to_utmstack(field_name)
        
        return f'safe("{utmstack_field}", "")'
    
    def _map_sigma_field_to_utmstack(self, sigma_field: str) -> str:
        """
        Map Sigma field names to UTMStack field names following the conversion patterns.
        
        Based on standarConversion.txt examples:
        - properties.message → log.propertiesMessage
        - TargetFilename → log.targetFileName
        - Operation → log.operation
        - debugContext?.debugData?.requestUri → log.debugContextDebugDataRequestUri
        """
        # Field mapping from Sigma to UTMStack
        field_mappings = {
            # Azure fields
            'properties.message': 'log.propertiesMessage',
            'Operation': 'log.operation',
            'ApplicationId': 'log.applicationId',
            'ResultStatus': 'resultStatus',  # Note: some fields don't have log prefix
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
            
            # Common fields
            'ProcessName': 'log.processName',
            'User': 'log.user',
            'ComputerName': 'log.computerName',
            'EventID': 'log.eventId',
        }
        
        # Handle exact matches
        if sigma_field in field_mappings:
            return field_mappings[sigma_field]
        
        # Handle nested fields with dots or question marks
        if '.' in sigma_field or '?' in sigma_field:
            # Convert debugContext?.debugData?.requestUri to debugContextDebugDataRequestUri
            clean_field = sigma_field.replace('?', '').replace('.', '')
            # Convert to camelCase
            parts = [part for part in sigma_field.replace('?', '').split('.') if part]
            if len(parts) > 1:
                camel_case = parts[0].lower() + ''.join(word.capitalize() for word in parts[1:])
                return f'log.{camel_case}'
        
        # Default: convert to camelCase and add log prefix
        # Convert snake_case or kebab-case to camelCase
        if '_' in sigma_field or '-' in sigma_field:
            parts = sigma_field.replace('-', '_').split('_')
            camel_case = parts[0].lower() + ''.join(word.capitalize() for word in parts[1:])
            return f'log.{camel_case}'
        
        # Default: assume it's already in the right format, just add log prefix
        return f'log.{sigma_field.lower()}'
    
    def _create_field_comparison(self, cel_field: str, value: str, modifiers: List[str]) -> str:
        """
        Create a comparison expression for a field and value.
        
        Based on standarConversion.txt patterns:
        - Use safe() wrapper without lower() functions
        - Handle different operators based on modifiers
        - Use && and || instead of and/or
        """
        # Escape quotes in value
        escaped_value = value.replace('"', '\\"')
        
        # Apply modifiers
        if 'contains' in modifiers:
            return f'{cel_field}.contains("{escaped_value}")'
        elif 'startswith' in modifiers:
            return f'{cel_field}.startsWith("{escaped_value}")'
        elif 'endswith' in modifiers:
            return f'{cel_field}.endsWith("{escaped_value}")'
        else:
            # Default equality comparison
            return f'{cel_field} == "{escaped_value}"'
    
    def _combine_expressions(self, selection_expressions: List[str], filter_expressions: List[str], condition: str) -> str:
        """
        Combine selection and filter expressions according to the condition.
        
        Examples from standarConversion.txt:
        - Simple: selection → just the selection expression
        - With filters: selection and not filter → selection_expr and not (filter_expr)
        - Multiple selections: 1 of selection_* → sel1 or sel2 or sel3
        """
        all_expressions = []
        
        # Add selection expressions
        if selection_expressions:
            if 'of selection' in condition:
                # Handle "1 of selection_*" pattern
                if len(selection_expressions) == 1:
                    all_expressions.append(selection_expressions[0])
                else:
                    combined_selections = " || ".join([f"({expr})" for expr in selection_expressions])
                    all_expressions.append(f"({combined_selections})")
            else:
                # Handle regular selection combinations
                if len(selection_expressions) == 1:
                    all_expressions.append(selection_expressions[0])
                else:
                    # Assume AND combination for multiple selections
                    combined_selections = " && ".join([f"({expr})" for expr in selection_expressions])
                    all_expressions.append(f"({combined_selections})")
        
        # Add filter expressions (NOT conditions)
        if filter_expressions:
            for filter_expr in filter_expressions:
                all_expressions.append(f"!({filter_expr})")
        
        # Combine all expressions
        if len(all_expressions) == 1:
            return all_expressions[0]
        elif len(all_expressions) > 1:
            return " && ".join(all_expressions)
        else:
            return ""
    
    def generate_simple_expression(self, field: str, value: str, operator: str = "equals") -> str:
        """
        Generate a simple CEL expression for testing.
        
        Args:
            field: Field name
            value: Value to compare
            operator: Comparison operator
        """
        cel_field = self._convert_field_to_cel(field)
        escaped_value = value.replace('\"', '\\\"')
        
        if operator == "equals":
            return f'{cel_field} == "{escaped_value}"'
        elif operator == "contains":
            return f'{cel_field}.contains("{escaped_value}")'
        elif operator == "startswith":
            return f'{cel_field}.startsWith("{escaped_value}")'
        elif operator == "endswith":
            return f'{cel_field}.endsWith("{escaped_value}")'
        else:
            return f'{cel_field} == "{escaped_value}"'