# Sigma to UTMStack SIEM Rule Converter

Arquitectura profesional de software para convertir reglas Sigma al formato del SIEM UTMStack.

## Estructura del Proyecto

```
convert/
├── __init__.py                    # Paquete principal
├── convert.py                     # Punto de entrada principal
├── README.md                      # Documentación
│
├── core/                          # Componentes principales
│   ├── __init__.py
│   ├── sigma_parser.py           # Parser de reglas Sigma
│   ├── cel_generator.py          # Generador de expresiones CEL
│   └── field_mapper.py           # Mapeo de campos y tecnologías
│
├── processors/                   # Procesadores de reglas
│   ├── __init__.py
│   ├── rule_converter.py         # Convertidor de reglas individuales
│   └── batch_processor.py        # Procesador de lotes
│
└── utils/                        # Utilidades
    ├── __init__.py
    ├── yaml_validator.py         # Validación YAML
    └── file_handler.py           # Manejo de archivos
```

## Principios de Arquitectura

### 1. **Separación de Responsabilidades**
- **Core**: Lógica de negocio principal (parsing, generación CEL, mapeo)
- **Processors**: Procesamiento de reglas (individual y lote)
- **Utils**: Utilidades auxiliares (validación, archivos)

### 2. **Reutilización de Funciones Existentes**
Todas las funciones están **copiadas sin modificación** del proyecto existente:

#### De `generate_correlation_rules.py`:
- `get_technology_mappings()` → `field_mapper.py`
- `check_existing_rules()` → `rule_converter.py`
- `save_execution_state()` → `batch_processor.py`
- `verify_files_created()` → `batch_processor.py`

#### De `verify_correlation_rules.py`:
- `get_filter_fields_for_technology()` → `field_mapper.py`
- `extract_technology_from_path()` → `field_mapper.py`
- `fix_common_yaml_issues()` → `yaml_validator.py`
- `check_impact_scores()` → `rule_converter.py`
- `save_progress()` → `batch_processor.py`

#### De `fix_rules.py`:
- `update_category_in_file()` → `batch_processor.py`
- `get_mitre_tactic()` → `batch_processor.py`

#### De `import_utmstack_rules.py`:
- `create_analysis_prompt()` → `file_handler.py`
- `load_progress()` → `batch_processor.py`

#### De `fix_rules.py`:
- `get_all_rule_files()` → `file_handler.py`

#### De `import_utmstack_rules.py`:
- `detect_rule_format()` → `file_handler.py`
- `get_technology_from_path()` → `file_handler.py`
- `map_repo_tech_to_local()` → `field_mapper.py`
- `explore_utmstack_repo()` → `file_handler.py`

#### De `validate_yaml.py`:
- `find_incorrect_yaml()` → `yaml_validator.py`

### 3. **Conversión Basada en Patrones**
Sigue los patrones definidos en `standarConversion.txt`:

```python
# Ejemplo de conversión
# Sigma:
detection:
    selection:
        gcp.audit.method_name:
            - storage.buckets.delete
            - storage.buckets.insert

# UTMStack CEL:
lower(gcp?.audit?.method_name) == lower("storage.buckets.delete") or 
lower(gcp?.audit?.method_name) == lower("storage.buckets.insert")
```

## Componentes Principales

### SigmaParser (`core/sigma_parser.py`)
- Parsea archivos YAML Sigma
- Extrae metadatos y lógica de detección
- Mapea tecnologías basándose en `logsource`
- Extrae técnicas MITRE ATT&CK

### CELExpressionGenerator (`core/cel_generator.py`)
- Genera expresiones CEL desde lógica Sigma
- Maneja modificadores (`contains`, `endswith`, etc.)
- Combina múltiples condiciones
- Implementa patrones de `standarConversion.txt`

### FieldMapper (`core/field_mapper.py`)
- Mapea tecnologías a filtros disponibles
- Lee campos desde `filter_fields_output.txt`
- Convierte nombres de tecnologías entre formatos

### RuleConverter (`processors/rule_converter.py`)
- Convierte reglas Sigma individuales
- Construye estructura UTMStack completa
- Determina `dataTypes`, `afterEvents`, etc.
- Guarda archivos convertidos

### BatchProcessor (`processors/batch_processor.py`)
- Procesa múltiples reglas en lote
- Maneja progreso y estado
- Permite resumir conversiones
- Valida reglas convertidas

## Uso

### Conversión Individual
```bash
python convert.py --file sigma_rule.yml --output converted_rules/
```

### Conversión en Lote
```bash
python convert.py --input sigma_rules/ --output converted_rules/ --batch
```

### Con Progreso
```bash
python convert.py --input sigma_rules/ --output converted_rules/ --batch --resume
```

### Validación
```bash
python convert.py --validate --output converted_rules/
```

### Prueba CEL
```bash
python convert.py --test-cel "malware.detected"
```

## Beneficios de esta Arquitectura

### 1. **Mantenibilidad**
- Código organizado por responsabilidades
- Funciones copiadas sin modificación preservan estabilidad
- Fácil localización de componentes

### 2. **Escalabilidad**
- Procesamiento en lotes con progreso
- Manejo de errores granular
- Capacidad de resumir operaciones

### 3. **Testabilidad**
- Componentes independientes
- Funciones puras para generación CEL
- Validación separada

### 4. **Reutilización**
- Aprovecha utilidades existentes probadas
- No reinventa funcionalidad ya disponible
- Mantiene compatibilidad con proyecto existente

### 5. **Flexibilidad**
- Conversión de reglas individuales o lotes
- Soporte para múltiples tecnologías
- Categorización automática basada en tags MITRE ATT&CK locales

## Funciones Clave Agregadas

### `create_analysis_prompt()`
Ubicación: `utils/file_handler.py`

Genera prompts detallados para analizar reglas Sigma antes de la conversión:
```python
from utils.file_handler import FileHandler

prompt = FileHandler.create_analysis_prompt(
    rule_file=Path("sigma_rule.yml"),
    tech_name="windows", 
    existing_rules=[Path("rule1.yml"), Path("rule2.yml")]
)
```

**Uso:** Análisis automático de duplicados y preparación para conversión.

### `_determine_category_from_tags()`
Ubicación: `core/sigma_parser.py`

Determina automáticamente categorías de reglas basándose en tags MITRE ATT&CK:
```python
import aiohttp
from processors.batch_processor import update_category_in_file

```python
from core.sigma_parser import SigmaParser

parser = SigmaParser()
category = parser._determine_category_from_tags(['attack.execution', 'attack.t1059.001'])
# Returns: "Execution"
```

**Uso:** Categorización automática basada en tags Sigma sin necesidad de conexión a internet.

## Próximos Pasos

1. **Adaptar las funciones copiadas** para optimizar la conversión
2. **Implementar mapeos específicos** de campos Sigma → UTMStack
3. **Agregar tests unitarios** para cada componente
4. **Optimizar generación CEL** para casos complejos
5. **Documentar patrones de conversión** específicos

Esta arquitectura proporciona una base sólida y profesional para el desarrollo del convertidor, reutilizando el código existente de manera organizada y mantenible.