"""
Validación avanzada de inputs - ScanFlaws v4.0
Security Hardening: Normalización, canonicalización, bloqueo de bypasses
"""
import re
import ipaddress
import urllib.parse
from typing import Union, List, Optional, Literal
from enum import Enum

# Caracteres peligrosos (incluyendo codificados)
DANGEROUS_CHARS = {
    ';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>',
    '\\', '\n', '\r', '\t', '"', "'", '!', '@', '#', '%', '^', '*',
    '+', '=', '~', ' '
}

# Caracteres peligrosos URL-encoded
DANGEROUS_ENCODED = {
    '%3B', '%26', '%7C', '%60', '%24', '%28', '%29', '%7B', '%7D',
    '%5B', '%5D', '%3C', '%3E', '%5C', '%0A', '%0D', '%09', '%22',
    '%27', '%21', '%40', '%23', '%25', '%5E', '%2A', '%2B', '%3D',
    '%7E', '%20', '%2F', '%5C%2F'
}

# Patrones de bypass Unicode
UNICODE_BYPASS_PATTERNS = [
    r'[\u0000-\u001F]',  # Control characters
    r'[\u200B-\u200F]',  # Zero-width chars
    r'[\u202A-\u202E]',  # Directional overrides
    r'[\uFEFF]',  # BOM
]

# Tipos de target soportados
TargetType = Literal['ip', 'ipv4', 'ipv6', 'cidr', 'domain', 'subdomain', 'url', 'aws_region', 'arn']


class ValidationLevel(Enum):
    """Niveles de validación según contexto."""
    STRICT = "strict"  # Producción - bloquear todo sospechoso
    NORMAL = "normal"  # Desarrollo - validar estándar
    PERMISSIVE = "permissive"  # Testing - solo bloquear crítico


def normalize_input(raw_input: Union[str, bytes]) -> str:
    """
    Normaliza cualquier input a string limpio.

    - Decodifica bytes si es necesario
    - Remueve BOM y caracteres invisibles
    - Convierte a lowercase para consistencia
    - Strip de whitespace
    """
    if isinstance(data, bytes):
        data = data.decode('utf-8', errors='ignore')

    # Remover BOM y caracteres de control
    data = re.sub(r'[\uFEFF\u0000-\u001F]', '', data)

    # Remover zero-width y directional chars
    for pattern in UNICODE_BYPASS_PATTERNS:
        data = re.sub(pattern, '', data)

    return data.strip().lower()


def decode_url_encoded(value: str, max_depth: int = 3) -> str:
    """
    Decodifica URL-encoded recursivamente para detectar bypasses.

    Args:
        value: String potencialmente encoded
        max_depth: Máxima profundidad de decodificación (previene loops)

    Returns:
        String completamente decodificado
    """
    result = value
    for _ in range(max_depth):
        decoded = urllib.parse.unquote(result)
        if decoded == result:
            break
        result = decoded
    return result


def contains_dangerous_content(Any, level: ValidationLevel = ValidationLevel.NORMAL) -> bool:
    """
    Verifica si un valor contiene contenido peligroso.

    Args:
        value: Valor a verificar (str, dict, list)
        level: Nivel de estricticidad

    Returns:
        bool: True si contiene contenido peligroso
    """
    if isinstance(value, str):
        # Normalizar primero
        normalized = normalize_input(value)
        decoded = decode_url_encoded(normalized)

        # Verificar caracteres peligrosos directos
        if any(char in decoded for char in DANGEROUS_CHARS):
            return True

        # Verificar encoded
        if any(encoded in value.upper() for encoded in DANGEROUS_ENCODED):
            return True

        # Verificar Unicode bypass
        if level == ValidationLevel.STRICT:
            for pattern in UNICODE_BYPASS_PATTERNS:
                if re.search(pattern, value):
                    return True

        return False

    elif isinstance(value, dict):
        return any(contains_dangerous_content(v, level) for v in value.values())

    elif isinstance(value, (list, tuple)):
        return any(contains_dangerous_content(item, level) for item in value)

    return False


def validate_ip(value: str, version: Optional[Literal[4, 6]] = None) -> bool:
    """
    Valida dirección IP con soporte IPv4/IPv6.

    Args:
        value: String con la IP
        version: 4 para IPv4, 6 para IPv6, None para cualquiera

    Returns:
        bool: True si es válida
    """
    try:
        ip = ipaddress.ip_address(normalize_input(value))
        if version is not None:
            return ip.version == version
        return True
    except (ValueError, TypeError):
        return False


def validate_cidr(value: str, allow_private: bool = True) -> bool:
    """
    Valida notación CIDR con opción de bloquear rangos privados.

    Args:
        value: String con CIDR (ej: 192.168.1.0/24)
        allow_private: Si False, rechaza RFC1918 ranges

    Returns:
        bool: True si es válido
    """
    try:
        network = ipaddress.ip_network(normalize_input(value), strict=False)

        if not allow_private:
            # Rechazar rangos privados, loopback, link-local
            if network.is_private or network.is_loopback or network.is_link_local:
                return False

        return True
    except (ValueError, TypeError):
        return False


def validate_domain(value: str, allow_subdomains: bool = True,
                    allowed_tlds: Optional[List[str]] = None) -> bool:
    """
    Valida dominio con soporte para subdominios y TLDs restringidos.

    Args:
        value: String con el dominio
        allow_subdomains: Si False, solo permite dominio.tld
        allowed_tlds: Lista de TLDs permitidos (None = todos)

    Returns:
        bool: True si es válido
    """
    normalized = normalize_input(value)

    # Regex para dominio válido
    if allow_subdomains:
        pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}$'
    else:
        pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,}$'

    if not re.match(pattern, normalized):
        return False

    # Verificar TLD permitido
    if allowed_tlds:
        tld = normalized.split('.')[-1].lower()
        if tld not in [t.lower() for t in allowed_tlds]:
            return False

    return True


def validate_url(value: str, allowed_schemes: Optional[List[str]] = None,
                 allowed_domains: Optional[List[str]] = None) -> bool:
    """
    Valida URL con restricciones de esquema y dominio.

    Args:
        value: String con la URL
        allowed_schemes: Lista de esquemas permitidos (default: ['https'])
        allowed_domains: Lista de dominios permitidos (None = cualquiera válido)

    Returns:
        bool: True si es válida
    """
    if allowed_schemes is None:
        allowed_schemes = ['https']

    try:
        parsed = urllib.parse.urlparse(normalize_input(value))

        # Verificar esquema
        if parsed.scheme not in allowed_schemes:
            return False

        # Verificar que tenga netloc (dominio)
        if not parsed.netloc:
            return False

        # Verificar dominio si hay restricción
        if allowed_domains:
            domain = parsed.netloc.split(':')[0].lower()
            if domain not in [d.lower() for d in allowed_domains]:
                return False

        # Verificar que no haya caracteres peligrosos en path/query
        full_path = parsed.path + parsed.query + parsed.fragment
        if contains_dangerous_content(full_path, level=ValidationLevel.STRICT):
            return False

        return True

    except Exception:
        return False


def validate_aws_region(value: str) -> bool:
    """Valida región AWS con lista oficial."""
    # Regiones AWS oficiales (actualizar periódicamente)
    VALID_REGIONS = {
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-central-2',
        'ap-south-1', 'ap-south-2', 'ap-southeast-1', 'ap-southeast-2',
        'ap-southeast-3', 'ap-southeast-4', 'ap-northeast-1', 'ap-northeast-2',
        'ap-northeast-3', 'ca-central-1', 'ca-west-1',
        'sa-east-1', 'il-central-1', 'me-central-1', 'me-south-1',
        'af-south-1', 'cn-north-1', 'cn-northwest-1'
    }
    return normalize_input(value) in VALID_REGIONS


def validate_target(value: str, target_type: Union[TargetType, str] = 'auto',
                    level: ValidationLevel = ValidationLevel.NORMAL) -> bool:
    """
    Validador unificado de targets con detección automática.

    Args:
        value: String a validar
        target_type: Tipo esperado o 'auto' para detección
        level: Nivel de estricticidad

    Returns:
        bool: True si es válido
    """
    # Primero: verificar contenido peligroso
    if contains_dangerous_content(value, level):
        return False

    normalized = normalize_input(value)
    decoded = decode_url_encoded(normalized)

    # Si después de decodificar hay contenido peligroso, rechazar
    if decoded != normalized and contains_dangerous_content(decoded, level):
        return False

    if target_type == 'auto':
        # Intentar detectar tipo automáticamente (orden de prioridad)
        if validate_ip(decoded):
            return True
        if validate_cidr(decoded):
            return True
        if validate_url(decoded):
            return True
        if validate_domain(decoded):
            return True
        if validate_aws_region(decoded):
            return True
        return False

    # Validación por tipo específico
    validators = {
        'ip': lambda v: validate_ip(v),
        'ipv4': lambda v: validate_ip(v, version=4),
        'ipv6': lambda v: validate_ip(v, version=6),
        'cidr': validate_cidr,
        'domain': validate_domain,
        'subdomain': lambda v: validate_domain(v, allow_subdomains=True),
        'url': validate_url,
        'aws_region': validate_aws_region,
    }

    validator = validators.get(target_type if isinstance(target_type, str) else str(target_type))
    if validator:
        return validator(decoded)

    return False