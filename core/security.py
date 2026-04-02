"""
Módulo de seguridad - Validación de inputs y sanitización
ScanFlaws Security Hardening v3.0
"""
import re
import ipaddress
from typing import Union, List, Optional, Any, Dict

# ============================================
# CONFIGURACIÓN DE SEGURIDAD
# ============================================

# Caracteres peligrosos para command injection
DANGEROUS_CHARS = [';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '\\', '\n', '\r', '\t', '"', "'"]

# Patrones de validación
DOMAIN_REGEX = re.compile(
    r'^(?!-)'  # No empieza con guión
    r'[A-Za-z0-9-]{1,63}'  # Primer label
    r'(?:\.(?!-)[A-Za-z0-9-]{1,63})*'  # Subdominios intermedios
    r'\.[A-Za-z]{2,}$'  # TLD (mínimo 2 letras)
)

URL_REGEX = re.compile(r'^https?://[^\s/$.?#].[^\s]*$')
AWS_REGION_REGEX = re.compile(r'^[a-z]{2}-(north|south|east|west|central)?-?\d{1,2}$')

# Patrones de datos sensibles para redacción en logs
SENSITIVE_PATTERNS = [
    r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
    r'aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*[^\s]+',  # AWS Secret Key variations
    r'password\s*[:=]\s*[^\s]+',  # Passwords
    r'passwd\s*[:=]\s*[^\s]+',  # Passwords (variante)
    r'secret\s*[:=]\s*[^\s]+',  # Secrets genéricos
    r'token\s*[:=]\s*[^\s]+',  # Tokens
    r'api[_-]?key\s*[:=]\s*[^\s]+',  # API Keys
    r'apikey\s*[:=]\s*[^\s]+',  # API Keys (sin guión)
    r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',  # Private keys
    r'Bearer\s+[A-Za-z0-9\-_\.]+',  # Bearer tokens
    r'Basic\s+[A-Za-z0-9+/=]+',  # Basic auth
]

# Claves sensibles para redactar en dicts
SENSITIVE_KEYS = [
    'password', 'passwd', 'secret', 'token', 'api_key', 'apikey',
    'access_key', 'secret_key', 'private_key', 'credential',
    'authorization', 'auth_token', 'bearer', 'jwt'
]


# ============================================
# VALIDACIÓN DE INPUTS
# ============================================

def is_safe_input(user_input: str, allow_special: Optional[List[str]] = None) -> bool:
    """
    Verifica si un input de usuario es seguro (sin caracteres peligrosos).

    Args:
        user_input: String a validar
        allow_special: Lista de caracteres especiales permitidos (ej: ['.', '/'])

    Returns:
        bool: True si es seguro, False si contiene caracteres peligrosos
    """
    if not isinstance(user_input, str):
        return False

    if allow_special is None:
        allow_special = []

    for char in user_input:
        if char in DANGEROUS_CHARS and char not in allow_special:
            return False
    return True


def validate_ip_address(ip: str) -> bool:
    """
    Valida si es una dirección IP válida (IPv4 o IPv6).

    Args:
        ip: String con la dirección IP

    Returns:
        bool: True si es válida
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False


def validate_cidr(cidr: str) -> bool:
    """
    Valida si es un CIDR válido.

    Args:
        cidr: String con notación CIDR (ej: 192.168.1.0/24)

    Returns:
        bool: True si es válido
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except (ValueError, TypeError):
        return False


def validate_domain(domain: str) -> bool:
    """
    Valida si es un dominio válido (soporta subdominios y TLDs compuestos).

    Ejemplos válidos:
    - example.com
    - sub.example.com
    - sub.example.co.uk
    - my-app.example-domain.com

    Args:
        domain: String con el dominio

    Returns:
        bool: True si es válido
    """
    if not domain or not isinstance(domain, str):
        return False

    if len(domain) > 253:
        return False

    return DOMAIN_REGEX.match(domain) is not None


def validate_url(url: str) -> bool:
    """
    Valida si es una URL válida.

    Args:
        url: String con la URL

    Returns:
        bool: True si es válida
    """
    if not url or not isinstance(url, str):
        return False
    return URL_REGEX.match(url) is not None


def validate_aws_region(region: str) -> bool:
    """
    Valida si es una región AWS válida.

    Args:
        region: String con el nombre de región (ej: us-east-1)

    Returns:
        bool: True si es válida
    """
    if not region or not isinstance(region, str):
        return False
    return AWS_REGION_REGEX.match(region) is not None


def validate_target(target: str, target_type: str = 'auto') -> bool:
    """
    Valida un target genérico (IP, dominio, URL, región AWS).

    Args:
        target: String a validar
        target_type: 'ip', 'cidr', 'domain', 'url', 'region', o 'auto' para detección automática

    Returns:
        bool: True si es válido
    """
    if not target or not isinstance(target, str):
        return False

    # Primero verificar caracteres peligrosos (permitiendo caracteres comunes en targets)
    if not is_safe_input(target, allow_special=['.', '/', ':', '-', '_', '@']):
        return False

    if target_type == 'auto':
        # Intentar detectar tipo automáticamente
        if validate_ip_address(target) or validate_cidr(target):
            return True
        if validate_domain(target):
            return True
        if validate_url(target):
            return True
        if validate_aws_region(target):
            return True
        return False

    validators = {
        'ip': validate_ip_address,
        'cidr': validate_cidr,
        'domain': validate_domain,
        'url': validate_url,
        'region': validate_aws_region,
    }

    validator = validators.get(target_type)
    if validator:
        return validator(target)

    return False


# ============================================
# SANITIZACIÓN DE DATOS
# ============================================

def _is_sensitive_key(key: str) -> bool:
    """Verifica si una clave de diccionario contiene datos sensibles."""
    key_lower = key.lower()
    return any(sensitive in key_lower for sensitive in SENSITIVE_KEYS)


def sanitize_for_log(data: Union[str, dict, list, tuple, Any]) -> Union[str, dict, list, tuple, Any]:
    """
    Redacta datos sensibles en logs (recursivo para dicts/lists).
    Considera tanto patrones en valores COMO claves sensibles.

    Args:
        data: String, dict, list, tuple o cualquier tipo

    Returns:
        Mismo tipo con datos sensibles redactados como [REDACTED]
    """
    # Caso base: string
    if isinstance(data, str):
        result = data
        for pattern in SENSITIVE_PATTERNS:
            result = re.sub(pattern, '[REDACTED]', result, flags=re.IGNORECASE)
        return result

    # Caso recursivo: dict (con verificación de claves sensibles)
    elif isinstance(data, dict):
        return {
            key: '[REDACTED]' if _is_sensitive_key(key) else sanitize_for_log(value)
            for key, value in data.items()
        }

    # Caso recursivo: list
    elif isinstance(data, list):
        return [sanitize_for_log(item) for item in data]

    # Caso recursivo: tuple
    elif isinstance(data, tuple):
        return tuple(sanitize_for_log(item) for item in data)

    # Caso base: cualquier otro tipo (int, float, bool, None, etc.)
    return data


def redact_sensitive_values(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Redacta valores sensibles en un diccionario plano.

    Args:
        data: Diccionario con posibles datos sensibles

    Returns:
        Dict con valores sensibles redactados
    """
    if not isinstance(data, dict):
        return data

    result = {}
    for key, value in data.items():
        if _is_sensitive_key(key):
            result[key] = '[REDACTED]'
        elif isinstance(value, str):
            result[key] = sanitize_for_log(value)
        else:
            result[key] = value
    return result


# ============================================
# UTILIDADES DE SEGURIDAD
# ============================================

def mask_string(value: str, visible_chars: int = 4, mask_char: str = '*') -> str:
    """
    Enmascara un string mostrando solo los primeros caracteres.

    Args:
        value: String a enmascarar
        visible_chars: Número de caracteres visibles al inicio
        mask_char: Carácter para enmascarar

    Returns:
        String enmascarado (ej: "AKIA********")
    """
    if not value or len(value) <= visible_chars:
        return mask_char * len(value) if value else ''

    return value[:visible_chars] + mask_char * (len(value) - visible_chars)


def validate_port(port: Any) -> bool:
    """
    Valida si es un número de puerto válido (1-65535).

    Args:
        port: Valor a validar (int o str)

    Returns:
        bool: True si es válido
    """
    try:
        port_int = int(port)
        return 1 <= port_int <= 65535
    except (ValueError, TypeError):
        return False


def validate_aws_arn(arn: str) -> bool:
    """
    Valida si es un ARN de AWS válido.

    Args:
        arn: String con el ARN

    Returns:
        bool: True si es válido
    """
    if not arn or not isinstance(arn, str):
        return False

    # Patrón básico de ARN de AWS
    arn_pattern = r'^arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[a-zA-Z0-9/_+=.@,-]+$'
    return bool(re.match(arn_pattern, arn))


def is_private_ip(ip: str) -> bool:
    """
    Verifica si una IP es privada (RFC 1918).

    Args:
        ip: Dirección IP a verificar

    Returns:
        bool: True si es IP privada
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except (ValueError, TypeError):
        return False


def is_public_ip(ip: str) -> bool:
    """
    Verifica si una IP es pública (no privada, no loopback, etc.).

    Args:
        ip: Dirección IP a verificar

    Returns:
        bool: True si es IP pública
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast)
    except (ValueError, TypeError):
        return False


# ============================================
# BLOQUEO DE CARACTERES PELIGROSOS
# ============================================

def contains_dangerous_chars(value: Any, allow_special: Optional[List[str]] = None) -> bool:
    """
    Verifica si un valor contiene caracteres peligrosos.

    Args:
        value: Valor a verificar (str, dict, list)
        allow_special: Caracteres especiales permitidos

    Returns:
        bool: True si contiene caracteres peligrosos
    """
    if isinstance(value, str):
        return not is_safe_input(value, allow_special)

    elif isinstance(value, dict):
        return any(contains_dangerous_chars(v, allow_special) for v in value.values())

    elif isinstance(value, (list, tuple)):
        return any(contains_dangerous_chars(item, allow_special) for item in value)

    return False


def strip_dangerous_chars(value: str, replacement: str = '') -> str:
    """
    Elimina caracteres peligrosos de un string.

    Args:
        value: String a limpiar
        replacement: String para reemplazar caracteres peligrosos

    Returns:
        String limpio
    """
    if not isinstance(value, str):
        return str(value)

    result = value
    for char in DANGEROUS_CHARS:
        result = result.replace(char, replacement)
    return result


# ============================================
# VALIDACIÓN DE RUTAS DE ARCHIVOS
# ============================================

def is_safe_path(path: str, allowed_base: Optional[str] = None) -> bool:
    """
    Verifica si una ruta de archivo es segura (sin path traversal).

    Args:
        path: Ruta a validar
        allowed_base: Directorio base permitido (opcional)

    Returns:
        bool: True si es segura
    """
    if not path or not isinstance(path, str):
        return False

    # Verificar caracteres de path traversal
    if '..' in path or path.startswith('/'):
        return False

    # Si hay allowed_base, verificar que la ruta está dentro
    if allowed_base:
        import os
        try:
            resolved = os.path.realpath(path)
            base_resolved = os.path.realpath(allowed_base)
            return resolved.startswith(base_resolved + os.sep) or resolved == base_resolved
        except Exception:
            return False

    return True