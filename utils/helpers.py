"""
Funciones auxiliares reutilizables - ScanFlaws Utils
"""
from datetime import datetime, timezone


def parse_aws_date(date_string):
    """
    Convierte string de fecha de AWS a datetime object.
    Ej: '2024-01-15T10:30:00Z' -> datetime
    """
    if not date_string or date_string in ['N/A', 'no_information', None]:
        return None

    try:
        # Manejar formato ISO con Z
        if date_string.endswith('Z'):
            date_string = date_string.replace('Z', '+00:00')
        return datetime.fromisoformat(date_string)
    except Exception:
        return None


def days_since(date_string):
    """
    Calcula días transcurridos desde una fecha de AWS.
    Returns: int o None si no se puede parsear
    """
    parsed = parse_aws_date(date_string)
    if parsed is None:
        return None

    now = datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return (now - parsed).days


def is_public_cidr(cidr):
    """Verifica si un CIDR es público (0.0.0.0/0 o ::/0)"""
    return cidr in ['0.0.0.0/0', '::/0']


def mask_sensitive_data(value, visible_chars=4):
    """Enmascara datos sensibles (ej: access keys)"""
    if not value or len(value) <= visible_chars:
        return "***"
    return value[:visible_chars] + "***"