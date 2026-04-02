"""
Módulo para manejo seguro de archivos
ScanFlaws Security Hardening - Path traversal protection
"""
import os
import uuid
import json
from pathlib import Path
from typing import Optional, Union
from core.security import is_safe_input
from core.logger import get_logger

logger = get_logger(__name__)

# Directorio base para archivos generados (configurable)
BASE_OUTPUT_DIR = Path(__file__).parent.parent / 'reports'


def generate_safe_filename(prefix: str, extension: str) -> str:
    """
    Genera un nombre de archivo seguro con UUID.

    Args:
        prefix: Prefijo descriptivo (ej: 'scan', 'report')
        extension: Extensión del archivo (ej: 'json', 'csv')

    Returns:
        str: Nombre de archivo seguro (ej: 'scan_a1b2c3d4.json')
    """
    # Validar prefix y extension
    if not is_safe_input(prefix, allow_special=['_', '-']):
        raise ValueError(f"Prefix inseguro: {prefix}")

    if not is_safe_input(extension):
        raise ValueError(f"Extensión insegura: {extension}")

    # Generar nombre con UUID
    unique_id = uuid.uuid4().hex[:8]
    timestamp = uuid.uuid4().hex[:8]  # Usar parte de UUID como timestamp seguro

    return f"{prefix}_{unique_id}_{timestamp}.{extension}"


def sanitize_path(user_path: Union[str, Path], base_dir: Optional[Path] = None) -> Path:
    """
    Sanitiza una ruta proporcionada por el usuario para prevenir path traversal.

    Args:
        user_path: Ruta proporcionada por el usuario
        base_dir: Directorio base permitido (default: BASE_OUTPUT_DIR)

    Returns:
        Path: Ruta absoluta y segura dentro de base_dir

    Raises:
        ValueError: Si la ruta intenta salir de base_dir
    """
    if base_dir is None:
        base_dir = BASE_OUTPUT_DIR

    # Convertir a Path y resolver ruta absoluta
    user_path = Path(user_path).resolve()
    base_dir = base_dir.resolve()

    # Verificar que la ruta está dentro del directorio base
    try:
        user_path.relative_to(base_dir)
    except ValueError:
        logger.warning(f"Intento de path traversal detectado: {user_path}")
        raise ValueError(f"Ruta fuera del directorio permitido: {user_path}")

    return user_path


def save_json_safe(data: dict, filename: Optional[str] = None, directory: Optional[Path] = None) -> Path:
    """
    Guarda datos JSON de forma segura.

    Args:
        data: Diccionario a guardar
        filename: Nombre opcional (se genera uno seguro si no se proporciona)
        directory: Directorio opcional (default: BASE_OUTPUT_DIR)

    Returns:
        Path: Ruta del archivo guardado
    """
    if directory is None:
        directory = BASE_OUTPUT_DIR

    # Crear directorio si no existe
    directory.mkdir(parents=True, exist_ok=True)

    # Generar nombre seguro si no se proporciona
    if filename is None:
        filename = generate_safe_filename('report', 'json')
    elif not filename.endswith('.json'):
        filename = f"{filename}.json"

    # Sanitizar ruta completa
    filepath = sanitize_path(directory / filename, base_dir=directory)

    # Guardar con encoding UTF-8
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    logger.info(f"Reporte JSON guardado: {filepath.name}")
    return filepath


def load_json_safe(filepath: Union[str, Path], base_dir: Optional[Path] = None) -> Optional[dict]:
    """
    Carga datos JSON de forma segura.

    Args:
        filepath: Ruta del archivo a cargar
        base_dir: Directorio base permitido

    Returns:
        dict o None si hay error
    """
    try:
        filepath = sanitize_path(filepath, base_dir)

        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)

    except json.JSONDecodeError as e:
        logger.error(f"Error parseando JSON: {e}")
        return None
    except Exception as e:
        logger.error(f"Error cargando archivo: {e}")
        return None