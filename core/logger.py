"""
Módulo de logging seguro con redacción de datos sensibles
ScanFlaws Security Hardening
"""
import logging
import sys
from typing import Optional
from core.security import sanitize_for_log

# Configuración global del logger
_logger: Optional[logging.Logger] = None


def setup_logger(
        name: str = 'scanflaws',
        level: int = logging.INFO,
        log_file: Optional[str] = None,
        redact_sensitive: bool = True
) -> logging.Logger:
    """
    Configura y retorna un logger seguro.

    Args:
        name: Nombre del logger
        level: Nivel de logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Archivo opcional para guardar logs
        redact_sensitive: Si True, redacta datos sensibles automáticamente

    Returns:
        logging.Logger configurado
    """
    global _logger

    if _logger is not None:
        return _logger

    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Evitar duplicación de handlers
    if logger.handlers:
        return logger

    # Formatter con timestamp
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Handler para consola
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Handler opcional para archivo
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    _logger = logger
    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Obtiene el logger global o crea uno nuevo."""
    if name is None:
        return setup_logger()
    return setup_logger(name=name)


class SafeLogger:
    """Wrapper para logging con redacción automática."""

    def __init__(self, logger: logging.Logger, redact: bool = True):
        self.logger = logger
        self.redact = redact

    def _sanitize(self, message: str) -> str:
        """Redacta datos sensibles si está habilitado."""
        if self.redact:
            return sanitize_for_log(message)
        return message

    def debug(self, msg: str, *args, **kwargs):
        self.logger.debug(self._sanitize(msg), *args, **kwargs)

    def info(self, msg: str, *args, **kwargs):
        self.logger.info(self._sanitize(msg), *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs):
        self.logger.warning(self._sanitize(msg), *args, **kwargs)

    def error(self, msg: str, *args, **kwargs):
        self.logger.error(self._sanitize(msg), *args, **kwargs)

    def critical(self, msg: str, *args, **kwargs):
        self.logger.critical(self._sanitize(msg), *args, **kwargs)