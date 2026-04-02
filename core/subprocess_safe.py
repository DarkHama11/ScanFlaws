"""
Módulo para ejecución segura de comandos externos
ScanFlaws Security Hardening - Sin shell=True
"""
import subprocess
from typing import List, Optional, Union
from core.security import is_safe_input
from core.logger import get_logger

logger = get_logger(__name__)

# Timeout por defecto para comandos externos (segundos)
DEFAULT_TIMEOUT = 60

# Comandos permitidos (whitelist)
ALLOWED_COMMANDS = {
    'nmap',
    'aws',
    'docker',
    'kubectl',
    # Agregar más según necesidad
}


class SafeSubprocessError(Exception):
    """Excepción para errores de subprocess seguro."""
    pass


def validate_command(cmd: List[str]) -> bool:
    """
    Valida que un comando sea seguro para ejecutar.

    Args:
        cmd: Lista de argumentos [comando, arg1, arg2, ...]

    Returns:
        bool: True si es válido
    """
    if not cmd or not isinstance(cmd, list):
        return False

    # Verificar que el comando base está en whitelist
    if cmd[0] not in ALLOWED_COMMANDS:
        logger.warning(f"Comando no permitido: {cmd[0]}")
        return False

    # Verificar que ningún argumento contiene caracteres peligrosos
    for arg in cmd:
        if isinstance(arg, str) and not is_safe_input(arg, allow_special=['.', '/', ':', '-', '_', '*', '?']):
            logger.warning(f"Argumento inseguro detectado: {arg}")
            return False

    return True


def run_safe_command(
        cmd: List[str],
        timeout: int = DEFAULT_TIMEOUT,
        check: bool = True,
        capture_output: bool = True
) -> subprocess.CompletedProcess:
    """
    Ejecuta un comando de forma segura (sin shell=True).

    Args:
        cmd: Lista de argumentos [comando, arg1, arg2, ...]
        timeout: Timeout en segundos
        check: Si True, lanza CalledProcessError si el comando falla
        capture_output: Si True, captura stdout/stderr

    Returns:
        subprocess.CompletedProcess con el resultado

    Raises:
        SafeSubprocessError: Si la validación falla o hay error de ejecución
    """
    # Validar comando
    if not validate_command(cmd):
        raise SafeSubprocessError(f"Comando rechazado por seguridad: {' '.join(cmd)}")

    try:
        logger.info(f"Ejecutando comando seguro: {' '.join(cmd[:3])}...")  # Log parcial por seguridad

        result = subprocess.run(
            cmd,
            shell=False,  # 🔒 CRÍTICO: Nunca usar shell=True
            timeout=timeout,
            check=check,
            capture_output=capture_output,
            text=True
        )

        logger.debug(f"Comando completado con código {result.returncode}")
        return result

    except subprocess.TimeoutExpired as e:
        logger.error(f"Timeout en comando: {' '.join(cmd[:3])}")
        raise SafeSubprocessError(f"Timeout después de {timeout}s") from e

    except subprocess.CalledProcessError as e:
        logger.error(f"Error en comando: {e.returncode}")
        raise SafeSubprocessError(f"Comando falló con código {e.returncode}") from e

    except FileNotFoundError:
        logger.error(f"Comando no encontrado: {cmd[0]}")
        raise SafeSubprocessError(f"Comando '{cmd[0]}' no instalado")

    except Exception as e:
        logger.error(f"Error inesperado: {e}")
        raise SafeSubprocessError(f"Error ejecutando comando: {e}") from e


def run_safe_command_with_retry(
        cmd: List[str],
        max_retries: int = 3,
        timeout: int = DEFAULT_TIMEOUT
) -> Optional[subprocess.CompletedProcess]:
    """
    Ejecuta un comando con reintentos en caso de fallo transitorio.

    Args:
        cmd: Lista de argumentos
        max_retries: Número máximo de intentos
        timeout: Timeout por intento

    Returns:
        subprocess.CompletedProcess o None si falla después de todos los intentos
    """
    import time

    for attempt in range(max_retries):
        try:
            return run_safe_command(cmd, timeout=timeout)
        except SafeSubprocessError as e:
            if attempt == max_retries - 1:
                logger.error(f"Falló después de {max_retries} intentos: {e}")
                return None
            logger.warning(f"Intento {attempt + 1} falló, reintentando...")
            time.sleep(2 ** attempt)  # Backoff exponencial

    return None