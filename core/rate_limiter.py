"""
Módulo de rate limiting para prevenir abuso
ScanFlaws Security Hardening
"""
import time
from collections import defaultdict, deque
from typing import Optional
from threading import Lock


class RateLimiter:
    """
    Rate limiter simple basado en ventana deslizante.
    Thread-safe para uso concurrente.
    """

    def __init__(self, max_calls: int, window_seconds: float):
        """
        Inicializa el rate limiter.

        Args:
            max_calls: Número máximo de llamadas permitidas
            window_seconds: Ventana de tiempo en segundos
        """
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self.calls = defaultdict(deque)
        self.lock = Lock()

    def allow(self, key: str = 'default') -> bool:
        """
        Verifica si se permite una llamada para la clave dada.

        Args:
            key: Identificador para limitar (ej: IP, usuario, endpoint)

        Returns:
            bool: True si se permite la llamada, False si se excedió el límite
        """
        with self.lock:
            now = time.time()
            window_start = now - self.window_seconds

            # Limpiar llamadas antiguas fuera de la ventana
            while self.calls[key] and self.calls[key][0] < window_start:
                self.calls[key].popleft()

            # Verificar si hay espacio
            if len(self.calls[key]) < self.max_calls:
                self.calls[key].append(now)
                return True

            return False

    def get_remaining(self, key: str = 'default') -> int:
        """Obtiene cuántas llamadas restantes hay en la ventana actual."""
        with self.lock:
            now = time.time()
            window_start = now - self.window_seconds

            # Limpiar primero
            while self.calls[key] and self.calls[key][0] < window_start:
                self.calls[key].popleft()

            return max(0, self.max_calls - len(self.calls[key]))

    def reset(self, key: str = 'default'):
        """Reseta el contador para una clave."""
        with self.lock:
            self.calls[key].clear()


# Instancia global para uso común
# Configurar según necesidades: 10 llamadas por minuto por defecto
global_limiter = RateLimiter(max_calls=10, window_seconds=60)


def rate_limit_check(key: Optional[str] = None, max_calls: int = 10, window_seconds: float = 60) -> bool:
    """
    Función helper para verificar rate limit rápidamente.

    Args:
        key: Clave para limitar (default: timestamp para limitar global)
        max_calls: Límite de llamadas
        window_seconds: Ventana en segundos

    Returns:
        bool: True si permitido, False si excedido
    """
    if key is None:
        key = f"global_{int(time.time() // window_seconds)}"

    limiter = RateLimiter(max_calls, window_seconds)
    return limiter.allow(key)