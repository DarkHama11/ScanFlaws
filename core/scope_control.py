"""
Control de alcance (scope) - Prevención de escaneo no autorizado
ScanFlaws v4.0
"""
import ipaddress
from typing import List, Set, Optional
from core.validators.advanced_input import validate_target

# 🚫 Targets bloqueados por defecto (nunca escanear)
BLOCKED_PATTERNS = {
    'localhost', '127.0.0.1', '::1',
    '0.0.0.0', '255.255.255.255',
}

# 🚫 Rangos de red privados (RFC1918) - bloquear si no es explícitamente permitido
PRIVATE_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
]


class ScopeValidator:
    """Valida que los targets estén dentro del alcance autorizado."""

    def __init__(self, allowed_targets: Optional[List[str]] = None,
                 allow_private: bool = False):
        """
        Args:
            allowed_targets: Lista blanca de targets permitidos (None = validar formato)
            allow_private: Si True, permite escanear redes privadas
        """
        self.allowed_targets = set(t.lower() for t in (allowed_targets or []))
        self.allow_private = allow_private

    def is_allowed(self, target: str) -> bool:
        """
        Verifica si un target está autorizado para escaneo.

        Returns:
            bool: True si permitido, False si bloqueado
        """
        normalized = target.lower().strip()

        # 1. Verificar contra lista negra
        if normalized in BLOCKED_PATTERNS:
            return False

        # 2. Si hay whitelist, verificar que esté incluida
        if self.allowed_targets:
            if normalized not in self.allowed_targets:
                # Verificar si es subdominio de un dominio permitido
                for allowed in self.allowed_targets:
                    if normalized.endswith(f'.{allowed}'):
                        return True
                return False

        # 3. Validar formato básico
        if not validate_target(normalized):
            return False

        # 4. Si es IP, verificar si es privada
        try:
            ip = ipaddress.ip_address(normalized)
            if not self.allow_private:
                if any(ip in network for network in PRIVATE_RANGES) or ip.is_loopback:
                    return False
        except ValueError:
            pass  # No es IP, continuar

        return True

    def validate_targets(self, targets: List[str]) -> List[str]:
        """
        Filtra una lista de targets, retornando solo los autorizados.

        Returns:
            Lista de targets válidos
        """
        return [t for t in targets if self.is_allowed(t)]

    def get_blocked_reason(self, target: str) -> Optional[str]:
        """Retorna razón por la cual un target fue bloqueado."""
        normalized = target.lower().strip()

        if normalized in BLOCKED_PATTERNS:
            return "Target en lista negra de seguridad"

        if self.allowed_targets and normalized not in self.allowed_targets:
            return "Target no incluido en lista blanca autorizada"

        if not validate_target(normalized):
            return "Formato de target inválido"

        try:
            ip = ipaddress.ip_address(normalized)
            if not self.allow_private:
                if any(ip in network for network in PRIVATE_RANGES):
                    return "Red privada bloqueada (configurar allow_private=True)"
        except ValueError:
            pass

        return "Target no autorizado"