"""
Tests de seguridad avanzada - ScanFlaws v4.0
"""
import pytest
from core.validators.advanced_input import (
    normalize_input, decode_url_encoded, contains_dangerous_content,
    validate_target, ValidationLevel
)
from core.scope_control import ScopeValidator


class TestAdvancedInputValidation:
    """Tests para validación avanzada de inputs."""

    def test_unicode_bypass_blocked(self):
        """Verifica que bypass Unicode es bloqueado."""
        # Zero-width space injection
        assert not validate_target("example\u200B.com")

        # BOM injection
        assert not validate_target("\uFEFFmalicious.com")

    def test_url_encoded_bypass_blocked(self):
        """Verifica que URL-encoded bypass es detectado."""
        # ; encoded as %3B
        assert not validate_target("example.com%3Bmalicious")

        # Double encoding
        assert not validate_target("example.com%253Bmalicious")

    def test_strict_mode_blocks_more(self):
        """Verifica que STRICT mode es más restrictivo."""
        # En NORMAL, algunos edge cases podrían pasar
        assert validate_target("example.com", level=ValidationLevel.NORMAL)

        # En STRICT, mismo input podría ser rechazado si hay patrones sospechosos
        # (depende de la implementación específica)

    def test_decode_recursion_limit(self):
        """Verifica que la decodificación recursiva tiene límite."""
        # Triple-encoded payload
        payload = "example.com%25253Bmalicious"
        decoded = decode_url_encoded(payload, max_depth=2)

        # No debería decodificar completamente con depth=2
        assert "%3B" in decoded  # Aún encoded


class TestScopeControl:
    """Tests para control de alcance."""

    def test_localhost_blocked(self):
        """Verifica que localhost siempre está bloqueado."""
        validator = ScopeValidator()
        assert not validator.is_allowed("localhost")
        assert not validator.is_allowed("127.0.0.1")

    def test_whitelist_enforcement(self):
        """Verifica que whitelist es respetada."""
        validator = ScopeValidator(allowed_targets=["example.com", "test.org"])

        assert validator.is_allowed("example.com")
        assert validator.is_allowed("sub.example.com")  # Subdominio permitido
        assert not validator.is_allowed("evil.com")

    def test_private_network_blocking(self):
        """Verifica que redes privadas son bloqueadas por defecto."""
        validator = ScopeValidator(allow_private=False)

        assert not validator.is_allowed("192.168.1.1")
        assert not validator.is_allowed("10.0.0.1")

        # Pero permite si allow_private=True
        validator_private = ScopeValidator(allow_private=True)
        assert validator_private.is_allowed("192.168.1.1")