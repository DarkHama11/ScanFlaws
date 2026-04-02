"""
Tests de seguridad para ScanFlaws
Valida protección contra vulnerabilidades comunes
"""
import pytest
from core.security import (
    is_safe_input, validate_ip_address, validate_domain,
    validate_target, sanitize_for_log, DANGEROUS_CHARS
)
from core.subprocess_safe import validate_command, SafeSubprocessError
from core.file_handler import sanitize_path, generate_safe_filename


class TestInputValidation:
    """Tests para validación de inputs."""

    def test_dangerous_chars_blocked(self):
        """Verifica que caracteres peligrosos son rechazados."""
        for char in DANGEROUS_CHARS:
            assert not is_safe_input(f"test{char}injection")

    def test_safe_inputs_allowed(self):
        """Verifica que inputs seguros son aceptados."""
        assert is_safe_input("example.com")
        assert is_safe_input("192.168.1.1")
        assert is_safe_input("my-resource_name-123")

    def test_ip_validation(self):
        """Tests para validación de IPs."""
        assert validate_ip_address("192.168.1.1")
        assert validate_ip_address("::1")
        assert not validate_ip_address("999.999.999.999")
        assert not validate_ip_address("not-an-ip")

    def test_domain_validation(self):
        """Tests para validación de dominios."""
        assert validate_domain("example.com")
        assert validate_domain("sub.example.co.uk")
        assert not validate_domain("http://example.com")  # URL, no dominio
        assert not validate_domain("example..com")  # Inválido

    def test_target_validation_auto(self):
        """Tests para validación automática de targets."""
        assert validate_target("10.0.0.1", target_type='auto')
        assert validate_target("example.com", target_type='auto')
        assert validate_target("us-east-1", target_type='auto')
        assert not validate_target("evil;rm -rf /", target_type='auto')


class TestSanitization:
    """Tests para sanitización de datos."""

    def test_sensitive_data_redacted(self):
        """Verifica que datos sensibles son redactados."""
        test_data = "API Key: AKIAIOSFODNN7EXAMPLE, password=secret123"
        sanitized = sanitize_for_log(test_data)

        assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
        assert "[REDACTED]" in sanitized

    def test_dict_sanitization(self):
        """Verifica sanitización en diccionarios."""
        data = {
            "user": "admin",
            "token": "super-secret-token",
            "config": {"password": "12345"}
        }
        sanitized = sanitize_for_log(data)

        assert sanitized["token"] == "[REDACTED]"
        assert sanitized["config"]["password"] == "[REDACTED]"


class TestPathSecurity:
    """Tests para seguridad de rutas de archivos."""

    def test_path_traversal_blocked(self):
        """Verifica que path traversal es bloqueado."""
        from pathlib import Path
        import pytest

        base = Path("/safe/dir")

        with pytest.raises(ValueError):
            sanitize_path("/safe/dir/../../../etc/passwd", base_dir=base)

        with pytest.raises(ValueError):
            sanitize_path("/etc/passwd", base_dir=base)

    def test_safe_filename_generation(self):
        """Verifica generación de nombres de archivo seguros."""
        filename = generate_safe_filename("report", "json")

        assert filename.startswith("report_")
        assert filename.endswith(".json")
        assert ".." not in filename
        assert "/" not in filename