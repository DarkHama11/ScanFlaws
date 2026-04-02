"""
Validación estructural con Pydantic - ScanFlaws v4.0
Compatible con Pydantic v2.x
"""
from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """Niveles de severidad estandarizados."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Finding(BaseModel):
    """
    Hallazgo de seguridad validado estructuralmente.
    Pydantic v2 model con validaciones automáticas.
    """
    # Campos requeridos
    check: str = Field(..., min_length=1, max_length=200, description="Nombre del check de seguridad")
    entity: str = Field(..., min_length=1, description="Entidad afectada (usuario, recurso, etc.)")
    issue: str = Field(..., min_length=10, description="Descripción del problema detectado")
    severity: Severity = Field(..., description="Nivel de severidad del hallazgo")

    # Campo con default
    timestamp: datetime = Field(default_factory=datetime.now, description="Timestamp del hallazgo")

    # Campos opcionales
    recommendation: Optional[str] = Field(None, description="Recomendación de remediación")
    cve_id: Optional[str] = Field(None, description="ID de CVE si aplica")
    risk_score: Optional[float] = Field(None, ge=0, le=100, description="Score de riesgo 0-100")
    extra_data: Optional[Dict[str, Any]] = Field(None, description="Datos adicionales del hallazgo")

    # Config para Pydantic v2
    model_config = ConfigDict(
        populate_by_name=True,
        use_enum_values=True,  # Convierte Enums a strings para JSON
        json_schema_extra={
            "example": {
                "check": "Usuarios sin MFA",
                "entity": "admin-user",
                "issue": "Usuario sin autenticación de dos factores",
                "severity": "HIGH",
                "recommendation": "Habilitar MFA en la consola de AWS"
            }
        }
    )

    # 🔐 Validadores Pydantic v2
    @field_validator('cve_id')
    @classmethod
    def validate_cve_format(cls, v: Optional[str]) -> Optional[str]:
        """Valida que el CVE tenga formato correcto."""
        if v and not v.upper().startswith('CVE-'):
            raise ValueError('CVE ID debe empezar con CVE- (ej: CVE-2024-1234)')
        return v.upper() if v else v

    @field_validator('risk_score')
    @classmethod
    def validate_risk_range(cls, v: Optional[float]) -> Optional[float]:
        """Valida que el risk_score esté entre 0 y 100."""
        if v is not None and not (0 <= v <= 100):
            raise ValueError('Risk score debe estar entre 0 y 100')
        return v

    @field_validator('entity')
    @classmethod
    def sanitize_entity(cls, v: str) -> str:
        """Sanitiza la entidad para prevenir injection en logs."""
        dangerous = ['<', '>', '&', '"', "'", '\\', ';', '`', '$']
        for char in dangerous:
            v = v.replace(char, '')
        return v.strip()

    # Métodos helper
    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario para serialización."""
        return self.model_dump(exclude_none=True)

    def get_summary(self) -> str:
        """Retorna resumen legible del hallazgo."""
        # Pydantic v2 con use_enum_values=True convierte enum a string
        severity_value = self.severity.value if hasattr(self.severity, 'value') else self.severity
        return f"[{severity_value}] {self.check}: {self.issue}"


class ScanResult(BaseModel):
    """
    Resultado de escaneo validado estructuralmente.
    Agrega metadata y métodos de análisis.
    """
    # Campos requeridos
    success: bool = Field(..., description="Si el escaneo se completó exitosamente")
    phase: str = Field(..., description="Fase del escaneo (identity, storage, compute, etc.)")

    # Campos con defaults
    findings: List[Finding] = Field(default_factory=list, description="Lista de hallazgos")
    error: Optional[str] = Field(None, description="Mensaje de error si success=False")
    duration_seconds: Optional[float] = Field(None, ge=0, description="Duración del escaneo en segundos")

    # Metadata automática
    scan_id: str = Field(
        default_factory=lambda: datetime.now().strftime("%Y%m%d_%H%M%S"),
        description="ID único del escaneo"
    )
    scanner_version: str = Field(default="4.0-hardened", description="Versión del scanner")

    # Config Pydantic v2
    model_config = ConfigDict(
        populate_by_name=True,
        use_enum_values=True
    )

    # 🔐 Validadores
    @field_validator('phase')
    @classmethod
    def validate_phase_name(cls, v: str) -> str:
        """Valida que el nombre de fase sea reconocido."""
        valid_phases = ['identity', 'storage', 'compute', 'network', 'governance', 'discovery', 'report']
        if v.lower() not in valid_phases:
            raise ValueError(f'Fase no válida. Opciones: {", ".join(valid_phases)}')
        return v.lower()

    # Propiedades calculadas
    @property
    def total_findings(self) -> int:
        """Total de hallazgos encontrados."""
        return len(self.findings)

    @property
    def has_critical(self) -> bool:
        """Verifica si hay al menos un hallazgo crítico."""
        for f in self.findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else f.severity
            if sev == 'CRITICAL':
                return True
        return False

    @property
    def has_high(self) -> bool:
        """Verifica si hay hallazgos de alta severidad."""
        for f in self.findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else f.severity
            if sev == 'HIGH':
                return True
        return False

    @property
    def overall_risk(self) -> str:
        """Calcula nivel de riesgo general basado en hallazgos."""
        if not self.findings:
            return "MINIMAL"

        # Helper para obtener valor de severidad
        def get_severity(finding):
            return finding.severity.value if hasattr(finding.severity, 'value') else finding.severity

        if any(get_severity(f) == 'CRITICAL' for f in self.findings):
            return "CRITICAL"

        high_count = sum(1 for f in self.findings if get_severity(f) == 'HIGH')
        if high_count >= 3:
            return "HIGH"

        medium_count = sum(1 for f in self.findings if get_severity(f) == 'MEDIUM')
        if medium_count >= 5:
            return "MEDIUM"

        return "LOW"

    @property
    def risk_summary(self) -> Dict[str, int]:
        """Retorna conteo de hallazgos por severidad."""
        summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in self.findings:
            # Manejar tanto Enum como string
            severity_value = f.severity.value if hasattr(f.severity, 'value') else f.severity
            if severity_value in summary:
                summary[severity_value] += 1
        return summary

    # Métodos de exportación
    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario para serialización JSON."""
        result = self.model_dump(exclude_none=True)
        result['risk_summary'] = self.risk_summary
        result['overall_risk'] = self.overall_risk
        return result

    def to_json(self) -> str:
        """Exporta a JSON string."""
        import json
        return json.dumps(self.to_dict(), indent=2, default=str)

    def get_top_risks(self, limit: int = 5) -> List[Finding]:
        """Retorna los hallazgos de mayor severidad."""

        # Helper para obtener valor de severidad
        def get_severity_value(finding):
            return finding.severity.value if hasattr(finding.severity, 'value') else finding.severity

        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_findings = sorted(
            self.findings,
            key=lambda f: severity_order.get(get_severity_value(f), 5)
        )
        return sorted_findings[:limit]


class ScanConfig(BaseModel):
    """
    Configuración de escaneo validada.
    Centraliza parámetros de ejecución con validación automática.
    Compatible con Pydantic v2.
    """
    # Campos requeridos
    targets: List[str] = Field(..., min_length=1, description="Lista de targets a escanear")

    # Campos con defaults
    phases: List[str] = Field(
        default=["identity", "storage", "compute"],
        description="Fases a ejecutar"
    )

    # Modos de ejecución
    safe_mode: bool = Field(default=False, description="Modo seguro: solo lecturas, sin acciones")
    aggressive_mode: bool = Field(default=False, description="Modo agresivo: scans más profundos")

    # Límites de recursos
    max_concurrent: int = Field(default=5, ge=1, le=20, description="Máximo de procesos concurrentes")
    timeout_seconds: int = Field(default=300, ge=30, le=3600, description="Timeout por fase en segundos")

    # Alcance y permisos
    allowed_regions: Optional[List[str]] = Field(None, description="Regiones AWS permitidas")
    allow_private_ips: bool = Field(default=False, description="Permitir escaneo de IPs privadas")

    # Config Pydantic v2
    model_config = ConfigDict(
        populate_by_name=True,
        validate_assignment=True
    )

    # 🔐 Validadores Pydantic v2 (sin each_item)

    @field_validator('targets', mode='before')
    @classmethod
    def normalize_targets(cls, v: Any) -> List[str]:
        """Normaliza y valida la lista de targets."""
        if isinstance(v, str):
            # Convertir string único a lista
            v = [t.strip() for t in v.split(',') if t.strip()]

        if not isinstance(v, list):
            raise ValueError('targets debe ser una lista o string comma-separated')

        # Validar cada target manualmente (Pydantic v2 way)
        normalized = []
        for target in v:
            t = str(target).strip().lower()
            if not t or len(t) > 253:
                raise ValueError(f'Target inválido: "{target}"')
            # Bloquear localhost y patrones peligrosos
            if t in ['localhost', '127.0.0.1', '::1', '0.0.0.0']:
                raise ValueError(f'Target bloqueado por seguridad: "{target}"')
            normalized.append(t)

        if not normalized:
            raise ValueError('Debe proporcionar al menos un target válido')

        return normalized

    @field_validator('phases')
    @classmethod
    def validate_phase_names(cls, v: List[str]) -> List[str]:
        """Valida que cada fase en la lista sea reconocida (Pydantic v2)."""
        valid_phases = ['identity', 'storage', 'compute', 'network', 'governance', 'discovery', 'report']
        for phase in v:
            if phase.lower() not in valid_phases:
                raise ValueError(f'Fase no válida: "{phase}". Opciones: {", ".join(valid_phases)}')
        return [p.lower() for p in v]

    @field_validator('allowed_regions')
    @classmethod
    def validate_aws_regions(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Valida formato de regiones AWS en la lista (Pydantic v2)."""
        if v is None:
            return None

        import re
        region_pattern = re.compile(r'^[a-z]{2}-(north|south|east|west|central)?-?\d{1,2}$')

        validated = []
        for region in v:
            r = region.lower().strip()
            if not region_pattern.match(r):
                raise ValueError(f'Región AWS no válida: "{region}"')
            validated.append(r)

        return validated

    # Métodos helper
    @property
    def is_production_ready(self) -> bool:
        """Verifica si la configuración es segura para producción."""
        return self.safe_mode or not self.aggressive_mode

    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario para logging/serialización."""
        return self.model_dump(exclude_none=True)