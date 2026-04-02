"""
Módulo para resultados estructurados de escaneo + scoring de riesgo
ScanFlaws Security Hardening
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
import hashlib


class Severity(Enum):
    """Niveles de severidad estandarizados."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScanStatus(Enum):
    """Estados posibles de un escaneo."""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class ScanFinding:
    """Representa un hallazgo individual de seguridad."""
    check_name: str
    entity: str
    issue: str
    severity: Severity
    timestamp: datetime = field(default_factory=datetime.now)
    extra_data: Dict[str, Any] = field(default_factory=dict)
    recommendation: Optional[str] = None
    cve_id: Optional[str] = None
    remediation_script: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario para serialización."""
        return {
            'check': self.check_name,
            'entity': self.entity,
            'issue': self.issue,
            'severity': self.severity.value,
            'timestamp': self.timestamp.isoformat(),
            'extra_data': self.extra_data,
            'recommendation': self.recommendation,
            'cve_id': self.cve_id,
        }

    def get_risk_score(self) -> int:
        """Calcula score de riesgo numérico (0-100)."""
        base_scores = {
            Severity.CRITICAL: 100,
            Severity.HIGH: 75,
            Severity.MEDIUM: 50,
            Severity.LOW: 25,
            Severity.INFO: 10,
        }

        score = base_scores.get(self.severity, 0)

        # Factores adicionales
        if self.cve_id:
            score = min(100, score + 10)  # CVE conocido aumenta riesgo

        if 'root' in self.entity.lower() or 'admin' in self.entity.lower():
            score = min(100, score + 15)  # Entidades privilegiadas

        return score


@dataclass
class ScanResult:
    """Resultado estructurado de un escaneo completo."""
    success: bool
    phase: str
    findings: List[ScanFinding] = field(default_factory=list)
    error: Optional[str] = None
    duration_seconds: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def overall_risk_score(self) -> int:
        """Calcula score de riesgo promedio ponderado."""
        if not self.findings:
            return 0

        total_score = sum(f.get_risk_score() for f in self.findings)
        return round(total_score / len(self.findings))

    @property
    def risk_level(self) -> str:
        """Determina nivel de riesgo basado en score."""
        score = self.overall_risk_score
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        return "MINIMAL"

    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario para serialización."""
        return {
            'success': self.success,
            'phase': self.phase,
            'findings': [f.to_dict() for f in self.findings],
            'error': self.error,
            'duration_seconds': self.duration_seconds,
            'metadata': self.metadata,
            'summary': {
                'total_findings': self.total_findings,
                'critical': self.critical_count,
                'high': self.high_count,
                'risk_score': self.overall_risk_score,
                'risk_level': self.risk_level,
            }
        }

    def get_fingerprint(self) -> str:
        """Genera hash único para este resultado (para deduplicación)."""
        content = f"{self.phase}:{self.total_findings}:{self.overall_risk_score}"
        for f in self.findings:
            content += f"{f.check_name}:{f.entity}:{f.severity.value}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]