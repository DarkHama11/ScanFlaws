"""
Modelo central de Finding - ScanFlaws v5.0
Todos los hallazgos usan esta clase para consistencia
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """Niveles de severidad estandarizados."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """
    Modelo central para todos los hallazgos de seguridad.
    Garantiza consistencia en todo el pipeline.
    """
    # Campos básicos (requeridos)
    check: str
    entity: str
    severity: str
    issue: str = ""
    details: str = ""

    # Campos opcionales
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    recommendation: Optional[str] = None
    cve_id: Optional[str] = None
    extra_data: Optional[Dict[str, Any]] = None  # ✅ CORREGIDO: una sola línea

    # Campos de riesgo (inicializados en 0/vacío)
    score: int = 0
    context: Dict[str, Any] = field(default_factory=dict)
    correlated_findings: List['Finding'] = field(default_factory=list)

    # Metadata
    source: str = "scan"  # "scan", "correlation", "manual"
    risk_level: str = "LOW"  # Calculado del score

    def __post_init__(self):
        """Validación y normalización después de inicializar."""
        # Normalizar severidad a mayúsculas
        if isinstance(self.severity, str):
            self.severity = self.severity.upper()

        # Validar que severity sea válido
        valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        if self.severity not in valid_severities:
            self.severity = 'MEDIUM'

        # Inicializar context como dict si es None
        if self.context is None:
            self.context = {}

        # Calcular risk_level inicial basado en severity
        self._update_risk_level()

    def _update_risk_level(self):
        """Actualiza risk_level basado en el score."""
        if self.score >= 81:
            self.risk_level = "CRITICAL"
        elif self.score >= 61:
            self.risk_level = "HIGH"
        elif self.score >= 31:
            self.risk_level = "MEDIUM"
        else:
            self.risk_level = "LOW"

    def set_score(self, score: int):
        """
        Setea el score de forma segura y actualiza risk_level.

        Args:
            score: Score entre 0 y 100
        """
        self.score = max(0, min(100, int(score)))
        self._update_risk_level()

    def add_context(self, key: str, value: Any):
        """
        Agrega un valor al contexto de forma segura.

        Args:
            key: Clave del contexto
            value: Valor a agregar
        """
        if self.context is None:
            self.context = {}
        self.context[key] = value

    def add_correlated_finding(self, finding: 'Finding'):
        """
        Agrega un hallazgo correlacionado.

        Args:
            finding: Hallazgo a correlacionar
        """
        if finding is not None and finding not in self.correlated_findings:
            self.correlated_findings.append(finding)

    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario para serialización."""
        return {
            'check': self.check,
            'entity': self.entity,
            'severity': self.severity,
            'issue': self.issue,
            'details': self.details,
            'timestamp': self.timestamp,
            'recommendation': self.recommendation,
            'cve_id': self.cve_id,
            'extra_data': self.extra_data,
            'score': self.score,
            'context': self.context,
            'risk_level': self.risk_level,
            'source': self.source,
            'correlated_count': len(self.correlated_findings),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """
        Crea un Finding desde un diccionario.

        Args:
            data: Diccionario con los datos del hallazgo

        Returns:
            Finding: Objeto Finding creado
        """
        return cls(
            check=data.get('check', 'Unknown'),
            entity=data.get('entity', 'Unknown'),
            severity=data.get('severity', 'MEDIUM'),
            issue=data.get('issue', data.get('details', '')),
            details=data.get('details', ''),
            recommendation=data.get('recommendation'),
            cve_id=data.get('cve_id'),
            extra_data=data.get('extra_data'),
        )

    def __str__(self) -> str:
        """Representación string del hallazgo."""
        return f"[{self.severity}] {self.check}: {self.entity}"

    def __repr__(self) -> str:
        """Representación para debugging."""
        return f"Finding(check='{self.check}', entity='{self.entity}', score={self.score})"


def normalize_to_finding(data: Any) -> Finding:
    """
    Normaliza cualquier input a un objeto Finding.

    Args:
        data: Dict, Finding, u otro formato

    Returns:
        Finding: Objeto Finding normalizado
    """
    if isinstance(data, Finding):
        return data

    if isinstance(data, dict):
        return Finding.from_dict(data)

    # Fallback para otros formatos
    return Finding(
        check=str(data),
        entity="unknown",
        severity="INFO",
        issue=str(data)
    )


def normalize_findings_list(findings: List[Any]) -> List[Finding]:
    """
    Normaliza una lista de hallazgos a lista de objetos Finding.

    Args:
        findings: Lista de hallazgos en cualquier formato

    Returns:
        List[Finding]: Lista normalizada
    """
    normalized = []
    for f in findings:
        try:
            normalized.append(normalize_to_finding(f))
        except Exception as e:
            # Logear error pero continuar
            print(f"[!] Error normalizando hallazgo: {e}")
            continue
    return normalized