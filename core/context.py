"""
Contexto de escaneo + Risk Scoring - ScanFlaws v4.0
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum
import hashlib


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class RiskScore:
    """Score de riesgo calculado con múltiples factores."""
    base_score: int  # 0-100 basado en severidad
    exposure_multiplier: float  # 1.0-3.0 basado en exposición
    business_criticality: float  # 1.0-2.0 basado en criticidad del recurso
    final_score: float = field(init=False)

    def __post_init__(self):
        self.final_score = min(100, self.base_score * self.exposure_multiplier * self.business_criticality)

    @property
    def risk_level(self) -> str:
        if self.final_score >= 80:
            return "CRITICAL"
        elif self.final_score >= 60:
            return "HIGH"
        elif self.final_score >= 40:
            return "MEDIUM"
        elif self.final_score >= 20:
            return "LOW"
        return "MINIMAL"


def calculate_risk_score(finding: Dict, context: Optional['ScanContext'] = None) -> RiskScore:
    """
    Calcula score de riesgo para un hallazgo.

    Factores considerados:
    - Severidad base del hallazgo
    - Exposición a internet
    - Criticidad del recurso (root, prod, etc.)
    - Correlación con otros hallazgos
    """
    # Score base por severidad
    severity_scores = {
        Severity.CRITICAL.value: 100,
        Severity.HIGH.value: 75,
        Severity.MEDIUM.value: 50,
        Severity.LOW.value: 25,
        Severity.INFO.value: 10,
    }
    base = severity_scores.get(finding.get('severity', 'INFO'), 10)

    # Multiplicador por exposición
    exposure = 1.0
    entity = finding.get('entity', '').lower()

    if '0.0.0.0/0' in str(finding) or 'public' in entity or 'internet' in entity:
        exposure = 3.0  # Expuesto a internet
    elif any(ip in entity for ip in ['10.', '192.168.', '172.16.']):
        exposure = 1.5  # Red privada
    else:
        exposure = 2.0  # Exposición desconocida (asumir riesgo)

    # Criticidad del recurso
    criticality = 1.0
    critical_keywords = ['root', 'admin', 'prod', 'production', 'master', 'primary']
    if any(kw in entity for kw in critical_keywords):
        criticality = 2.0

    return RiskScore(
        base_score=base,
        exposure_multiplier=exposure,
        business_criticality=criticality
    )


@dataclass
class ScanContext:
    """Contexto enriquecido con scoring y correlación."""

    # ... (usar la clase de decision_engine.py como base)

    def get_prioritized_findings(self, limit: Optional[int] = None) -> List[Dict]:
        """
        Retorna hallazgos ordenados por riesgo (más críticos primero).

        Args:
            limit: Máximo de hallazgos a retornar (None = todos)

        Returns:
            Lista de hallazgos con score calculado, ordenados
        """
        scored = []
        for finding in self.vulnerabilities:
            risk = calculate_risk_score(finding, self)
            finding_with_score = finding.copy()
            finding_with_score['risk_score'] = risk.final_score
            finding_with_score['risk_level'] = risk.risk_level
            scored.append(finding_with_score)

        # Ordenar por score descendente
        scored.sort(key=lambda x: x['risk_score'], reverse=True)

        if limit:
            return scored[:limit]
        return scored

    def get_executive_summary(self) -> Dict[str, Any]:
        """Genera resumen ejecutivo para reporte."""
        if not self.vulnerabilities:
            return {
                'status': 'SECURE',
                'message': 'No se encontraron vulnerabilidades',
                'total_findings': 0,
            }

        prioritized = self.get_prioritized_findings()

        # Conteos por nivel de riesgo
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'MINIMAL': 0}
        for f in prioritized:
            level = f.get('risk_level', 'MINIMAL')
            risk_counts[level] = risk_counts.get(level, 0) + 1

        # Determinar estado general
        if risk_counts['CRITICAL'] > 0:
            status = 'CRITICAL_RISK'
        elif risk_counts['HIGH'] > 2:
            status = 'HIGH_RISK'
        elif risk_counts['MEDIUM'] > 5:
            status = 'MEDIUM_RISK'
        else:
            status = 'LOW_RISK'

        return {
            'status': status,
            'total_findings': len(self.vulnerabilities),
            'risk_distribution': risk_counts,
            'top_risks': prioritized[:5],  # Top 5 más críticos
            'scan_timestamp': datetime.now().isoformat(),
            'phases_executed': list(self.executed_phases),
        }