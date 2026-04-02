"""
Risk Engine - Scoring avanzado de riesgos (0-100)
ScanFlaws v5.0 - Intelligent Risk Analysis
"""
from typing import Dict, List, Optional, Union
from enum import Enum
from dataclasses import dataclass


class RiskLevel(Enum):
    """Niveles de riesgo basados en score."""
    LOW = "LOW"  # 0-30
    MEDIUM = "MEDIUM"  # 31-60
    HIGH = "HIGH"  # 61-80
    CRITICAL = "CRITICAL"  # 81-100


@dataclass
class RiskScore:
    """Resultado del cálculo de riesgo."""
    base_score: int  # Score base por severidad (0-80)
    context_bonus: int  # Bonus por contexto (0-20)
    correlation_bonus: int  # Bonus por correlación (0-20)
    final_score: int  # Score final 0-100
    risk_level: RiskLevel  # Nivel clasificado

    @property
    def color_code(self) -> str:
        """Código de color para visualización."""
        colors = {
            RiskLevel.LOW: '🟢',
            RiskLevel.MEDIUM: '🟡',
            RiskLevel.HIGH: '🟠',
            RiskLevel.CRITICAL: '🔴'
        }
        return colors.get(self.risk_level, '⚪')

    def to_dict(self) -> Dict:
        return {
            'base_score': self.base_score,
            'context_bonus': self.context_bonus,
            'correlation_bonus': self.correlation_bonus,
            'final_score': self.final_score,
            'risk_level': self.risk_level.value,
            'color_code': self.color_code
        }


# Mapeo de severidad a score base
SEVERITY_BASE_SCORES = {
    'INFO': 5,
    'LOW': 10,
    'MEDIUM': 30,
    'HIGH': 60,
    'CRITICAL': 80
}

# Factores de contexto y sus bonuses
CONTEXT_FACTORS = {
    'is_public': 20,
    'has_internet_exposure': 15,
    'is_production': 10,
    'has_sensitive_data': 15,
    'data_restricted': 20,
    'data_confidential': 10,
    'multiple_related_resources': 5,
}

# Factores de correlación y sus bonuses
CORRELATION_FACTORS = {
    'credential_exposure': 20,  # Credenciales + exposición
    'public_compute': 15,  # EC2 pública + puerto abierto
    'data_exfiltration_risk': 20,  # S3 público + datos sensibles
    'privilege_escalation': 20,  # IAM débil + recurso crítico
    'lateral_movement': 15,  # Múltiples recursos comprometidos
}


def calculate_risk_score(
        finding: Dict,
        context: Optional[Dict] = None,
        correlation_flags: Optional[List[str]] = None
) -> RiskScore:
    """
    Calcula score de riesgo avanzado (0-100) para un hallazgo.

    Args:
        finding: Diccionario del hallazgo
        context: Contexto enriquecido (opcional)
        correlation_flags: Flags de correlación aplicables (opcional)

    Returns:
        RiskScore: Objeto con score desglosado
    """
    # 1. Score base por severidad
    severity = finding.get('severity', 'MEDIUM').upper()
    base_score = SEVERITY_BASE_SCORES.get(severity, 30)

    # 2. Bonus por contexto
    context_bonus = 0
    if context:
        if context.get('is_public'):
            context_bonus += CONTEXT_FACTORS['is_public']
        if context.get('has_internet_exposure'):
            context_bonus += CONTEXT_FACTORS['has_internet_exposure']
        if context.get('is_production'):
            context_bonus += CONTEXT_FACTORS['is_production']
        if context.get('has_sensitive_data'):
            context_bonus += CONTEXT_FACTORS['has_sensitive_data']

        data_class = context.get('data_classification', '')
        if data_class == 'restricted':
            context_bonus += CONTEXT_FACTORS['data_restricted']
        elif data_class == 'confidential':
            context_bonus += CONTEXT_FACTORS['data_confidential']

        related = context.get('related_resources', [])
        if len(related) > 3:
            context_bonus += CONTEXT_FACTORS['multiple_related_resources']

    # 3. Bonus por correlación
    correlation_bonus = 0
    if correlation_flags:
        for flag in correlation_flags:
            if flag in CORRELATION_FACTORS:
                correlation_bonus += CORRELATION_FACTORS[flag]

    # 4. Calcular score final (cap en 100)
    final_score = min(100, base_score + context_bonus + correlation_bonus)

    # 5. Clasificar nivel de riesgo
    if final_score >= 81:
        risk_level = RiskLevel.CRITICAL
    elif final_score >= 61:
        risk_level = RiskLevel.HIGH
    elif final_score >= 31:
        risk_level = RiskLevel.MEDIUM
    else:
        risk_level = RiskLevel.LOW

    return RiskScore(
        base_score=base_score,
        context_bonus=context_bonus,
        correlation_bonus=correlation_bonus,
        final_score=final_score,
        risk_level=risk_level
    )


def classify_risk_level(score: int) -> RiskLevel:
    """Clasifica un score numérico en nivel de riesgo."""
    if score >= 81:
        return RiskLevel.CRITICAL
    elif score >= 61:
        return RiskLevel.HIGH
    elif score >= 31:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def get_risk_thresholds() -> Dict[str, Dict]:
    """Retorna umbrales de riesgo para configuración."""
    return {
        'LOW': {'min': 0, 'max': 30, 'action': 'log'},
        'MEDIUM': {'min': 31, 'max': 60, 'action': 'alert'},
        'HIGH': {'min': 61, 'max': 80, 'action': 'escalate'},
        'CRITICAL': {'min': 81, 'max': 100, 'action': 'immediate'},
    }


def prioritize_findings(findings: List[Dict]) -> List[Dict]:
    """
    Ordena hallazgos por score de riesgo (más críticos primero).

    Args:
        findings: Lista de hallazgos con 'risk_score' calculado

    Returns:
        Lista ordenada por riesgo descendente
    """
    return sorted(
        findings,
        key=lambda f: f.get('risk_score', {}).get('final_score', 0),
        reverse=True
    )


def get_top_risks(findings: List[Dict], limit: int = 5) -> List[Dict]:
    """
    Retorna los N hallazgos de mayor riesgo.

    Args:
        findings: Lista de hallazgos
        limit: Número máximo a retornar

    Returns:
        Top N hallazgos por riesgo
    """
    prioritized = prioritize_findings(findings)
    return prioritized[:limit]