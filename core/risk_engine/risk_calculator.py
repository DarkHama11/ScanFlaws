"""
Risk Calculator - Scoring seguro de riesgos (0-100)
ScanFlaws v5.0 - Fixed & Hardened
"""
from typing import Union, Dict, Optional
from models.finding import Finding

# Mapeo de severidad a score base
SEVERITY_BASE_SCORES = {
    "INFO": 5,
    "LOW": 10,
    "MEDIUM": 30,
    "HIGH": 60,
    "CRITICAL": 80
}

# Factores de contexto y sus bonuses
CONTEXT_BONUSES = {
    "is_public": 20,
    "has_internet_exposure": 15,
    "is_production": 10,
    "has_sensitive_data": 15,
}


def calculate_risk_score(finding: Union[Finding, Dict]) -> int:
    """
    Calcula score de riesgo (0-100) de forma segura.

    Args:
        finding: Objeto Finding o dict con datos del hallazgo

    Returns:
        int: Score entre 0 y 100
    """
    # Normalizar a Finding si es dict
    if isinstance(finding, dict):
        finding = Finding.from_dict(finding)

    # Validar que es un Finding
    if not isinstance(finding, Finding):
        return 0

    # 1. Score base por severidad
    severity = str(finding.severity).upper()
    base_score = SEVERITY_BASE_SCORES.get(severity, 30)

    # 2. Bonus por contexto (con validación de tipo)
    context_bonus = 0
    context = finding.context

    # Validar que context es un dict antes de usar .get()
    if isinstance(context, dict):
        if context.get("is_public", False):
            context_bonus += CONTEXT_BONUSES["is_public"]

        if context.get("has_internet_exposure", False):
            context_bonus += CONTEXT_BONUSES["has_internet_exposure"]

        if context.get("is_production", False):
            context_bonus += CONTEXT_BONUSES["is_production"]

        if context.get("has_sensitive_data", False):
            context_bonus += CONTEXT_BONUSES["has_sensitive_data"]

    # 3. Bonus por correlación
    correlation_bonus = 0
    if hasattr(finding, 'correlated_findings') and finding.correlated_findings:
        correlation_bonus = min(20, len(finding.correlated_findings) * 5)

    # 4. Calcular score final (cap en 100)
    final_score = min(100, base_score + context_bonus + correlation_bonus)

    return final_score


def set_finding_score(finding: Union[Finding, Dict], score: Optional[int] = None) -> int:
    """
    Calcula y setea el score en un finding de forma segura.

    Args:
        finding: Objeto Finding o dict
        score: Score opcional (si None, se calcula)

    Returns:
        int: Score final seteado
    """
    # Normalizar a Finding
    if isinstance(finding, dict):
        finding = Finding.from_dict(finding)

    if not isinstance(finding, Finding):
        return 0

    # Calcular score si no se proporcionó
    if score is None:
        score = calculate_risk_score(finding)

    # Setear score de forma segura
    finding.set_score(score)

    return finding.score


def get_risk_level_from_score(score: int) -> str:
    """
    Clasifica un score numérico en nivel de riesgo.

    Args:
        score: Score entre 0 y 100

    Returns:
        str: Nivel de riesgo (CRITICAL, HIGH, MEDIUM, LOW)
    """
    if score >= 81:
        return "CRITICAL"
    elif score >= 61:
        return "HIGH"
    elif score >= 31:
        return "MEDIUM"
    return "LOW"


def get_score_color_code(score: int) -> str:
    """
    Retorna código de color/emoji para un score.

    Args:
        score: Score entre 0 y 100

    Returns:
        str: Emoji/color code
    """
    if score >= 81:
        return "🔴"
    elif score >= 61:
        return "🟠"
    elif score >= 31:
        return "🟡"
    return "🟢"


def prioritize_findings(findings: list) -> list:
    """
    Ordena hallazgos por score (más críticos primero).

    Args:
        findings: Lista de Finding objects

    Returns:
        list: Lista ordenada por score descendente
    """
    return sorted(findings, key=lambda f: getattr(f, 'score', 0), reverse=True)


def get_top_risks(findings: list, limit: int = 5) -> list:
    """
    Retorna los N hallazgos de mayor riesgo.

    Args:
        findings: Lista de Finding objects
        limit: Número máximo a retornar

    Returns:
        list: Top N hallazgos por score
    """
    prioritized = prioritize_findings(findings)
    return prioritized[:limit]