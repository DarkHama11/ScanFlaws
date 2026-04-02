"""
Correlation Engine - Detección de riesgos compuestos
ScanFlaws v5.0 - Fixed & Hardened
"""
from typing import List, Dict, Optional, Union, Any
from models.finding import Finding, normalize_findings_list


def correlate_findings(findings: List[Union[Finding, Dict]]) -> List[Finding]:
    """
    Detecta correlaciones entre hallazgos.

    Args:
        findings: Lista de hallazgos

    Returns:
        List[Finding]: Lista con correlaciones establecidas
    """
    # Normalizar a lista de Finding objects
    normalized = normalize_findings_list(findings)

    if not normalized:
        return []

    # Agrupar por entidad para encontrar correlaciones
    by_entity = {}
    for f in normalized:
        entity = f.entity
        if entity not in by_entity:
            by_entity[entity] = []
        by_entity[entity].append(f)

    # Establecer correlaciones para entidades con múltiples hallazgos
    for entity, entity_findings in by_entity.items():
        if len(entity_findings) >= 2:
            for f in entity_findings:
                for other in entity_findings:
                    if f != other:
                        f.add_correlated_finding(other)

    # Detectar correlaciones específicas (reglas de negocio)
    normalized = _apply_correlation_rules(normalized)

    return normalized


def _apply_correlation_rules(findings: List[Finding]) -> List[Finding]:
    """
    Aplica reglas de correlación específicas.

    Reglas:
    1. Usuario sin MFA + Access Key = Credential Exposure
    2. SG abierto + EC2 pública = Public Compute
    """
    # Regla 1: Credential Exposure (MFA + Keys en mismo usuario)
    mfa_findings = [f for f in findings if 'mfa' in f.check.lower()]
    key_findings = [f for f in findings if 'key' in f.check.lower() or 'access' in f.check.lower()]

    for mfa_f in mfa_findings:
        for key_f in key_findings:
            if mfa_f.entity == key_f.entity:
                # Correlacionar bidireccionalmente
                mfa_f.add_correlated_finding(key_f)
                key_f.add_correlated_finding(mfa_f)

    # Regla 2: Security Group + EC2 (mismo recurso)
    sg_findings = [f for f in findings if 'sg' in f.entity.lower() or 'security group' in f.check.lower()]
    ec2_findings = [f for f in findings if 'ec2' in f.entity.lower() or 'instance' in f.entity.lower()]

    for sg_f in sg_findings:
        for ec2_f in ec2_findings:
            # Si comparten entidad o hay referencia cruzada
            if sg_f.entity == ec2_f.entity or sg_f.entity in ec2_f.details or ec2_f.entity in sg_f.details:
                sg_f.add_correlated_finding(ec2_f)
                ec2_f.add_correlated_finding(sg_f)

    return findings


def get_correlated_findings(findings: List[Finding]) -> List[Finding]:
    """
    Retorna solo hallazgos que tienen correlaciones.

    Args:
        findings: Lista de hallazgos

    Returns:
        List[Finding]: Hallazgos correlacionados
    """
    return [f for f in findings if f.correlated_findings]


def create_correlation_summary(findings: List[Finding]) -> Dict[str, Any]:
    """
    Crea resumen de correlaciones detectadas.

    Args:
        findings: Lista de hallazgos

    Returns:
        Dict: Resumen de correlaciones
    """
    correlated = get_correlated_findings(findings)

    return {
        'total_findings': len(findings),
        'correlated_count': len(correlated),
        'correlation_ratio': round(len(correlated) / len(findings) * 100, 2) if findings else 0,
        'top_correlated': [
            {
                'entity': f.entity,
                'check': f.check,
                'correlation_count': len(f.correlated_findings)
            }
            for f in sorted(correlated, key=lambda x: len(x.correlated_findings), reverse=True)[:5]
        ]
    }