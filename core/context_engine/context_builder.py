"""
Context Builder - Enriquecimiento de contexto seguro
ScanFlaws v5.0 - Fixed & Hardened
"""
from typing import Union, Dict, List, Optional
from models.finding import Finding

# Patrones para detectar exposición pública
PUBLIC_INDICATORS = [
    '0.0.0.0/0', '::/0', 'public', 'internet', 'external',
    'sg-', 'security.group', 'loadbalancer', 'cloudfront'
]

# Patrones para detectar datos sensibles
SENSITIVE_INDICATORS = [
    'password', 'secret', 'token', 'key', 'credential',
    'database', 'sensitive', 'confidential', 'pii', 'pci'
]

# Patrones para detectar producción
PROD_INDICATORS = [
    'prod', 'production', 'live', 'main', 'primary',
    '-prod-', '.prod.', 'master'
]


def enrich_context(finding: Union[Finding, Dict]) -> Finding:
    """
    Enriquece un hallazgo con contexto de riesgo.

    Args:
        finding: Objeto Finding o dict

    Returns:
        Finding: Hallazgo con contexto enriquecido
    """
    # Normalizar a Finding
    if isinstance(finding, dict):
        finding = Finding.from_dict(finding)

    if not isinstance(finding, Finding):
        return finding

    # Inicializar contexto si es None
    if finding.context is None:
        finding.context = {}

    # Convertir a texto para análisis
    entity_str = str(finding.entity).lower()
    issue_str = str(finding.issue).lower()
    details_str = str(finding.details).lower()
    check_str = str(finding.check).lower()

    full_text = f"{entity_str} {issue_str} {details_str} {check_str}"

    # 1. Detectar exposición pública
    is_public = any(ind in full_text for ind in PUBLIC_INDICATORS)
    finding.add_context("is_public", is_public)

    # 2. Detectar exposición a internet
    has_internet = '0.0.0.0/0' in full_text or 'internet' in full_text or 'public' in full_text
    finding.add_context("has_internet_exposure", has_internet)

    # 3. Detectar entorno de producción
    is_production = any(ind in entity_str for ind in PROD_INDICATORS)
    finding.add_context("is_production", is_production)

    # 4. Detectar datos sensibles
    has_sensitive = any(ind in full_text for ind in SENSITIVE_INDICATORS)
    finding.add_context("has_sensitive_data", has_sensitive)

    # 5. Extraer tipo de recurso
    resource_type = _extract_resource_type(entity_str, check_str)
    finding.add_context("resource_type", resource_type)

    return finding


def _extract_resource_type(entity: str, check: str) -> str:
    """Extrae el tipo de recurso del hallazgo."""
    if 'iam' in check or 'user' in entity or 'role' in entity:
        return 'IAM'
    elif 's3' in check or 'bucket' in entity:
        return 'S3'
    elif 'ec2' in check or 'instance' in entity or 'sg-' in entity:
        return 'EC2'
    elif 'lambda' in check or 'function' in entity:
        return 'Lambda'
    elif 'ecr' in check or 'repository' in entity:
        return 'ECR'
    elif 'ebs' in check or 'volume' in entity or 'snapshot' in entity:
        return 'EBS'
    elif 'key' in entity or 'access' in check:
        return 'Credential'
    return 'Unknown'


def enrich_batch(findings: List[Union[Finding, Dict]]) -> List[Finding]:
    """
    Enriquece múltiples hallazgos en lote.

    Args:
        findings: Lista de hallazgos

    Returns:
        List[Finding]: Lista enriquecida
    """
    from models.finding import normalize_findings_list

    normalized = normalize_findings_list(findings)
    enriched = []

    for finding in normalized:
        try:
            enriched.append(enrich_context(finding))
        except Exception as e:
            # Logear error pero continuar
            print(f"[!] Error enriqueciendo contexto: {e}")
            enriched.append(finding)

    return enriched