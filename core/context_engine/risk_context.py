"""
Context Engine - Enriquecimiento de hallazgos con contexto de riesgo
ScanFlaws v5.0 - Intelligent Risk Analysis
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from enum import Enum, auto
import re


class ExposureLevel(Enum):
    """Niveles de exposición a internet."""
    NONE = auto()  # Sin exposición
    INTERNAL = auto()  # Solo red interna
    LIMITED = auto()  # Acceso limitado (VPN, IP whitelist)
    PUBLIC = auto()  # Acceso público total


class EnvironmentType(Enum):
    """Tipo de entorno del recurso."""
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TESTING = "testing"
    UNKNOWN = "unknown"


@dataclass
class RiskContext:
    """
    Contexto de riesgo para un hallazgo.
    Determina si un hallazgo es realmente explotable.
    """
    # Exposición
    is_public: bool = False
    has_internet_exposure: bool = False
    exposure_level: ExposureLevel = ExposureLevel.NONE

    # Entorno
    environment: EnvironmentType = EnvironmentType.UNKNOWN
    is_production: bool = False

    # Datos sensibles
    has_sensitive_data: bool = False
    data_classification: Optional[str] = None  # "public", "internal", "confidential", "restricted"

    # Recursos relacionados
    related_resources: Set[str] = field(default_factory=set)
    dependencies: List[str] = field(default_factory=list)

    # Metadatos AWS
    region: Optional[str] = None
    account_id: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None

    # Tags (para detectar producción, sensibilidad, etc.)
    tags: Dict[str, str] = field(default_factory=dict)

    # Score de contexto (calculado)
    context_risk_multiplier: float = 1.0

    def calculate_multiplier(self) -> float:
        """
        Calcula el multiplicador de riesgo basado en el contexto.
        Retorna: 1.0 (base) a 3.0 (máximo riesgo contextual)
        """
        multiplier = 1.0

        # Exposición a internet (factor más importante)
        if self.exposure_level == ExposureLevel.PUBLIC:
            multiplier += 1.0  # +100% riesgo
        elif self.exposure_level == ExposureLevel.LIMITED:
            multiplier += 0.5  # +50% riesgo
        elif self.has_internet_exposure:
            multiplier += 0.75  # +75% riesgo

        # Entorno de producción
        if self.is_production or self.environment == EnvironmentType.PRODUCTION:
            multiplier += 0.5  # +50% riesgo

        # Datos sensibles
        if self.has_sensitive_data:
            multiplier += 0.5  # +50% riesgo

        # Clasificación de datos restrictiva
        if self.data_classification in ['confidential', 'restricted']:
            multiplier += 0.75  # +75% riesgo

        # Múltiples recursos relacionados (superficie de ataque ampliada)
        if len(self.related_resources) > 3:
            multiplier += 0.25 * min(len(self.related_resources) - 3, 2)  # Máximo +50%

        return min(multiplier, 3.0)  # Máximo 3x riesgo base

    def update(self):
        """Actualiza campos derivados después de cambios."""
        self.is_production = (
                self.environment == EnvironmentType.PRODUCTION or
                self.tags.get('Environment', '').lower() == 'production' or
                self.tags.get('env', '').lower() == 'prod'
        )
        self.context_risk_multiplier = self.calculate_multiplier()
        return self

    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario para serialización."""
        return {
            'is_public': self.is_public,
            'has_internet_exposure': self.has_internet_exposure,
            'exposure_level': self.exposure_level.name,
            'environment': self.environment.value,
            'is_production': self.is_production,
            'has_sensitive_data': self.has_sensitive_data,
            'data_classification': self.data_classification,
            'related_resources': list(self.related_resources),
            'region': self.region,
            'resource_type': self.resource_type,
            'context_risk_multiplier': round(self.context_risk_multiplier, 2),
        }


class ContextEnricher:
    """
    Enriquece hallazgos con contexto de riesgo basado en análisis de recursos AWS.
    """

    # Patrones para detectar producción en nombres/tags
    PROD_PATTERNS = [
        r'\bprod\b', r'\bproduction\b', r'-prod-', r'\.prod\.',
        r'\bmain\b', r'\blive\b', r'\bprimary\b'
    ]

    # Patrones para detectar datos sensibles
    SENSITIVE_PATTERNS = [
        r'\b(password|passwd|secret|token|key|credential|api[_-]?key)\b',
        r'\b(ssn|social[_-]?security|credit[_-]?card|pci|pii|phi)\b',
        r'\b(database|db|credentials|auth)\b'
    ]

    # Recursos que por defecto tienen exposición pública
    PUBLIC_BY_DEFAULT = {
        'AWS::S3::Bucket', 'AWS::CloudFront::Distribution',
        'AWS::ElasticLoadBalancing::LoadBalancer',
        'AWS::ElasticLoadBalancingV2::LoadBalancer',
        'AWS::ApiGateway::RestApi'
    }

    def __init__(self, aws_session=None):
        """
        Args:
            aws_session: Sesión boto3 para consultar metadata de recursos (opcional)
        """
        self.aws_session = aws_session

    def enrich_finding(self, finding: Dict, resource_metadata: Optional[Dict] = None) -> Dict:
        """
        Enriquece un hallazgo con contexto de riesgo.

        Args:
            finding: Diccionario del hallazgo original
            resource_metadata: Metadata opcional del recurso (de AWS API)

        Returns:
            Dict: Hallazgo enriquecido con contexto y score
        """
        # Crear contexto base
        context = RiskContext()

        # Extraer información del finding
        entity = finding.get('entity', '')
        issue = finding.get('issue', '').lower()
        check_name = finding.get('check', '').lower()

        # 1. Detectar exposición pública
        context.has_internet_exposure = self._detect_internet_exposure(entity, issue, check_name)
        context.is_public = '0.0.0.0/0' in entity or 'public' in entity.lower()

        if context.is_public or context.has_internet_exposure:
            context.exposure_level = ExposureLevel.PUBLIC
        elif any(cidr in entity for cidr in ['10.', '192.168.', '172.16.']):
            context.exposure_level = ExposureLevel.INTERNAL

        # 2. Detectar entorno de producción
        context.environment = self._detect_environment(entity, resource_metadata)
        context.is_production = (context.environment == EnvironmentType.PRODUCTION)

        # 3. Detectar datos sensibles
        context.has_sensitive_data = self._detect_sensitive_data(entity, issue, check_name)
        context.data_classification = self._classify_data(entity, issue, check_name)

        # 4. Extraer metadata AWS si está disponible
        if resource_metadata:
            context.region = resource_metadata.get('region')
            context.account_id = resource_metadata.get('account_id')
            context.resource_type = resource_metadata.get('resource_type')
            context.resource_id = resource_metadata.get('resource_id')
            context.tags = resource_metadata.get('tags', {})

        # 5. Calcular multiplicador de riesgo
        context.update()

        # 6. Agregar contexto al finding
        enriched = finding.copy()
        enriched['context'] = context.to_dict()
        enriched['context_risk_multiplier'] = context.context_risk_multiplier

        return enriched

    def _detect_internet_exposure(self, entity: str, issue: str, check_name: str) -> bool:
        """Detecta si el recurso tiene exposición a internet."""
        indicators = [
            '0.0.0.0/0', '::/0', 'public', 'internet', 'external',
            'sg-', 'loadbalancer', 'cloudfront', 'api.gateway'
        ]
        text = f"{entity} {issue} {check_name}".lower()
        return any(ind in text for ind in indicators)

    def _detect_environment(self, entity: str, metadata: Optional[Dict]) -> EnvironmentType:
        """Detecta el tipo de entorno del recurso."""
        text = entity.lower()

        # Verificar metadata primero
        if metadata:
            env_tag = metadata.get('tags', {}).get('Environment', '').lower()
            if env_tag in ['production', 'prod']:
                return EnvironmentType.PRODUCTION
            elif env_tag in ['staging', 'stage']:
                return EnvironmentType.STAGING
            elif env_tag in ['development', 'dev']:
                return EnvironmentType.DEVELOPMENT
            elif env_tag in ['testing', 'test']:
                return EnvironmentType.TESTING

        # Verificar patrones en nombre
        for pattern in self.PROD_PATTERNS:
            if re.search(pattern, text):
                return EnvironmentType.PRODUCTION

        if re.search(r'\b(stag|stage)\b', text):
            return EnvironmentType.STAGING
        if re.search(r'\b(dev|development)\b', text):
            return EnvironmentType.DEVELOPMENT
        if re.search(r'\b(test|testing)\b', text):
            return EnvironmentType.TESTING

        return EnvironmentType.UNKNOWN

    def _detect_sensitive_data(self, entity: str, issue: str, check_name: str) -> bool:
        """Detecta si el recurso maneja datos sensibles."""
        text = f"{entity} {issue} {check_name}".lower()
        return any(re.search(pattern, text) for pattern in self.SENSITIVE_PATTERNS)

    def _classify_data(self, entity: str, issue: str, check_name: str) -> Optional[str]:
        """Clasifica el nivel de sensibilidad de los datos."""
        text = f"{entity} {issue} {check_name}".lower()

        # Restricted: datos regulados (PCI, PHI, PII)
        if any(kw in text for kw in ['pci', 'phi', 'pii', 'ssn', 'credit.card', 'social.security']):
            return 'restricted'

        # Confidential: secretos, credenciales
        if any(kw in text for kw in ['password', 'secret', 'token', 'credential', 'api.key']):
            return 'confidential'

        # Internal: datos de negocio
        if any(kw in text for kw in ['database', 'internal', 'proprietary']):
            return 'internal'

        return 'public'

    def enrich_batch(self, findings: List[Dict], metadata_map: Optional[Dict[str, Dict]] = None) -> List[Dict]:
        """
        Enriquece múltiples hallazgos en lote.

        Args:
            findings: Lista de hallazgos
            metadata_map: Dict {entity: metadata} para lookup eficiente

        Returns:
            Lista de hallazgos enriquecidos
        """
        enriched = []
        for finding in findings:
            entity = finding.get('entity', '')
            metadata = metadata_map.get(entity) if metadata_map else None
            enriched.append(self.enrich_finding(finding, metadata))
        return enriched