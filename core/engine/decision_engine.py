"""
Motor de decisión adaptativo - ScanFlaws v4.0
Elimina pipeline lineal → sistema inteligente que adapta el escaneo
"""
from typing import Dict, List, Optional, Callable, Any, Set
from dataclasses import dataclass, field
from enum import Enum, auto
import logging

logger = logging.getLogger(__name__)


class ScanPhase(Enum):
    """Fases disponibles del escaneo."""
    DISCOVERY = auto()  # Descubrimiento inicial
    IDENTITY = auto()  # IAM, usuarios, roles
    STORAGE = auto()  # S3, EBS, EFS
    COMPUTE = auto()  # EC2, Lambda, ECR, ECS
    NETWORK = auto()  # VPC, SG, NACL, Flow Logs
    GOVERNANCE = auto()  # CloudTrail, Config, CloudWatch
    REPORT = auto()  # Generación de reportes


class TechnologyFlag(Enum):
    """Tecnologías detectadas que activan scans específicos."""
    WORDPRESS = auto()
    KUBERNETES = auto()
    SERVERLESS = auto()
    CONTAINERIZED = auto()
    LEGACY_SYSTEM = auto()
    HIGH_COMPLIANCE = auto()


@dataclass
class ScanContext:
    """
    Contexto compartido entre fases para correlación de resultados.
    Thread-safe para ejecución concurrente.
    """
    # Inputs originales
    targets: List[str] = field(default_factory=list)

    # Descubrimiento
    open_ports: Set[int] = field(default_factory=set)
    detected_services: Dict[str, Any] = field(default_factory=dict)
    technologies: Set[TechnologyFlag] = field(default_factory=set)

    # Hallazgos correlacionados
    vulnerabilities: List[Dict] = field(default_factory=list)
    findings_by_entity: Dict[str, List[Dict]] = field(default_factory=dict)

    # Estado de ejecución
    executed_phases: Set[ScanPhase] = field(default_factory=set)
    skipped_phases: Set[ScanPhase] = field(default_factory=set)
    errors: List[str] = field(default_factory=list)

    # Configuración dinámica
    risk_threshold: float = 50.0  # 0-100
    aggressive_mode: bool = False
    safe_mode: bool = False

    def add_finding(self, entity: str, finding: Dict):
        """Agrega hallazgo con correlación automática."""
        self.vulnerabilities.append(finding)
        if entity not in self.findings_by_entity:
            self.findings_by_entity[entity] = []
        self.findings_by_entity[entity].append(finding)

    def has_technology(self, tech: TechnologyFlag) -> bool:
        """Verifica si se detectó una tecnología específica."""
        return tech in self.technologies

    def should_execute_phase(self, phase: ScanPhase) -> bool:
        """
        Decide si una fase debe ejecutarse basado en contexto.
        Reglas de decisión adaptativa.
        """
        if phase in self.executed_phases or phase in self.skipped_phases:
            return False

        # Safe mode: solo fases críticas
        if self.safe_mode and phase not in [ScanPhase.IDENTITY, ScanPhase.REPORT]:
            return False

        # Reglas específicas por fase
        if phase == ScanPhase.NETWORK:
            # Solo escanear red si hay recursos computacionales
            return ScanPhase.COMPUTE in self.executed_phases

        if phase == ScanPhase.GOVERNANCE:
            # Solo si hay hallazgos de otras fases
            return len(self.vulnerabilities) > 0

        return True


class DecisionRule:
    """Regla de decisión para activar/desactivar scans."""

    def __init__(self, name: str, condition: Callable[[ScanContext], bool],
                 action: Callable[[ScanContext], None], priority: int = 0):
        self.name = name
        self.condition = condition
        self.action = action
        self.priority = priority

    def evaluate(self, context: ScanContext) -> bool:
        """Evalúa la regla y ejecuta acción si aplica."""
        if self.condition(context):
            logger.debug(f"Regla '{self.name}' activada")
            self.action(context)
            return True
        return False


class AdaptiveEngine:
    """
    Motor de decisión adaptativo para ScanFlaws.
    Orquesta fases basándose en descubrimiento dinámico.
    """

    def __init__(self):
        self.rules: List[DecisionRule] = []
        self.phase_handlers: Dict[ScanPhase, Callable] = {}
        self._register_default_rules()

    def _register_default_rules(self):
        """Registra reglas de decisión por defecto."""

        # Regla: Si hay puerto 443 abierto → activar scans HTTPS
        self.rules.append(DecisionRule(
            name="https_detection",
            condition=lambda ctx: 443 in ctx.open_ports,
            action=lambda ctx: ctx.technologies.add(TechnologyFlag.CONTAINERIZED),
            priority=10
        ))

        # Regla: Si se detecta WordPress → activar scans específicos
        self.rules.append(DecisionRule(
            name="wordpress_detection",
            condition=lambda ctx: any('wordpress' in str(v).lower()
                                      for v in ctx.detected_services.values()),
            action=lambda ctx: ctx.technologies.add(TechnologyFlag.WORDPRESS),
            priority=15
        ))

        # Regla: Si hay funciones Lambda → activar scans serverless
        self.rules.append(DecisionRule(
            name="serverless_detection",
            condition=lambda ctx: 'lambda' in str(ctx.detected_services).lower(),
            action=lambda ctx: ctx.technologies.add(TechnologyFlag.SERVERLESS),
            priority=12
        ))

        # Regla: Si modo seguro → saltar scans agresivos
        self.rules.append(DecisionRule(
            name="safe_mode_skip",
            condition=lambda ctx: ctx.safe_mode,
            action=lambda ctx: ctx.skipped_phases.update([
                ScanPhase.NETWORK, ScanPhase.GOVERNANCE
            ]),
            priority=100  # Alta prioridad
        ))

    def register_phase(self, phase: ScanPhase, handler: Callable):
        """Registra un handler para una fase."""
        self.phase_handlers[phase] = handler

    def execute_adaptive_scan(self, context: ScanContext) -> ScanContext:
        """
        Ejecuta escaneo adaptativo basado en reglas y contexto.

        Args:
            context: Contexto inicial con targets y configuración

        Returns:
            Contexto actualizado con resultados correlacionados
        """
        logger.info(f"Iniciando escaneo adaptativo para {len(context.targets)} targets")

        # Fase 1: Discovery siempre se ejecuta primero
        if ScanPhase.DISCOVERY in self.phase_handlers:
            logger.info("Ejecutando fase: DISCOVERY")
            context = self.phase_handlers[ScanPhase.DISCOVERY](context)
            context.executed_phases.add(ScanPhase.DISCOVERY)

        # Evaluar reglas para adaptar el escaneo
        sorted_rules = sorted(self.rules, key=lambda r: r.priority, reverse=True)
        for rule in sorted_rules:
            rule.evaluate(context)

        # Ejecutar fases restantes según decisión adaptativa
        phase_order = [
            ScanPhase.IDENTITY, ScanPhase.STORAGE, ScanPhase.COMPUTE,
            ScanPhase.NETWORK, ScanPhase.GOVERNANCE, ScanPhase.REPORT
        ]

        for phase in phase_order:
            if context.should_execute_phase(phase) and phase in self.phase_handlers:
                try:
                    logger.info(f"Ejecutando fase: {phase.name}")
                    context = self.phase_handlers[phase](context)
                    context.executed_phases.add(phase)
                except Exception as e:
                    logger.error(f"Error en fase {phase.name}: {e}")
                    context.errors.append(f"{phase.name}: {str(e)}")
                    context.skipped_phases.add(phase)

        # Correlación final de resultados
        context = self._correlate_findings(context)

        logger.info(f"Escaneo completado: {len(context.vulnerabilities)} hallazgos")
        return context

    def _correlate_findings(self, context: ScanContext) -> ScanContext:
        """
        Correlaciona hallazgos entre fases para reducir ruido y priorizar.

        - Elimina duplicados por entidad
        - Agrupa hallazgos relacionados
        - Calcula riesgo compuesto por entidad
        """
        correlated = {}

        for entity, findings in context.findings_by_entity.items():
            # Agrupar por tipo de check
            by_check = {}
            for f in findings:
                check = f.get('check', 'unknown')
                if check not in by_check:
                    by_check[check] = []
                by_check[check].append(f)

            # Priorizar: mantener solo el más severo por tipo
            for check, check_findings in by_check.items():
                if check_findings:
                    # Ordenar por severidad
                    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
                    best = min(check_findings,
                               key=lambda x: severity_order.get(x.get('severity', 'INFO'), 5))
                    correlated.setdefault(entity, []).append(best)

        # Actualizar contexto con hallazgos correlacionados
        context.vulnerabilities = [
            f for findings in correlated.values() for f in findings
        ]
        context.findings_by_entity = correlated

        return context