"""
Risk Pipeline - Orquestador del flujo de análisis de riesgo
ScanFlaws v5.0 - Fixed & Hardened
"""
from typing import List, Dict, Optional, Any
from datetime import datetime
from models.finding import Finding, normalize_findings_list
from core.risk_engine.risk_calculator import set_finding_score, prioritize_findings, get_top_risks, get_score_color_code
from core.context_engine.context_builder import enrich_batch
from core.correlation_engine.correlator import correlate_findings, create_correlation_summary


class RiskAnalysisPipeline:
    """
    Pipeline completo de análisis de riesgo:
    Hallazgos → Normalizar → Contexto → Correlación → Scoring → Output
    """

    def __init__(self):
        self.errors = []

    def analyze(
            self,
            findings: List[Any],
            enable_correlation: bool = True,
            top_n: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Ejecuta el pipeline completo de análisis de riesgo.

        Args:
            findings: Hallazgos brutos (dict o Finding)
            enable_correlation: Si ejecutar correlación
            top_n: Limitar output a top N riesgos

        Returns:
            Dict: Resultados estructurados
        """
        start_time = datetime.now()

        try:
            # PASO 1: Normalizar todos los hallazgos a objetos Finding
            normalized = normalize_findings_list(findings)

            if not normalized:
                return self._create_empty_result()

            # PASO 2: Enriquecer con contexto
            enriched = enrich_batch(normalized)

            # PASO 3: Correlación (opcional)
            if enable_correlation:
                correlated = correlate_findings(enriched)
            else:
                correlated = enriched

            # PASO 4: Calcular scores (CRÍTICO: usar set_finding_score, NO sobrescribir)
            for finding in correlated:
                try:
                    score = set_finding_score(finding)
                except Exception as e:
                    self.errors.append(f"Error calculando score: {e}")
                    finding.set_score(10)  # Fallback score

            # PASO 5: Priorizar por score
            prioritized = prioritize_findings(correlated)

            # PASO 6: Limitar si se especificó top_n
            if top_n:
                output_findings = prioritized[:top_n]
            else:
                output_findings = prioritized

            # PASO 7: Generar resumen ejecutivo
            summary = self._generate_summary(output_findings, len(findings))

            elapsed = (datetime.now() - start_time).total_seconds()

            return {
                'success': True,
                'analysis_timestamp': datetime.now().isoformat(),
                'processing_time_seconds': round(elapsed, 2),
                'input_count': len(findings),
                'output_count': len(output_findings),
                'correlation_enabled': enable_correlation,
                'summary': summary,
                'findings': output_findings,
                'top_risks': get_top_risks(output_findings, limit=5),
                'errors': self.errors,
            }

        except Exception as e:
            # Fallback graceful
            return self._create_error_result(str(e), findings)

    def _generate_summary(self, findings: List[Finding], original_count: int) -> Dict:
        """Genera resumen ejecutivo."""
        if not findings:
            return {
                'status': 'SECURE',
                'message': 'No se encontraron riesgos significativos',
                'total_analyzed': original_count,
                'risk_distribution': {},
                'top_risks': [],
            }

        # Conteos por nivel de riesgo
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in findings:
            level = getattr(f, 'risk_level', 'LOW')
            if level in risk_counts:
                risk_counts[level] += 1

        # Determinar estado
        if risk_counts['CRITICAL'] > 0:
            status = 'CRITICAL_RISK'
            message = f"Se detectaron {risk_counts['CRITICAL']} riesgo(s) crítico(s)"
        elif risk_counts['HIGH'] >= 3:
            status = 'HIGH_RISK'
            message = f"Múltiples riesgos altos ({risk_counts['HIGH']})"
        elif risk_counts['HIGH'] > 0:
            status = 'MEDIUM_RISK'
            message = "Riesgos moderados detectados"
        else:
            status = 'LOW_RISK'
            message = "Riesgos menores detectados"

        # Top 3 por score
        top_3 = [
            {
                'entity': f.entity,
                'check': f.check,
                'score': f.score,
                'level': f.risk_level,
                'color': get_score_color_code(f.score)
            }
            for f in findings[:3]
        ]

        return {
            'status': status,
            'message': message,
            'total_analyzed': original_count,
            'total_reported': len(findings),
            'risk_distribution': risk_counts,
            'top_risks': top_3,
            'recommendation': self._get_recommendation(status),
        }

    def _get_recommendation(self, status: str) -> str:
        """Retorna recomendación basada en estado."""
        recommendations = {
            'CRITICAL_RISK': '🔴 ACCIÓN INMEDIATA: Remediar riesgos críticos',
            'HIGH_RISK': '🟠 PRIORIDAD ALTA: Planificar remediación en 24-48h',
            'MEDIUM_RISK': '🟡 REVISIÓN PROGRAMADA: Incluir en próximo sprint',
            'LOW_RISK': '🟢 MONITOREO CONTINUO: Mantener escaneos periódicos',
            'SECURE': '✅ SIN ACCIÓN REQUERIDA',
        }
        return recommendations.get(status, '⚪ Sin recomendaciones')

    def _create_empty_result(self) -> Dict:
        """Crea resultado vacío."""
        return {
            'success': True,
            'analysis_timestamp': datetime.now().isoformat(),
            'processing_time_seconds': 0,
            'input_count': 0,
            'output_count': 0,
            'correlation_enabled': True,
            'summary': {
                'status': 'SECURE',
                'message': 'No hay hallazgos para analizar',
                'risk_distribution': {},
                'top_risks': [],
            },
            'findings': [],
            'top_risks': [],
            'errors': [],
        }

    def _create_error_result(self, error: str, findings: List) -> Dict:
        """Crea resultado de error con fallback."""
        return {
            'success': False,
            'error': error,
            'analysis_timestamp': datetime.now().isoformat(),
            'input_count': len(findings),
            'output_count': 0,
            'summary': {
                'status': 'ANALYSIS_ERROR',
                'message': f'Error en análisis: {error}',
                'risk_distribution': {},
                'top_risks': [],
            },
            'findings': [],
            'top_risks': [],
            'errors': [error],
        }