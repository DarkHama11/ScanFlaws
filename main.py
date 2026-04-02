"""
ScanFlaws - AWS Security Audit Tool v5.0
Intelligent Risk Analysis Engine - Fixed & Hardened
Orquestador principal con modelo Finding unificado
"""
import sys
import os
from datetime import datetime
from typing import List, Dict, Optional, Any

# Agregar la raíz del proyecto al PATH
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# ============================================
# IMPORTS - MODELS (v5.0 Central)
# ============================================
from models.finding import Finding, normalize_findings_list

# ============================================
# IMPORTS - FASE 1: IDENTITY SECURITY
# ============================================
from phases.phase1_identity.iam_checks import (
    check_users_without_mfa,
    check_old_access_keys,
    check_wildcard_policies,
    check_users_with_direct_admin_policies,
    check_root_without_mfa,
    check_roles_with_dangerous_trust_policy,
    check_inactive_users,
    check_unrestricted_passrole,
    check_unrestricted_assume_role,
    check_inline_policies,
    check_cloudtrail_disable_permissions
)
from phases.phase1_identity.access_analyzer import check_access_analyzer_findings_multi_region
from phases.phase1_identity.key_rotation import check_all_key_rotation
from phases.phase1_identity.policy_simulator import check_all_policy_simulations

# ============================================
# IMPORTS - FASE 2: STORAGE SECURITY
# ============================================
from phases.phase2_storage.s3_auditor import check_all_s3
from phases.phase2_storage.ebs_auditor import check_all_ebs

# ============================================
# IMPORTS - FASE 3: COMPUTE SECURITY
# ============================================
from phases.phase3_compute.ec2_auditor import check_all_ec2
from phases.phase3_compute.lambda_auditor import check_all_lambda
from phases.phase3_compute.ecr_auditor import check_all_ecr

# ============================================
# IMPORTS - RISK ANALYSIS ENGINE (v5.0)
# ============================================
from core.risk_pipeline import RiskAnalysisPipeline
from core.risk_engine.risk_calculator import get_score_color_code, prioritize_findings

# ============================================
# IMPORTS - CORE UTILITIES
# ============================================
from core.reporter import print_table, export_to_json, export_to_csv, format_finding
from core.aws_session import get_session


# ============================================
# FUNCIONES - FASE 1: IDENTITY
# ============================================

def run_phase1_identity() -> List[Dict]:
    """
    Ejecuta todos los checks de la Fase 1: Identity Security.

    Returns:
        list: Lista de hallazgos de Fase 1 (como dicts)
    """
    all_findings = []

    print("\n" + "=" * 60)
    print("🛡️  FASE 1: Identity Security")
    print("=" * 60 + "\n")

    # --- Checks Base (11 checks) ---
    print("📋 Ejecutando checks base de IAM...\n")

    base_checks = [
        check_users_without_mfa,
        check_old_access_keys,
        check_wildcard_policies,
        check_users_with_direct_admin_policies,
        check_root_without_mfa,
        check_roles_with_dangerous_trust_policy,
        check_inactive_users,
        check_unrestricted_passrole,
        check_unrestricted_assume_role,
        check_inline_policies,
        check_cloudtrail_disable_permissions,
    ]

    for check_func in base_checks:
        try:
            findings = check_func()
            all_findings.extend(findings)
        except Exception as e:
            print(f"[!] Error ejecutando {check_func.__name__}: {e}")

    # --- Checks Avanzados ---
    print("\n📋 Ejecutando checks avanzados...\n")

    try:
        findings = check_access_analyzer_findings_multi_region()
        all_findings.extend(findings)
    except Exception as e:
        print(f"[!] Error en Access Analyzer: {e}")

    try:
        findings = check_all_key_rotation()
        all_findings.extend(findings)
    except Exception as e:
        print(f"[!] Error en Key Rotation: {e}")

    try:
        findings = check_all_policy_simulations()
        all_findings.extend(findings)
    except Exception as e:
        print(f"[!] Error en Policy Simulator: {e}")

    return all_findings


# ============================================
# FUNCIONES - FASE 2: STORAGE
# ============================================

def run_phase2_storage() -> List[Dict]:
    """
    Ejecuta todos los checks de la Fase 2: Storage Security (S3/EBS).

    Returns:
        list: Lista de hallazgos de Fase 2 (como dicts)
    """
    all_findings = []

    print("\n" + "=" * 60)
    print("🗄️  FASE 2: Storage Security (S3/EBS)")
    print("=" * 60 + "\n")

    # --- S3 Checks ---
    try:
        print("📋 Ejecutando checks de S3...\n")
        findings = check_all_s3()
        all_findings.extend(findings)
    except Exception as e:
        print(f"[!] Error en S3 Auditor: {e}")

    # --- EBS Checks ---
    try:
        print("\n📋 Ejecutando checks de EBS...\n")
        findings = check_all_ebs()
        all_findings.extend(findings)
    except Exception as e:
        print(f"[!] Error en EBS Auditor: {e}")

    return all_findings


# ============================================
# FUNCIONES - FASE 3: COMPUTE
# ============================================

def run_phase3_compute() -> List[Dict]:
    """
    Ejecuta todos los checks de la Fase 3: Compute Security (EC2/Lambda/ECR).

    Returns:
        list: Lista de hallazgos de Fase 3 (como dicts)
    """
    all_findings = []

    print("\n" + "=" * 60)
    print("🖥️  FASE 3: Compute Security (EC2/Lambda/ECR)")
    print("=" * 60 + "\n")

    # --- EC2 Checks ---
    try:
        print("📋 Ejecutando checks de EC2...\n")
        findings = check_all_ec2()
        all_findings.extend(findings)
    except Exception as e:
        print(f"[!] Error en EC2 Auditor: {e}")

    # --- Lambda Checks ---
    try:
        print("\n📋 Ejecutando checks de Lambda...\n")
        findings = check_all_lambda()
        all_findings.extend(findings)
    except Exception as e:
        print(f"[!] Error en Lambda Auditor: {e}")

    # --- ECR Checks ---
    try:
        print("\n📋 Ejecutando checks de ECR...\n")
        findings = check_all_ecr()
        all_findings.extend(findings)
    except Exception as e:
        print(f"[!] Error en ECR Auditor: {e}")

    return all_findings


# ============================================
# ORQUESTADOR DE FASES TRADICIONAL
# ============================================

def run_all_phases(phases_to_run: Optional[List[str]] = None) -> List[Dict]:
    """
    Ejecuta los checks de las fases seleccionadas (modo tradicional).

    Args:
        phases_to_run: Lista de fases a ejecutar (default: todas)

    Returns:
        list: Lista combinada de hallazgos brutos (como dicts)
    """
    if phases_to_run is None:
        phases_to_run = ['phase1', 'phase2', 'phase3']

    all_findings = []

    if 'phase1' in phases_to_run:
        findings = run_phase1_identity()
        all_findings.extend(findings)

    if 'phase2' in phases_to_run:
        findings = run_phase2_storage()
        all_findings.extend(findings)

    if 'phase3' in phases_to_run:
        findings = run_phase3_compute()
        all_findings.extend(findings)

    return all_findings


# ============================================
# PIPELINE DE ANÁLISIS DE RIESGO INTELIGENTE
# ============================================

def run_intelligent_risk_analysis(
        raw_findings: List[Dict],
        enable_correlation: bool = True,
        top_n: Optional[int] = None
) -> Dict:
    """
    Ejecuta el pipeline de análisis de riesgo inteligente v5.0.

    Args:
        raw_findings: Hallazgos brutos de las fases de escaneo (dicts)
        enable_correlation: Si ejecutar motor de correlación
        top_n: Limitar output a top N riesgos (None = todos)

    Returns:
        Dict: Resultados estructurados del análisis de riesgo
    """
    print("\n" + "=" * 60)
    print("🧠 Ejecutando Risk Analysis Pipeline v5.0")
    print("=" * 60 + "\n")

    try:
        # Inicializar pipeline
        pipeline = RiskAnalysisPipeline()

        # Ejecutar análisis completo
        result = pipeline.analyze(
            findings=raw_findings,
            enable_correlation=enable_correlation,
            top_n=top_n
        )

        print(f"✅ Análisis completado en {result.get('processing_time_seconds', 0)}s")
        print(f"✅ Hallazgos procesados: {result.get('input_count', 0)} → {result.get('output_count', 0)}")

        return result

    except Exception as e:
        print(f"[!] Error en Risk Analysis Pipeline: {e}")
        # Fallback: retornar hallazgos originales sin enriquecimiento
        return {
            'success': False,
            'error': str(e),
            'findings': raw_findings,
            'summary': {
                'status': 'ANALYSIS_ERROR',
                'message': f'Error en análisis: {e}',
                'risk_distribution': {},
                'top_risks': [],
                'recommendation': '⚠️ Revisar logs de error'
            }
        }


# ============================================
# PRESENTACIÓN DE RESULTADOS ENRIQUECIDOS
# ============================================

def display_risk_analysis_results(analysis_result: Dict):
    """
    Muestra los resultados del análisis de riesgo de forma legible.

    Args:
        analysis_result: Dict retornado por RiskAnalysisPipeline.analyze()
    """
    summary = analysis_result.get('summary', {})
    findings = analysis_result.get('findings', [])

    print("\n" + "=" * 60)
    print("📊 RESULTADOS - ANÁLISIS DE RIESGO INTELIGENTE")
    print("=" * 60 + "\n")

    # Estado general con emoji
    status_emoji = {
        'CRITICAL_RISK': '🔴',
        'HIGH_RISK': '🟠',
        'MEDIUM_RISK': '🟡',
        'LOW_RISK': '🟢',
        'SECURE': '✅',
        'ANALYSIS_ERROR': '⚠️'
    }
    status = summary.get('status', 'UNKNOWN')
    emoji = status_emoji.get(status, '⚪')

    print(f"{emoji} ESTADO: {status}")
    print(f"💬 {summary.get('message', 'Sin información adicional')}")
    print()

    # Distribución de riesgos con barra visual
    risk_dist = summary.get('risk_distribution', {})
    if risk_dist:
        print("📈 Distribución por nivel de riesgo:")
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = risk_dist.get(level, 0)
            if count > 0:
                bar = '█' * min(count, 20)
                print(f"  {level:10s} {count:3d} {bar}")
        print()

    # Top riesgos priorizados - ACCESO SEGURO
    top_risks = analysis_result.get('top_risks', [])
    if top_risks:
        print("🎯 TOP Riesgos Prioritarios:")
        for i, risk in enumerate(top_risks, 1):
            # Acceso seguro al score (puede ser Finding object o dict)
            score, color, check, entity = _safe_extract_risk_info(risk)

            print(f"  {i}. {color} Score: {score:3d} | {check[:50]}{'...' if len(check) > 50 else ''}")
            print(f"     └─ Entidad: {entity}")

            # Mostrar info de correlación si aplica
            if isinstance(risk, Finding) and risk.correlated_findings:
                print(f"     └─ 🔗 Correlaciones: {len(risk.correlated_findings)} hallazgos relacionados")
            elif isinstance(risk, dict) and risk.get('correlated'):
                print(f"     └─ 🔗 Correlación detectada")
        print()

    # Tabla de hallazgos detallados (limitada para no saturar)
    if findings:
        print("=" * 60)
        print("📋 Hallazgos Detallados (Top 15 por riesgo)")
        print("=" * 60 + "\n")

        display_findings = findings[:15]
        table_data = []

        for f in display_findings:
            score, color, check, entity, risk_level, correlated = _safe_extract_finding_info(f)

            corr_indicator = "🔗 " if correlated else ""

            table_data.append([
                f"{color} {score:3d}",
                f"{corr_indicator}{check[:35]}{'...' if len(check) > 35 else ''}",
                entity[:20] + '...' if len(entity) > 20 else entity,
                risk_level
            ])

        print_table(table_data, headers=["Score", "Check", "Entidad", "Riesgo"])
        print()


def _safe_extract_risk_info(risk: Any) -> tuple:
    """
    Extrae información de riesgo de forma segura (Finding o dict).

    Returns:
        tuple: (score, color, check, entity)
    """
    if isinstance(risk, Finding):
        score = risk.score
        color = get_score_color_code(score)
        check = risk.check
        entity = risk.entity
    elif isinstance(risk, dict):
        score_info = risk.get('score', 0)
        if isinstance(score_info, dict):
            score = score_info.get('final_score', 0)
            color = score_info.get('color_code', '⚪')
        else:
            score = score_info if isinstance(score_info, int) else 0
            color = get_score_color_code(score)
        check = risk.get('check', 'N/A')
        entity = risk.get('entity', 'N/A')
    else:
        score = 0
        color = '⚪'
        check = str(risk)
        entity = 'N/A'

    return score, color, check, entity


def _safe_extract_finding_info(f: Any) -> tuple:
    """
    Extrae información de hallazgo de forma segura (Finding o dict).

    Returns:
        tuple: (score, color, check, entity, risk_level, correlated)
    """
    if isinstance(f, Finding):
        score = f.score
        color = get_score_color_code(score)
        check = f.check
        entity = f.entity
        risk_level = f.risk_level
        correlated = len(f.correlated_findings) > 0
    elif isinstance(f, dict):
        score_info = f.get('score', 0)
        if isinstance(score_info, dict):
            score = score_info.get('final_score', 0)
            color = score_info.get('color_code', '⚪')
        else:
            score = score_info if isinstance(score_info, int) else 0
            color = get_score_color_code(score)
        check = f.get('check', 'N/A')
        entity = f.get('entity', 'N/A')
        risk_level = f.get('risk_level', f.get('severity', 'N/A'))
        correlated = f.get('correlated', False)
    else:
        score = 0
        color = '⚪'
        check = str(f)
        entity = 'N/A'
        risk_level = 'N/A'
        correlated = False

    return score, color, check, entity, risk_level, correlated


def export_enriched_reports(analysis_result: Dict, base_filename: Optional[str] = None):
    """
    Exporta los hallazgos enriquecidos a JSON y CSV.

    Args:
        analysis_result: Resultados del análisis de riesgo
        base_filename: Nombre base para los archivos (opcional)
    """
    print("\n" + "=" * 60)
    print("💾 Exportando reportes con análisis de riesgo")
    print("=" * 60 + "\n")

    findings = analysis_result.get('findings', [])

    if base_filename is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_filename = f"scanflaws_risk_{timestamp}"

    # Convertir Finding objects a dicts para exportación
    export_data = []
    for f in findings:
        if isinstance(f, Finding):
            export_data.append(f.to_dict())
        elif isinstance(f, dict):
            export_data.append(f)
        else:
            export_data.append({'data': str(f)})

    # Exportar JSON
    json_path = export_to_json(export_data, filename=base_filename)

    # Exportar CSV
    csv_path = export_to_csv(export_data, filename=base_filename)

    # Mostrar paths de exportación
    if json_path:
        print(f"📄 JSON: {os.path.basename(json_path)}")
    if csv_path:
        print(f"📄 CSV:  {os.path.basename(csv_path)}")


# ============================================
# FUNCIÓN PRINCIPAL
# ============================================

def main():
    """Función principal de ScanFlaws v5.0"""
    print("\n" + "=" * 60)
    print("🧠 ScanFlaws v5.0 - Intelligent Risk Analysis")
    print("=" * 60)
    print("\n📌 Ejecutando análisis de riesgo inteligente...\n")

    start_time = datetime.now()

    # ========================================
    # PASO 1: Ejecutar fases de escaneo tradicionales
    # ========================================
    print("🔍 Ejecutando fases de escaneo tradicionales...\n")

    raw_findings = run_all_phases()

    if not raw_findings:
        print("\n[+] ✅ ¡Excelente! No se encontraron hallazgos en las fases de escaneo.")
        print("\n" + "=" * 60)
        print("✅ ScanFlaws v5.0 - Auditoría Completada")
        print("=" * 60 + "\n")
        return

    print(f"\n✅ Fases completadas: {len(raw_findings)} hallazgos brutos detectados")

    # ========================================
    # PASO 2: Ejecutar análisis de riesgo inteligente
    # ========================================
    analysis_result = run_intelligent_risk_analysis(
        raw_findings=raw_findings,
        enable_correlation=True,  # Activar correlación de hallazgos
        top_n=None  # None = retornar todos, o poner número para limitar
    )

    # ========================================
    # PASO 3: Mostrar resultados enriquecidos
    # ========================================
    display_risk_analysis_results(analysis_result)

    # ========================================
    # PASO 4: Exportar reportes
    # ========================================
    export_enriched_reports(analysis_result)

    # ========================================
    # PASO 5: Recomendación final
    # ========================================
    summary = analysis_result.get('summary', {})
    recommendation = summary.get('recommendation', '⚪ Sin recomendaciones específicas')

    print("\n" + "=" * 60)
    print(f"💡 RECOMENDACIÓN: {recommendation}")
    print("=" * 60 + "\n")

    # Tiempo total de ejecución
    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"⏱️  Tiempo total de ejecución: {elapsed:.2f} segundos")

    print("\n" + "=" * 60)
    print("✅ ScanFlaws v5.0 - Análisis de Riesgo Completado")
    print("=" * 60 + "\n")


# ============================================
# ENTRY POINT
# ============================================

if __name__ == "__main__":
    main()