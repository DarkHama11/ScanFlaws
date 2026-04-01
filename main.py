"""
ScanFlaws - AWS Security Audit Tool
Orquestador principal
"""
import sys
import os

# Agregar la raíz del proyecto al PATH
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# ============================================
# IMPORTS - FASE 1: IDENTITY SECURITY
# ============================================

# Checks Base de IAM (11 checks)
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

# Módulos Avanzados de Fase 1
from phases.phase1_identity.access_analyzer import check_access_analyzer_findings_multi_region
from phases.phase1_identity.key_rotation import check_all_key_rotation
from phases.phase1_identity.policy_simulator import check_all_policy_simulations

# ============================================
# IMPORTS - FASE 2: STORAGE SECURITY
# ============================================

from phases.phase2_storage.s3_auditor import check_all_s3
from phases.phase2_storage.ebs_auditor import check_all_ebs

# ============================================
# CORE
# ============================================

from core.reporter import print_table, export_to_json, export_to_csv


# ============================================
# FUNCIONES PRINCIPALES
# ============================================

def run_phase1_identity():
    """
    Ejecuta todos los checks de la Fase 1: Identity Security.

    Returns:
        list: Lista de hallazgos de Fase 1
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


def run_phase2_storage():
    """
    Ejecuta todos los checks de la Fase 2: Storage Security (S3/EBS).

    Returns:
        list: Lista de hallazgos de Fase 2
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


def run_all_phases(phases_to_run=None):
    """
    Ejecuta los checks de las fases seleccionadas.

    Args:
        phases_to_run: Lista de fases a ejecutar (default: todas)
                       Opciones: ['phase1'], ['phase2'], ['phase1', 'phase2']

    Returns:
        list: Lista combinada de todos los hallazgos
    """
    if phases_to_run is None:
        phases_to_run = ['phase1', 'phase2']

    all_findings = []

    if 'phase1' in phases_to_run:
        findings = run_phase1_identity()
        all_findings.extend(findings)

    if 'phase2' in phases_to_run:
        findings = run_phase2_storage()
        all_findings.extend(findings)

    return all_findings


def main():
    """Función principal de ScanFlaws"""
    print("\n" + "=" * 60)
    print("🚀 ScanFlaws - AWS Security Audit Tool")
    print("=" * 60)
    print("\n📌 Ejecutando todas las fases disponibles...\n")

    # Ejecutar todas las fases
    findings = run_all_phases()

    # Mostrar resultados
    print("\n" + "=" * 60)
    print("📊 RESULTADOS GLOBALES")
    print("=" * 60 + "\n")

    if findings:
        # Agrupar por severidad
        critical = [f for f in findings if f.get('severity') == 'CRITICAL']
        high = [f for f in findings if f.get('severity') == 'HIGH']
        medium = [f for f in findings if f.get('severity') == 'MEDIUM']
        low = [f for f in findings if f.get('severity') == 'LOW']

        print(f"🔴 CRITICAL: {len(critical)}")
        print(f"🟠 HIGH: {len(high)}")
        print(f"🟡 MEDIUM: {len(medium)}")
        print(f"🟢 LOW: {len(low)}")
        print(f"📊 TOTAL: {len(findings)}\n")

        # Agrupar por categoría
        s3_findings = [f for f in findings if f.get('storage_type') == 'S3']
        ebs_findings = [f for f in findings if f.get('storage_type') == 'EBS']
        iam_findings = [f for f in findings if not f.get('storage_type')]

        print("📈 Hallazgos por categoría:")
        if iam_findings:
            print(f"  🛡️  Identity (IAM): {len(iam_findings)} hallazgos")
        if s3_findings:
            print(f"  🗄️  Storage (S3): {len(s3_findings)} hallazgos")
        if ebs_findings:
            print(f"  💾 Storage (EBS): {len(ebs_findings)} hallazgos")
        print()

        # Tabla completa de hallazgos
        print("=" * 60)
        print("📋 DETALLE DE HALLAZGOS")
        print("=" * 60 + "\n")

        table_data = [
            [f['check'], f['entity'], f['issue'], f['severity']]
            for f in findings
        ]
        print_table(table_data, headers=["Check", "Entidad", "Detalle", "Severidad"])

        # Exportar reportes
        print("\n" + "=" * 60)
        print("💾 EXPORTANDO REPORTES")
        print("=" * 60 + "\n")

        export_to_json(findings)
        export_to_csv(findings)

    else:
        print("[+] ✅ ¡Excelente! No se encontraron hallazgos de seguridad.")

    print("\n" + "=" * 60)
    print("✅ ScanFlaws - Auditoría Completada")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()