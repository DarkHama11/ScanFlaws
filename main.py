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

# Imports Fase 1 - Identity (11 checks base)
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

# Imports Fase 1 - Módulos Avanzados 🆕
from phases.phase1_identity.access_analyzer import check_access_analyzer_findings_multi_region
from phases.phase1_identity.key_rotation import check_all_key_rotation
from phases.phase1_identity.policy_simulator import check_all_policy_simulations

from core.reporter import print_table, export_to_json, export_to_csv


def run_phase1_identity():
    """Ejecuta todos los checks de la Fase 1: Identity"""
    all_findings = []

    print("\n" + "=" * 60)
    print("🛡️  ScanFlaws - Fase 1: Identity Security")
    print("=" * 60 + "\n")

    # --- Checks Base (11) ---
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

    # --- Checks Avanzados 🆕 ---
    print("\n📋 Ejecutando checks avanzados...\n")

    # Access Analyzer
    try:
        findings = check_access_analyzer_findings_multi_region()
        all_findings.extend(findings)
    except Exception as e:
        print(f"[!] Error en Access Analyzer: {e}")

    # Key Rotation
    try:
        findings = check_all_key_rotation()
        all_findings.extend(findings)
    except Exception as e:
        print(f"[!] Error en Key Rotation: {e}")

    # Policy Simulator (puede tardar)
    try:
        findings = check_all_policy_simulations()
        all_findings.extend(findings)
    except Exception as e:
        print(f"[!] Error en Policy Simulator: {e}")

    return all_findings


def main():
    """Función principal"""
    print("\n🚀 Iniciando ScanFlaws...\n")

    # Ejecutar Fase 1
    findings = run_phase1_identity()

    # Mostrar resultados
    print("\n" + "=" * 60)
    print("📊 RESULTADOS")
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

        # Tabla completa
        table_data = [
            [f['check'], f['entity'], f['issue'], f['severity']]
            for f in findings
        ]
        print_table(table_data, headers=["Check", "Entidad", "Detalle", "Severidad"])

        # Exportar reportes
        export_to_json(findings)
        export_to_csv(findings)
    else:
        print("[+] ✅ ¡Excelente! No se encontraron hallazgos en Fase 1.")

    print("\n" + "=" * 60)
    print("✅ ScanFlaws - Fase 1 Completada")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()