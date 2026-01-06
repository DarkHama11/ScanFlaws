from checksiam_checks import (
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
from access_analyzer import check_access_analyzer_findings_multi_region
from tabulate import tabulate

def run_iam_checks():
    all_findings = []

    print("[*] Ejecutando checks de IAM...")

    findings = check_users_without_mfa()
    for f in findings:
        all_findings.append(["Usuarios sin MFA", f["user"], f["issue"]])

    findings = check_old_access_keys()
    for f in findings:
        all_findings.append(["Access Key antigua", f["user"], f["issue"]])

    findings = check_wildcard_policies()
    for f in findings:
        all_findings.append(["Política insegura", f["resource"], f["issue"]])

    findings = check_users_with_direct_admin_policies()
    for f in findings:
        all_findings.append(["Asignación admin directa", f["user"], f["issue"]])

    findings = check_root_without_mfa()
    for f in findings:
        all_findings.append(["Root sin MFA", "root", f["issue"]])

    findings = check_roles_with_dangerous_trust_policy()
    for f in findings:
        all_findings.append(["Trust policy peligrosa", f["role"], f["issue"]])

    findings = check_inactive_users()
    for f in findings:
        all_findings.append(["Usuario inactivo", f["user"], f["issue"]])

    findings = check_unrestricted_passrole()
    for f in findings:
        all_findings.append(["PassRole sin restricciones", f["resource"], f["issue"]])

    findings = check_unrestricted_assume_role()
    for f in findings:
        all_findings.append(["AssumeRole sin restricciones", f["resource"], f["issue"]])

    findings = check_inline_policies()
    for f in findings:
        all_findings.append([f["type"] + " con política en línea", f["entity"], f["issue"]])

    findings = check_cloudtrail_disable_permissions()
    for f in findings:
        all_findings.append(["Peligro en CloudTrail", f["resource"], f["issue"]])

    return all_findings

def main():
    iam_findings = run_iam_checks()
    analyzer_findings = check_access_analyzer_findings_multi_region()

    if iam_findings:
        print("\n🛡️  Hallazgos en IAM:")
        print(tabulate(iam_findings, headers=["Check", "Entidad", "Detalle"], tablefmt="grid"))
    else:
        print("[+] No se encontraron hallazgos en IAM.")

    if analyzer_findings:
        aa_table = [[f["region"], f["resource"], f["principal"]] for f in analyzer_findings]
        print("\n🔍 Hallazgos de Access Analyzer (acceso externo):")
        print(tabulate(aa_table, headers=["Región", "Recurso", "Principal"], tablefmt="grid"))
    else:
        print("[+] No se encontraron hallazgos de acceso externo.")

if __name__ == "__main__":
    main()