import boto3
from checksiam_checks import check_iam_issues


def main():
    print("[🛡️] AWS Security Scanner - Auditoría IAM Avanzada")
    print("=" * 55)

    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        print(f"[✅] Autenticado como: {identity['Arn']}\n")
    except Exception as e:
        print(f"[❌] Error de autenticación: {e}")
        return

    issues = check_iam_issues()
    has_issues = False

    # --- Root ---
    if issues["root_without_mfa"]:
        has_issues = True
        print("🔴 [CRÍTICO] Cuenta root SIN MFA")
    if issues["root_has_access_keys"]:
        has_issues = True
        print("🔴 [CRÍTICO] Cuenta root TIENE ACCESS KEYS")

    # --- Password policy ---
    if isinstance(issues["password_policy_weak"], str):
        has_issues = True
        print(f"⚠️  Política de contraseña: {issues['password_policy_weak']}")
    elif issues["password_policy_weak"]:
        weak = issues["password_policy_weak"]
        if not all(weak.values()):
            has_issues = True
            print("⚠️  Política de contraseña débil (CIS):")
            if not weak["min_length_ok"]: print("   - Longitud mínima < 14")
            if not weak["max_age_ok"]: print("   - Vigencia > 90 días")

    # --- Usuarios sin MFA ---
    if issues["users_without_mfa"]:
        has_issues = True
        print(f"\n👤 Usuarios sin MFA ({len(issues['users_without_mfa'])}):")
        for u in issues["users_without_mfa"]:
            print(f"   - {u}")

    # --- ESCALADA DE PRIVILEGIOS (¡NUEVO!) ---
    if issues["users_with_privilege_escalation"]:
        has_issues = True
        print(f"\n🧨 USUARIOS CON ESCALADA DE PRIVILEGIOS ({len(issues['users_with_privilege_escalation'])}):")
        for u in issues["users_with_privilege_escalation"]:
            print(f"   - {u} → puede volverse administrador")

    # --- Access Keys ---
    if issues["old_access_keys"]:
        has_issues = True
        print(f"\n⏳ Access keys activas >90 días ({len(issues['old_access_keys'])}):")
        for k in issues["old_access_keys"]:
            print(f"   - {k['user']} | {k['key_id']} | {k['age_days']} días")

    # --- Políticas peligrosas ---
    if issues["wildcard_resource_policies"]:
        has_issues = True
        print(f"\n💣 Resource:* + acciones sensibles ({len(issues['wildcard_resource_policies'])}):")
        for p in issues["wildcard_resource_policies"]:
            print(f"   - {p['user']} | {p['action']} | {p['source']}")

    # --- CloudTrail ---
    if issues["users_can_disable_cloudtrail"]:
        has_issues = True
        print(f"\n🔥 Puede deshabilitar CloudTrail:")
        for u in issues["users_can_disable_cloudtrail"]:
            print(f"   - {u}")

    # --- Roles ---
    if issues["publicly_assumable_roles"]:
        has_issues = True
        print(f"\n🌍 Roles asumibles desde Internet:")
        for r in issues["publicly_assumable_roles"]:
            print(f"   - {r}")

    # --- IAM ACCESS ANALYZER (¡NUEVO!) ---
    if issues["access_analyzer_findings"]:
        has_issues = True
        print(f"\n🔍 IAM ACCESS ANALYZER - Hallazgos externos ({len(issues['access_analyzer_findings'])}):")
        for f in issues["access_analyzer_findings"]:
            print(f"   - {f['resource']}")
            print(f"     Acción: {f['action']} | Principal: {f['principal']}")

    # --- Limpieza ---
    if issues["empty_groups"] or issues["unused_customer_managed_policies"]:
        has_issues = True
        if issues["empty_groups"]:
            print(f"\n🧹 Grupos vacíos: {len(issues['empty_groups'])}")
        if issues["unused_customer_managed_policies"]:
            print(f"🗑️  Políticas no usadas: {len(issues['unused_customer_managed_policies'])}")

    if not has_issues:
        print("\n[✅] ✨ ¡Excelente! Tu configuración IAM es segura.")

    print("\n[🔷] Auditoría IAM avanzada finalizada.")


if __name__ == "__main__":
    main()