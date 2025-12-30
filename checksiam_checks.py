import boto3
from datetime import datetime, timezone
import json

SENSITIVE_ACTIONS = [
    "iam:*", "s3:*", "kms:*", "secretsmanager:*", "rds:*", "ec2:*", "lambda:*",
    "cloudtrail:*", "organizations:*", "sts:AssumeRole", "iam:PassRole",
    "iam:CreateAccessKey", "iam:DeleteUser", "iam:AttachUserPolicy",
    "iam:PutUserPolicy", "iam:UpdateAssumeRolePolicy", "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail", "iam:AddUserToGroup", "iam:CreatePolicy",
    "iam:CreateRole", "iam:AttachRolePolicy"
]

def check_iam_issues():
    iam = boto3.client('iam')
    sts = boto3.client('sts')
    report = {
        "root_without_mfa": False,
        "root_has_access_keys": False,
        "users_without_mfa": [],
        "old_access_keys": [],
        "unused_access_keys": [],
        "unused_console_passwords": [],
        "high_risk_policies": [],
        "wildcard_resource_policies": [],
        "empty_groups": [],
        "unused_customer_managed_policies": [],
        "users_with_admin_policies": [],
        "publicly_assumable_roles": [],
        "roles_with_excessive_trust": [],
        "users_can_disable_cloudtrail": [],
        "password_policy_weak": {},
        "users_with_privilege_escalation": [],  # ← NUEVO
        "access_analyzer_findings": []          # ← Para Access Analyzer
    }

    account_id = sts.get_caller_identity()['Account']

    # --- Root checks ---
    try:
        summary = iam.get_account_summary()
        report["root_without_mfa"] = (summary['SummaryMap'].get('AccountMFAEnabled', 0) == 0)
    except Exception as e:
        print(f"[!] Error al verificar root MFA: {e}")

    # --- Password policy ---
    try:
        policy = iam.get_account_password_policy()['PasswordPolicy']
        report["password_policy_weak"] = {
            "min_length_ok": policy.get('MinimumPasswordLength', 0) >= 14,
            "require_symbols": policy.get('RequireSymbols', False),
            "require_numbers": policy.get('RequireNumbers', False),
            "require_uppercase": policy.get('RequireUppercaseCharacters', False),
            "require_lowercase": policy.get('RequireLowercaseCharacters', False),
            "max_age_ok": policy.get('MaxPasswordAge', 0) <= 90,
            "reuse_prevention_ok": policy.get('PasswordReusePrevention', 0) >= 24
        }
    except iam.exceptions.NoSuchEntityException:
        report["password_policy_weak"] = "❌ No existe política de contraseña"
    except Exception as e:
        print(f"[!] Error política de contraseña: {e}")

    # --- Usuarios ---
    try:
        users = iam.list_users()['Users']
    except Exception as e:
        print(f"[!] Error al listar usuarios: {e}")
        return report

    for user in users:
        username = user['UserName']
        # MFA
        mfa_devices = iam.list_mfa_devices(UserName=username).get('MFADevices', [])
        if not mfa_devices:
            report["users_without_mfa"].append(username)

        # Access keys
        try:
            access_keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
            for key in access_keys:
                if key['Status'] == 'Active':
                    created = normalize_date(key['CreateDate'])
                    age = (datetime.now(timezone.utc) - created).days
                    if age > 90:
                        report["old_access_keys"].append({"user": username, "key_id": key['AccessKeyId'], "age_days": age})
                else:
                    report["unused_access_keys"].append({"user": username, "key_id": key['AccessKeyId']})
        except Exception as e:
            print(f"[!] Error keys de {username}: {e}")

        # Contraseña sin usar
        if 'PasswordLastUsed' not in user:
            create_date = normalize_date(user['CreateDate'])
            age = (datetime.now(timezone.utc) - create_date).days
            if age > 90:
                report["unused_console_passwords"].append({"user": username, "reason": "Nunca usó contraseña"})
        else:
            last_used = normalize_date(user['PasswordLastUsed'])
            age = (datetime.now(timezone.utc) - last_used).days
            if age > 90:
                report["unused_console_passwords"].append({"user": username, "last_used_days_ago": age})

        # Analizar políticas
        risky_inline, wildcard_inline = analyze_user_policies(iam, username, is_inline=True)
        risky_attached, wildcard_attached = analyze_user_policies(iam, username, is_inline=False)
        all_risky = risky_inline + risky_attached
        all_wildcard = wildcard_inline + wildcard_attached

        report["high_risk_policies"].extend(all_risky)
        report["wildcard_resource_policies"].extend(all_wildcard)

        # Verificar escalada
        if can_escalate_privileges(all_risky):
            report["users_with_privilege_escalation"].append(username)

        # CloudTrail
        if can_disable_cloudtrail(all_risky):
            report["users_can_disable_cloudtrail"].append(username)

    # --- Roles ---
    try:
        roles = iam.list_roles()['Roles']
        for role in roles:
            policy = role['AssumeRolePolicyDocument']
            if is_publicly_assumable(policy):
                report["publicly_assumable_roles"].append(role['RoleName'])
            if has_excessive_trust(policy):
                report["roles_with_excessive_trust"].append(role['RoleName'])
    except Exception as e:
        print(f"[!] Error roles: {e}")

    # --- Grupos y políticas no usadas ---
    try:
        groups = iam.list_groups()['Groups']
        for group in groups:
            if not iam.get_group(GroupName=group['GroupName'])['Users']:
                report["empty_groups"].append(group['GroupName'])
        policies = iam.list_policies(Scope='Local')['Policies']
        for p in policies:
            if p['AttachmentCount'] == 0:
                report["unused_customer_managed_policies"].append(p['PolicyName'])
    except Exception as e:
        print(f"[!] Error grupos/políticas: {e}")

    # --- Usuarios con AdministratorAccess ---
    for user in users:
        try:
            attached = iam.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
            if any("AdministratorAccess" in p['PolicyName'] for p in attached):
                report["users_with_admin_policies"].append(user['UserName'])
        except:
            pass

    # --- IAM Access Analyzer (se ejecuta al final) ---
    report["access_analyzer_findings"] = check_access_analyzer_findings()

    return report

# === FUNCIONES AUXILIARES ===

def normalize_date(date_val):
    if isinstance(date_val, str):
        date_val = date_val.replace('Z', '+00:00')
        if '.' in date_val:
            date_val = date_val.split('.')[0] + '+00:00'
        return datetime.fromisoformat(date_val)
    return date_val

def analyze_user_policies(iam, username, is_inline=True):
    risky = []
    wildcard = []
    try:
        if is_inline:
            policies = iam.list_user_policies(UserName=username)['PolicyNames']
            for name in policies:
                doc = iam.get_user_policy(UserName=username, PolicyName=name)['PolicyDocument']
                r, w = analyze_policy_document(doc, username, f"inline:{name}")
                risky.extend(r)
                wildcard.extend(w)
        else:
            attached = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
            for ap in attached:
                policy_arn = ap['PolicyArn']
                version = iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version)['PolicyVersion']['Document']
                r, w = analyze_policy_document(doc, username, f"attached:{ap['PolicyName']}")
                risky.extend(r)
                wildcard.extend(w)
    except Exception as e:
        print(f"[!] Error analizando políticas de {username}: {e}")
    return risky, wildcard

def analyze_policy_document(doc, user, source):
    risky = []
    wildcard = []
    if isinstance(doc, str):
        doc = json.loads(doc)
    statements = doc.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get('Effect') != 'Allow':
            continue
        actions = stmt.get('Action', [])
        resources = stmt.get('Resource', '*')
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        for action in actions:
            if any(sens in action for sens in SENSITIVE_ACTIONS):
                risky.append({"user": user, "action": action, "source": source})
        if "*" in resources:
            for action in actions:
                if any(sens in action for sens in SENSITIVE_ACTIONS):
                    wildcard.append({"user": user, "action": action, "source": source})
    return risky, wildcard

def can_disable_cloudtrail(policies):
    for p in policies:
        if "cloudtrail:StopLogging" in p["action"] or "cloudtrail:DeleteTrail" in p["action"]:
            return True
    return False

def is_publicly_assumable(policy_doc):
    for stmt in policy_doc.get('Statement', []):
        principal = stmt.get('Principal', {})
        if principal == "*" or principal == {"AWS": "*"}:
            return True
        if isinstance(principal, dict) and "AWS" in principal:
            aws_principals = principal["AWS"]
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            current_account = boto3.client('sts').get_caller_identity()['Account']
            for arn in aws_principals:
                if arn == "*":
                    return True
                if not arn.startswith(f"arn:aws:iam::{current_account}:") and not arn.startswith("arn:aws:iam::aws:"):
                    return True
    return False

def has_excessive_trust(policy_doc):
    allowed_services = {
        "lambda.amazonaws.com", "ec2.amazonaws.com", "s3.amazonaws.com",
        "events.amazonaws.com", "sns.amazonaws.com", "sqs.amazonaws.com",
        "apigateway.amazonaws.com", "ec2.application-autoscaling.amazonaws.com"
    }
    for stmt in policy_doc.get('Statement', []):
        principal = stmt.get('Principal', {})
        if isinstance(principal, dict) and "Service" in principal:
            services = principal["Service"]
            if isinstance(services, str):
                services = [services]
            for svc in services:
                if svc not in allowed_services and not svc.endswith(".amazonaws.com"):
                    return True
        elif principal == "*":
            return True
    return False

# === 🔥 NUEVO: Detección de escalada de privilegios ===
def can_escalate_privileges(risky_policies):
    actions = set()
    for p in risky_policies:
        action = p["action"]
        if isinstance(action, list):
            actions.update(a.lower() for a in action)
        else:
            actions.add(action.lower())

    # Combinaciones peligrosas
    if "iam:putuserpolicy" in actions:
        return True
    if "iam:attachuserpolicy" in actions:
        return True
    if "iam:createpolicy" in actions and "iam:attachuserpolicy" in actions:
        return True
    if "iam:addusertogroup" in actions:
        # Podría agregarse a un grupo admin
        return True
    if "iam:createrole" in actions and "sts:assumerole" in actions:
        return True
    if "iam:attachrolepolicy" in actions:
        return True
    return False

# === 🌐 NUEVO: IAM Access Analyzer ===
def check_access_analyzer_findings():
    try:
        # ✅ Nombre CORRECTO del servicio: 'accessanalyzer' (sin guion)
        client = boto3.client('accessanalyzer')
        analyzers = client.list_analyzers().get('analyzers', [])
        findings = []
        for analyzer in analyzers:
            paginator = client.get_paginator('list_findings')
            for page in paginator.paginate(analyzerArn=analyzer['arn']):
                for f in page.get('findings', []):
                    if f.get('status') == 'ACTIVE':
                        principal = f.get('principal', {})
                        current_account = boto3.client('sts').get_caller_identity()['Account']
                        # Verificar si es acceso externo
                        is_external = False
                        if principal == "*":
                            is_external = True
                        elif isinstance(principal, dict):
                            aws_principal = principal.get("AWS")
                            if aws_principal:
                                if isinstance(aws_principal, str):
                                    aws_principal = [aws_principal]
                                for arn in aws_principal:
                                    if not arn.startswith(f"arn:aws:iam::{current_account}:") and arn != "*":
                                        is_external = True
                                        break
                        if is_external:
                            findings.append({
                                "resource": f.get('resource', 'Unknown'),
                                "action": ", ".join(f.get('action', []))[:50],
                                "principal": str(principal)[:60]
                            })
        return findings
    except boto3.exceptions.botocore.exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDeniedException':
            print("[!] Acceso denegado a IAM Access Analyzer (requiere permisos)")
        else:
            print(f"[!] Error en Access Analyzer: {e}")
        return []
    except Exception as e:
        # Si no hay analyzers o el servicio no está disponible
        if "no analyzers" in str(e).lower() or "ResourceNotFoundException" in str(e):
            return []
        print(f"[!] Error inesperado en Access Analyzer: {e}")
        return []