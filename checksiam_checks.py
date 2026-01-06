import boto3
from datetime import datetime, timezone
from botocore.exceptions import ClientError
import json
import csv
from io import StringIO
import time


def get_iam_client():
    return boto3.client('iam')


# --------------------------------------------------------------
# 1. Usuarios sin MFA
# --------------------------------------------------------------
def check_users_without_mfa():
    client = get_iam_client()
    findings = []
    try:
        paginator = client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']
                try:
                    mfa_devices = client.list_mfa_devices(UserName=username)['MFADevices']
                    if not mfa_devices:
                        findings.append({
                            "user": username,
                            "issue": "MFA no habilitado"
                        })
                except ClientError:
                    continue
    except Exception as e:
        print(f"[!] Error escaneando usuarios sin MFA: {e}")
    return findings


# --------------------------------------------------------------
# 2. Access Keys antiguas (>90 días)
# --------------------------------------------------------------
def check_old_access_keys(max_age_days=90):
    client = get_iam_client()
    findings = []
    try:
        paginator = client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']
                try:
                    keys = client.list_access_keys(UserName=username)['AccessKeyMetadata']
                    for key in keys:
                        if key['Status'] != 'Active':
                            continue
                        create_date = key['CreateDate']
                        if create_date.tzinfo is None:
                            create_date = create_date.replace(tzinfo=timezone.utc)
                        age = (datetime.now(timezone.utc) - create_date).days
                        if age > max_age_days:
                            findings.append({
                                "user": username,
                                "key_id": key['AccessKeyId'],
                                "age_days": age,
                                "issue": f"Access Key con {age} días (>{max_age_days})"
                            })
                except ClientError:
                    continue
    except Exception as e:
        print(f"[!] Error escaneando access keys antiguas: {e}")
    return findings


# --------------------------------------------------------------
# 3. Políticas con Resource: "*"
# --------------------------------------------------------------
def _has_wildcard_resource(policy_doc):
    if isinstance(policy_doc, str):
        policy_doc = json.loads(policy_doc)
    for stmt in policy_doc.get('Statement', []):
        if stmt.get('Effect') == 'Allow':
            resource = stmt.get('Resource')
            if resource == '*':
                return True
            if isinstance(resource, list) and '*' in resource:
                return True
    return False


def check_wildcard_policies():
    client = get_iam_client()
    findings = []
    try:
        paginator = client.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):
            for policy in page['Policies']:
                try:
                    version = client.get_policy_version(
                        PolicyArn=policy['Arn'],
                        VersionId=policy['DefaultVersionId']
                    )
                    if _has_wildcard_resource(version['PolicyVersion']['Document']):
                        findings.append({
                            "resource": policy['PolicyName'],
                            "arn": policy['Arn'],
                            "issue": "Política con Resource: '*'"
                        })
                except ClientError:
                    continue
    except Exception as e:
        print(f"[!] Error escaneando políticas wildcard: {e}")
    return findings


# --------------------------------------------------------------
# 4. Usuarios con políticas administrativas directas
# --------------------------------------------------------------
def check_users_with_direct_admin_policies():
    client = get_iam_client()
    findings = []
    try:
        paginator = client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']
                try:
                    policies = client.list_attached_user_policies(UserName=username)['AttachedPolicies']
                    for p in policies:
                        if 'AdministratorAccess' in p['PolicyName']:
                            findings.append({
                                "user": username,
                                "policy": p['PolicyName'],
                                "issue": "Política administrativa asignada directamente"
                            })
                except ClientError:
                    continue
    except Exception as e:
        print(f"[!] Error escaneando políticas admin en usuarios: {e}")
    return findings


# --------------------------------------------------------------
# 5. Root sin MFA (usando credential report)
# --------------------------------------------------------------
def check_root_without_mfa():
    client = get_iam_client()
    try:
        client.generate_credential_report()
        for _ in range(10):
            try:
                report = client.get_credential_report()
                break
            except ClientError as e:
                if 'ReportNotPresent' in str(e):
                    time.sleep(1)
                    continue
                else:
                    raise
        else:
            return []

        rows = list(csv.DictReader(StringIO(report['Content'].decode())))
        for row in rows:
            if row['user'] == '<root_account>':
                if row['mfa_active'] == 'false':
                    return [{"issue": "Cuenta root sin MFA"}]
        return []
    except Exception as e:
        print(f"[!] No se pudo verificar MFA en root: {e}")
        return []


# --------------------------------------------------------------
# 6. Roles con trust policy peligrosa (pública o externa)
# --------------------------------------------------------------
def check_roles_with_dangerous_trust_policy():
    client = boto3.client('iam')
    findings = []
    try:
        sts = boto3.client('sts')
        current_account = sts.get_caller_identity()['Account']
    except Exception as e:
        print(f"[!] No se pudo obtener la cuenta actual: {e}")
        current_account = None

    try:
        paginator = client.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                role_name = role['RoleName']
                policy_doc = role['AssumeRolePolicyDocument']

                if isinstance(policy_doc, str):
                    policy_doc = json.loads(policy_doc)

                for stmt in policy_doc.get('Statement', []):
                    if stmt.get('Effect') != 'Allow':
                        continue

                    principal = stmt.get('Principal', {})

                    if principal == "*":
                        findings.append({
                            "role": role_name,
                            "principal": "*",
                            "issue": "Trust policy permite asumir desde cualquier cuenta (público)"
                        })
                        continue

                    if isinstance(principal, dict):
                        aws_principals = principal.get("AWS", [])
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]

                        for arn in aws_principals:
                            if arn == "*":
                                findings.append({
                                    "role": role_name,
                                    "principal": "*",
                                    "issue": "Trust policy permite asumir desde cualquier cuenta (ARN comodín)"
                                })
                            elif current_account and not arn.startswith(f"arn:aws:iam::{current_account}:"):
                                findings.append({
                                    "role": role_name,
                                    "principal": arn,
                                    "issue": "Trust policy permite asumir desde cuenta externa"
                                })
    except Exception as e:
        print(f"[!] Error escaneando trust policies de roles: {e}")
    return findings


# --------------------------------------------------------------
# 7. Usuarios inactivos (>90 días)
# --------------------------------------------------------------
def check_inactive_users(max_inactivity_days=90):
    client = boto3.client('iam')
    findings = []
    try:
        client.generate_credential_report()
        for _ in range(10):
            try:
                report = client.get_credential_report()
                break
            except ClientError as e:
                if 'ReportNotPresent' in str(e):
                    time.sleep(1)
                    continue
                else:
                    raise
        else:
            return []

        rows = list(csv.DictReader(StringIO(report['Content'].decode())))
        now = datetime.now(timezone.utc)

        for row in rows:
            if row['user'] == '<root_account>':
                continue

            username = row['user']
            active = False

            if row['password_enabled'] == 'true' and row['password_last_used'] != 'N/A':
                pwd_last = datetime.fromisoformat(row['password_last_used'].replace('Z', '+00:00'))
                if (now - pwd_last).days <= max_inactivity_days:
                    active = True

            if not active and row['access_key_1_active'] == 'true':
                if row['access_key_1_last_used_date'] != 'N/A':
                    ak1_last = datetime.fromisoformat(row['access_key_1_last_used_date'].replace('Z', '+00:00'))
                    if (now - ak1_last).days <= max_inactivity_days:
                        active = True
                else:
                    ak1_created = datetime.fromisoformat(row['access_key_1_last_rotated'].replace('Z', '+00:00'))
                    if (now - ak1_created).days <= max_inactivity_days:
                        active = True

            if not active and row['access_key_2_active'] == 'true':
                if row['access_key_2_last_used_date'] != 'N/A':
                    ak2_last = datetime.fromisoformat(row['access_key_2_last_used_date'].replace('Z', '+00:00'))
                    if (now - ak2_last).days <= max_inactivity_days:
                        active = True
                else:
                    ak2_created = datetime.fromisoformat(row['access_key_2_last_rotated'].replace('Z', '+00:00'))
                    if (now - ak2_created).days <= max_inactivity_days:
                        active = True

            if not active:
                findings.append({
                    "user": username,
                    "issue": f"Usuario inactivo por más de {max_inactivity_days} días"
                })

    except Exception as e:
        print(f"[!] Error escaneando usuarios inactivos: {e}")
    return findings


# --------------------------------------------------------------
# 8. Políticas con iam:PassRole sin restricciones
# --------------------------------------------------------------
def check_unrestricted_passrole():
    client = boto3.client('iam')
    findings = []
    try:
        paginator = client.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):
            for policy in page['Policies']:
                try:
                    version = client.get_policy_version(
                        PolicyArn=policy['Arn'],
                        VersionId=policy['DefaultVersionId']
                    )
                    doc = version['PolicyVersion']['Document']
                    if isinstance(doc, str):
                        doc = json.loads(doc)

                    for stmt in doc.get('Statement', []):
                        if stmt.get('Effect') != 'Allow':
                            continue
                        actions = stmt.get('Action', [])
                        if not isinstance(actions, list):
                            actions = [actions]
                        actions = [a.lower() for a in actions]
                        if 'iam:passrole' in actions or 'passrole' in actions:
                            resource = stmt.get('Resource', [])
                            if not isinstance(resource, list):
                                resource = [resource]
                            if '*' in resource:
                                findings.append({
                                    "resource": policy['PolicyName'],
                                    "arn": policy['Arn'],
                                    "issue": "Permite iam:PassRole sobre todos los roles (Resource: '*')"
                                })
                except ClientError:
                    continue
    except Exception as e:
        print(f"[!] Error escaneando iam:PassRole sin restricciones: {e}")
    return findings


# --------------------------------------------------------------
# 9. Políticas con sts:AssumeRole sin restricciones
# --------------------------------------------------------------
def check_unrestricted_assume_role():
    client = boto3.client('iam')
    findings = []
    try:
        paginator = client.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):
            for policy in page['Policies']:
                try:
                    version = client.get_policy_version(
                        PolicyArn=policy['Arn'],
                        VersionId=policy['DefaultVersionId']
                    )
                    doc = version['PolicyVersion']['Document']
                    if isinstance(doc, str):
                        doc = json.loads(doc)

                    for stmt in doc.get('Statement', []):
                        if stmt.get('Effect') != 'Allow':
                            continue
                        actions = stmt.get('Action', [])
                        if not isinstance(actions, list):
                            actions = [actions]
                        actions = [a.lower() for a in actions]
                        if 'sts:assumerole' in actions or 'assumerole' in actions:
                            resource = stmt.get('Resource', [])
                            if not isinstance(resource, list):
                                resource = [resource]
                            if '*' in resource:
                                findings.append({
                                    "resource": policy['PolicyName'],
                                    "arn": policy['Arn'],
                                    "issue": "Permite sts:AssumeRole sobre cualquier rol (Resource: '*')"
                                })
                except ClientError:
                    continue
    except Exception as e:
        print(f"[!] Error escaneando sts:AssumeRole sin restricciones: {e}")
    return findings


# --------------------------------------------------------------
# 10. Usuarios o roles con políticas en línea
# --------------------------------------------------------------
def check_inline_policies():
    client = boto3.client('iam')
    findings = []
    try:
        # Usuarios
        user_paginator = client.get_paginator('list_users')
        for page in user_paginator.paginate():
            for user in page['Users']:
                try:
                    policies = client.list_user_policies(UserName=user['UserName'])
                    if policies['PolicyNames']:
                        for name in policies['PolicyNames']:
                            findings.append({
                                "entity": user['UserName'],
                                "type": "Usuario",
                                "policy": name,
                                "issue": "Usa política en línea"
                            })
                except ClientError:
                    continue

        # Roles
        role_paginator = client.get_paginator('list_roles')
        for page in role_paginator.paginate():
            for role in page['Roles']:
                try:
                    policies = client.list_role_policies(RoleName=role['RoleName'])
                    if policies['PolicyNames']:
                        for name in policies['PolicyNames']:
                            findings.append({
                                "entity": role['RoleName'],
                                "type": "Rol",
                                "policy": name,
                                "issue": "Usa política en línea"
                            })
                except ClientError:
                    continue

    except Exception as e:
        print(f"[!] Error escaneando políticas en línea: {e}")
    return findings


# --------------------------------------------------------------
# 11. Políticas que permiten deshabilitar CloudTrail
# --------------------------------------------------------------
def check_cloudtrail_disable_permissions():
    client = boto3.client('iam')
    findings = []
    dangerous_actions = {
        'cloudtrail:stoplogging',
        'cloudtrail:deletetrail',
        'cloudtrail:deleteeventselectors',
        'cloudtrail:puteventselectors'
    }
    try:
        paginator = client.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):
            for policy in page['Policies']:
                try:
                    version = client.get_policy_version(
                        PolicyArn=policy['Arn'],
                        VersionId=policy['DefaultVersionId']
                    )
                    doc = version['PolicyVersion']['Document']
                    if isinstance(doc, str):
                        doc = json.loads(doc)

                    for stmt in doc.get('Statement', []):
                        if stmt.get('Effect') != 'Allow':
                            continue
                        actions = stmt.get('Action', [])
                        if not isinstance(actions, list):
                            actions = [actions]
                        actions = {a.lower() for a in actions}
                        if actions & dangerous_actions:  # intersección
                            findings.append({
                                "resource": policy['PolicyName'],
                                "arn": policy['Arn'],
                                "issue": "Permite deshabilitar o modificar CloudTrail"
                            })
                except ClientError:
                    continue
    except Exception as e:
        print(f"[!] Error escaneando permisos de CloudTrail: {e}")
    return findings