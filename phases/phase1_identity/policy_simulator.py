"""
Evaluación automática de políticas con IAM Policy Simulator
Fase 1: Identity Security - Módulo Security Specialty
"""
import sys, os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from botocore.exceptions import ClientError

from core.aws_session import get_iam_client, get_sts_client
from core.reporter import format_finding

# Acciones críticas para detectar privilege escalation
CRITICAL_ACTIONS = [
    'iam:AttachUserPolicy',
    'iam:AttachRolePolicy',
    'iam:AttachGroupPolicy',
    'iam:CreateAccessKey',
    'iam:CreateLoginProfile',
    'iam:UpdateLoginProfile',
    'iam:PassRole',
    'sts:AssumeRole',
    'lambda:CreateFunction',
    'lambda:UpdateFunctionCode',
    'glue:CreateDevEndpoint',
    'cloudformation:CreateStack',
    'ec2:RunInstances',
    'iam:CreatePolicyVersion',
    'iam:SetDefaultPolicyVersion',
    'iam:CreateUser',
    'iam:DeleteUserPolicy',
    'iam:PutUserPolicy'
]


def simulate_role_policy(role_name, actions_to_test=None):
    """
    Simula permisos efectivos de un rol usando IAM Policy Simulator.
    Detecta si un rol podría escalar privilegios.

    Args:
        role_name: Nombre del rol a simular
        actions_to_test: Lista de acciones a probar (default: CRITICAL_ACTIONS)

    Returns:
        list: Lista de hallazgos
    """
    if actions_to_test is None:
        actions_to_test = CRITICAL_ACTIONS

    client = get_iam_client()
    sts = get_sts_client()
    account_id = sts.get_caller_identity()['Account']
    findings = []

    try:
        response = client.simulate_principal_policy(
            PolicySourceArn=f'arn:aws:iam::{account_id}:role/{role_name}',
            ActionNames=actions_to_test
        )

        for result in response.get('EvaluationResults', []):
            if result.get('EvalDecision') == 'allowed':
                action = result.get('EvalActionName')

                # Verificar si hay condiciones restrictivas
                matched_statements = result.get('MatchedStatements', [])
                has_conditions = any(
                    stmt.get('Condition', {})
                    for stmt in matched_statements
                )

                # Si no tiene condiciones, es un riesgo potencial
                if not has_conditions:
                    severity = "CRITICAL" if action in ['iam:CreateAccessKey', 'iam:PassRole',
                                                        'iam:SetDefaultPolicyVersion'] else "HIGH"

                    findings.append(format_finding(
                        check_name="Escalada de privilegios",
                        entity=role_name,
                        issue=f"Rol puede ejecutar {action} SIN restricciones",
                        severity=severity,
                        extra_data={
                            "action": action,
                            "recommendation": f"Revisar si {action} es necesario y agregar condiciones"
                        }
                    ))

    except ClientError as e:
        if 'NoSuchEntity' in str(e):
            pass  # Rol no existe, ignorar
        elif 'AccessDenied' in str(e):
            pass  # Sin permisos para simular, ignorar
        else:
            print(f"[!] Error simulando política de {role_name}: {e}")
    except Exception as e:
        print(f"[!] Error inesperado en simulación de {role_name}: {e}")

    return findings


def check_roles_with_escalation_paths(max_roles_to_check=50):
    """
    Escanea roles para detectar posibles rutas de escalada de privilegios.

    Args:
        max_roles_to_check: Máximo número de roles a escanear (para no hacer lento)

    Returns:
        list: Lista de hallazgos
    """
    client = get_iam_client()
    findings = []
    roles_checked = 0

    try:
        print(f"[*] Simulando políticas de roles (máx {max_roles_to_check})...")

        paginator = client.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                if roles_checked >= max_roles_to_check:
                    break

                role_name = role['RoleName']

                # Saltar roles de servicio de AWS
                if role_name.startswith('AWSServiceRole'):
                    continue

                role_findings = simulate_role_policy(role_name)
                findings.extend(role_findings)
                roles_checked += 1

            if roles_checked >= max_roles_to_check:
                break

    except Exception as e:
        print(f"[!] Error escaneando roles para escalada: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_users_with_escalation_paths(max_users_to_check=50):
    """
    Escanea usuarios para detectar posibles rutas de escalada de privilegios.

    Args:
        max_users_to_check: Máximo número de usuarios a escanear

    Returns:
        list: Lista de hallazgos
    """
    client = get_iam_client()
    findings = []
    users_checked = 0

    try:
        print(f"[*] Simulando políticas de usuarios (máx {max_users_to_check})...")

        paginator = client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                if users_checked >= max_users_to_check:
                    break

                username = user['UserName']

                # Saltar usuario root
                if username == '<root_account>':
                    continue

                user_findings = simulate_role_policy(username)  # simulate_principal_policy funciona con users también
                findings.extend(user_findings)
                users_checked += 1

            if users_checked >= max_users_to_check:
                break

    except Exception as e:
        print(f"[!] Error escaneando usuarios para escalada: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_all_policy_simulations():
    """
    Función combinada para ejecutar todos los checks de Policy Simulator.
    """
    all_findings = []

    findings = check_roles_with_escalation_paths()
    all_findings.extend(findings)

    # Opcional: Descomentar si quieres escanear usuarios también (puede ser lento)
    # findings = check_users_with_escalation_paths()
    # all_findings.extend(findings)

    return all_findings