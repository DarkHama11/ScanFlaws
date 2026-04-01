"""
AWS Lambda Security Auditor - Fase 3: Compute Security
Detecta configuraciones inseguras en funciones Lambda
"""
import sys, os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from botocore.exceptions import ClientError
from core.aws_session import get_session, get_account_id
from core.reporter import format_finding

# Acciones IAM peligrosas para roles de Lambda
DANGEROUS_LAMBDA_ACTIONS = {
    'iam:PassRole',
    'iam:CreateAccessKey',
    'iam:CreateUser',
    'sts:AssumeRole',
    'lambda:CreateFunction',
    'lambda:UpdateFunctionCode',
    's3:PutBucketPolicy',
    's3:DeleteBucket',
    'ec2:AuthorizeSecurityGroupIngress'
}


def check_lambda_excessive_roles(regions=None):
    """
    Detecta funciones Lambda con roles que tienen permisos excesivos.

    Returns:
        list: Lista de hallazgos
    """
    if regions is None:
        regions = ['us-east-1']

    session = get_session()
    findings = []

    try:
        print("[*] Verificando roles de Lambda con permisos excesivos...")

        for region in regions:
            try:
                lambda_client = session.client('lambda', region_name=region)
                iam_client = session.client('iam')

                # Obtener funciones Lambda
                paginator = lambda_client.get_paginator('list_functions')
                for page in paginator.paginate():
                    for func in page.get('Functions', []):
                        func_name = func['FunctionName']
                        role_arn = func['Role']

                        # Extraer nombre del rol del ARN
                        role_name = role_arn.split('/')[-1]

                        try:
                            # Obtener políticas adjuntas al rol
                            attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)

                            for policy in attached_policies.get('AttachedPolicies', []):
                                policy_arn = policy['PolicyArn']
                                policy_name = policy['PolicyName']

                                # Verificar si es política administrada de AWS con permisos amplios
                                if 'AdministratorAccess' in policy_name or 'FullAccess' in policy_name:
                                    findings.append(format_finding(
                                        check_name="Lambda con rol excesivo",
                                        entity=func_name,
                                        issue=f"Función usa política '{policy_name}' con permisos amplios",
                                        severity="HIGH",
                                        compute_type="Lambda",
                                        region=region,
                                        role_name=role_name,
                                        policy_name=policy_name
                                    ))

                                # Para políticas custom, verificar acciones peligrosas
                                elif not policy_arn.startswith('arn:aws:iam::aws:'):
                                    try:
                                        policy_version = iam_client.get_policy_version(
                                            PolicyArn=policy_arn,
                                            VersionId=policy['DefaultVersionId']
                                        )
                                        doc = policy_version['PolicyVersion']['Document']

                                        import json
                                        if isinstance(doc, str):
                                            doc = json.loads(doc)

                                        for stmt in doc.get('Statement', []):
                                            if stmt.get('Effect') != 'Allow':
                                                continue

                                            actions = stmt.get('Action', [])
                                            if not isinstance(actions, list):
                                                actions = [actions]

                                            dangerous_found = set(actions) & DANGEROUS_LAMBDA_ACTIONS
                                            if dangerous_found and stmt.get('Resource') == '*':
                                                findings.append(format_finding(
                                                    check_name="Lambda con acción peligrosa",
                                                    entity=func_name,
                                                    issue=f"Rol permite {dangerous_found} sobre todos los recursos",
                                                    severity="HIGH",
                                                    compute_type="Lambda",
                                                    region=region,
                                                    role_name=role_name,
                                                    actions=list(dangerous_found)
                                                ))

                                    except ClientError:
                                        pass

                        except ClientError as e:
                            print(f"[!] Error verificando rol de {func_name}: {e}")

            except ClientError as e:
                print(f"[!] Error en región {region}: {e}")
            except Exception as e:
                print(f"[!] Error inesperado en región {region}: {e}")

    except Exception as e:
        print(f"[!] Error en check_lambda_excessive_roles: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_unencrypted_lambda_env_variables(regions=None):
    """
    Detecta funciones Lambda con variables de entorno sensibles sin cifrar con KMS.

    Returns:
        list: Lista de hallazgos
    """
    if regions is None:
        regions = ['us-east-1']

    session = get_session()
    findings = []

    # Palabras clave que indican datos sensibles en nombres de variables
    sensitive_keywords = ['password', 'secret', 'key', 'token', 'api_key', 'apikey', 'credential']

    try:
        print("[*] Verificando variables de entorno sensibles sin cifrar...")

        for region in regions:
            try:
                lambda_client = session.client('lambda', region_name=region)

                paginator = lambda_client.get_paginator('list_functions')
                for page in paginator.paginate():
                    for func in page.get('Functions', []):
                        func_name = func['FunctionName']

                        # Obtener configuración completa
                        config = lambda_client.get_function_configuration(FunctionName=func_name)
                        env_vars = config.get('Environment', {}).get('Variables', {})
                        kms_key = config.get('KMSKeyArn')

                        if env_vars:
                            for var_name in env_vars.keys():
                                var_lower = var_name.lower()

                                # Verificar si el nombre sugiere dato sensible
                                if any(keyword in var_lower for keyword in sensitive_keywords):
                                    if not kms_key:
                                        findings.append(format_finding(
                                            check_name="Lambda env variable sin cifrar",
                                            entity=func_name,
                                            issue=f"Variable '{var_name}' parece sensible pero no usa KMS",
                                            severity="HIGH",
                                            compute_type="Lambda",
                                            region=region,
                                            variable_name=var_name
                                        ))

            except ClientError as e:
                print(f"[!] Error en región {region}: {e}")
            except Exception as e:
                print(f"[!] Error inesperado en región {region}: {e}")

    except Exception as e:
        print(f"[!] Error en check_unencrypted_lambda_env_variables: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_lambda_without_xray(regions=None):
    """
    Detecta funciones Lambda sin AWS X-Ray habilitado (sin trazabilidad).

    Returns:
        list: Lista de hallazgos
    """
    if regions is None:
        regions = ['us-east-1']

    session = get_session()
    findings = []

    try:
        print("[*] Verificando funciones Lambda sin X-Ray...")

        for region in regions:
            try:
                lambda_client = session.client('lambda', region_name=region)

                paginator = lambda_client.get_paginator('list_functions')
                for page in paginator.paginate():
                    for func in page.get('Functions', []):
                        func_name = func['FunctionName']
                        tracing_config = func.get('TracingConfig', {}).get('Mode', 'PassThrough')

                        if tracing_config != 'Active':
                            findings.append(format_finding(
                                check_name="Lambda sin X-Ray",
                                entity=func_name,
                                issue="Función sin AWS X-Ray habilitado (sin trazabilidad de requests)",
                                severity="LOW",
                                compute_type="Lambda",
                                region=region,
                                tracing_mode=tracing_config
                            ))

            except ClientError as e:
                print(f"[!] Error en región {region}: {e}")
            except Exception as e:
                print(f"[!] Error inesperado en región {region}: {e}")

    except Exception as e:
        print(f"[!] Error en check_lambda_without_xray: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_all_lambda():
    """
    Función combinada para ejecutar todos los checks de Lambda.
    """
    all_findings = []

    findings = check_lambda_excessive_roles()
    all_findings.extend(findings)

    findings = check_unencrypted_lambda_env_variables()
    all_findings.extend(findings)

    findings = check_lambda_without_xray()
    all_findings.extend(findings)

    return all_findings