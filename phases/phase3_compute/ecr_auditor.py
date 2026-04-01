"""
AWS ECR Security Auditor - Fase 3: Compute Security
Detecta configuraciones inseguras en Elastic Container Registry
"""
import sys, os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from botocore.exceptions import ClientError
from core.aws_session import get_session, get_account_id
from core.reporter import format_finding


def check_images_without_scanning(regions=None):
    """
    Detecta repositorios ECR con imágenes que no han sido escaneadas por vulnerabilidades.

    Returns:
        list: Lista de hallazgos
    """
    if regions is None:
        regions = ['us-east-1']

    session = get_session()
    findings = []

    try:
        print("[*] Verificando imágenes ECR sin vulnerability scanning...")

        for region in regions:
            try:
                ecr_client = session.client('ecr', region_name=region)

                # Obtener repositorios
                paginator = ecr_client.get_paginator('describe_repositories')
                for page in paginator.paginate():
                    for repo in page.get('repositories', []):
                        repo_name = repo['repositoryName']

                        # Verificar configuración de scanning
                        try:
                            scanning_config = ecr_client.get_repository_scanning_configuration(
                                repositoryName=repo_name
                            )
                            if not scanning_config.get('scanningConfiguration', {}).get('scanOnPush', False):
                                findings.append(format_finding(
                                    check_name="ECR scanOnPush desactivado",
                                    entity=repo_name,
                                    issue="Repositorio ECR con scanOnPush desactivado (imágenes no escaneadas)",
                                    severity="MEDIUM",
                                    compute_type="ECR",
                                    region=region
                                ))
                        except ClientError:
                            pass  # Configuración no disponible en todas las regiones

                        # Verificar imágenes sin resultados de scanning
                        try:
                            images = ecr_client.list_images(repositoryName=repo_name, maxResults=10)
                            for image in images.get('imageIds', []):
                                image_tag = image.get('imageTag', 'untagged')

                                try:
                                    scan_status = ecr_client.describe_image_scan_findings(
                                        repositoryName=repo_name,
                                        imageId=image
                                    )
                                    findings_data = scan_status.get('imageScanFindings', {})

                                    if findings_data.get('imageScanCompletedAt') is None:
                                        findings.append(format_finding(
                                            check_name="ECR imagen sin scanning",
                                            entity=f"{repo_name}:{image_tag}",
                                            issue="Imagen ECR sin resultados de vulnerability scanning",
                                            severity="MEDIUM",
                                            compute_type="ECR",
                                            region=region,
                                            image_digest=image.get('imageDigest', 'N/A')[:12]
                                        ))

                                except ClientError as e:
                                    if 'ScanNotFoundException' in str(e) or 'RepositoryPolicyNotFoundException' in str(
                                            e):
                                        findings.append(format_finding(
                                            check_name="ECR imagen sin scanning",
                                            entity=f"{repo_name}:{image_tag}",
                                            issue="Imagen ECR nunca ha sido escaneada",
                                            severity="MEDIUM",
                                            compute_type="ECR",
                                            region=region
                                        ))

                        except ClientError:
                            pass

            except ClientError as e:
                print(f"[!] Error en región {region}: {e}")
            except Exception as e:
                print(f"[!] Error inesperado en región {region}: {e}")

    except Exception as e:
        print(f"[!] Error en check_images_without_scanning: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_public_ecr_repositories(regions=None):
    """
    Detecta repositorios ECR propios que son públicos.

    Returns:
        list: Lista de hallazgos
    """
    if regions is None:
        regions = ['us-east-1']

    session = get_session()
    account_id = get_account_id(session)
    findings = []

    try:
        print("[*] Verificando repositorios ECR públicos...")

        for region in regions:
            try:
                ecr_client = session.client('ecr', region_name=region)

                paginator = ecr_client.get_paginator('describe_repositories')
                for page in paginator.paginate():
                    for repo in page.get('repositories', []):
                        repo_name = repo['repositoryName']
                        repo_arn = repo['repositoryArn']

                        # Verificar política del repositorio
                        try:
                            policy = ecr_client.get_repository_policy(repositoryName=repo_name)
                            import json
                            policy_doc = json.loads(policy['policyText'])

                            for stmt in policy_doc.get('Statement', []):
                                if stmt.get('Effect') == 'Allow':
                                    principal = stmt.get('Principal', {})

                                    if principal == '*':
                                        findings.append(format_finding(
                                            check_name="ECR repositorio público",
                                            entity=repo_name,
                                            issue="Repositorio ECR con política pública (Principal: *)",
                                            severity="HIGH",
                                            compute_type="ECR",
                                            region=region,
                                            repo_arn=repo_arn
                                        ))
                                        break

                                    if isinstance(principal, dict):
                                        aws_principal = principal.get('AWS', '')
                                        if aws_principal == '*' or (
                                                isinstance(aws_principal, list) and '*' in aws_principal):
                                            findings.append(format_finding(
                                                check_name="ECR repositorio público",
                                                entity=repo_name,
                                                issue="Repositorio ECR accesible desde cualquier cuenta AWS",
                                                severity="HIGH",
                                                compute_type="ECR",
                                                region=region
                                            ))

                        except ClientError as e:
                            if 'RepositoryPolicyNotFoundException' not in str(e):
                                print(f"[!] Error verificando política de {repo_name}: {e}")

            except ClientError as e:
                print(f"[!] Error en región {region}: {e}")
            except Exception as e:
                print(f"[!] Error inesperado en región {region}: {e}")

    except Exception as e:
        print(f"[!] Error en check_public_ecr_repositories: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_missing_lifecycle_policy(regions=None):
    """
    Detecta repositorios ECR sin lifecycle policy (acumulación de imágenes).

    Returns:
        list: Lista de hallazgos
    """
    if regions is None:
        regions = ['us-east-1']

    session = get_session()
    findings = []

    try:
        print("[*] Verificando repositorios ECR sin lifecycle policy...")

        for region in regions:
            try:
                ecr_client = session.client('ecr', region_name=region)

                paginator = ecr_client.get_paginator('describe_repositories')
                for page in paginator.paginate():
                    for repo in page.get('repositories', []):
                        repo_name = repo['repositoryName']

                        try:
                            ecr_client.get_lifecycle_policy(repositoryName=repo_name)
                        except ClientError as e:
                            if 'LifecyclePolicyNotFoundException' in str(e):
                                findings.append(format_finding(
                                    check_name="ECR sin lifecycle policy",
                                    entity=repo_name,
                                    issue="Repositorio sin lifecycle policy (puede acumular imágenes viejas)",
                                    severity="LOW",
                                    compute_type="ECR",
                                    region=region,
                                    recommendation="Configurar regla para eliminar imágenes antiguas"
                                ))

            except ClientError as e:
                print(f"[!] Error en región {region}: {e}")
            except Exception as e:
                print(f"[!] Error inesperado en región {region}: {e}")

    except Exception as e:
        print(f"[!] Error en check_missing_lifecycle_policy: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_all_ecr():
    """
    Función combinada para ejecutar todos los checks de ECR.
    """
    all_findings = []

    findings = check_images_without_scanning()
    all_findings.extend(findings)

    findings = check_public_ecr_repositories()
    all_findings.extend(findings)

    findings = check_missing_lifecycle_policy()
    all_findings.extend(findings)

    return all_findings