"""
AWS S3 Security Auditor - Fase 2: Storage Security
Detecta configuraciones inseguras en buckets S3
"""
import sys, os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from botocore.exceptions import ClientError
from core.aws_session import get_session, get_account_id
from core.reporter import format_finding


def check_public_buckets():
    """
    Detecta buckets S3 con acceso público (ACL o Policy).

    Returns:
        list: Lista de hallazgos
    """
    session = get_session()
    client = session.client('s3')
    findings = []

    try:
        print("[*] Verificando buckets S3 públicos...")

        response = client.list_buckets()

        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']

            try:
                # Verificar ACL pública
                acl = client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('URI') and 'AllUsers' in grantee.get('URI'):
                        findings.append(format_finding(
                            check_name="S3 Bucket Público (ACL)",
                            entity=bucket_name,
                            issue="Bucket con ACL pública (AllUsers)",
                            severity="CRITICAL",
                            storage_type="S3"
                        ))
                        break

                # Verificar Bucket Policy pública
                try:
                    policy = client.get_bucket_policy(Bucket=bucket_name)
                    import json
                    policy_doc = json.loads(policy['Policy'])

                    for stmt in policy_doc.get('Statement', []):
                        if stmt.get('Effect') == 'Allow':
                            principal = stmt.get('Principal', {})
                            if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                                findings.append(format_finding(
                                    check_name="S3 Bucket Público (Policy)",
                                    entity=bucket_name,
                                    issue="Bucket Policy permite acceso público",
                                    severity="CRITICAL",
                                    storage_type="S3"
                                ))
                                break
                except ClientError as e:
                    if 'NoSuchBucketPolicy' not in str(e):
                        pass  # Sin policy, está bien

                # Verificar PublicAccessBlock
                try:
                    pab = client.get_public_access_block(Bucket=bucket_name)
                    block = pab.get('PublicAccessBlockConfiguration', {})

                    if not all([
                        block.get('BlockPublicAcls', False),
                        block.get('BlockPublicPolicy', False),
                        block.get('IgnorePublicAcls', False),
                        block.get('RestrictPublicBuckets', False)
                    ]):
                        # Solo agregar si no se encontró ya como público
                        existing = [f for f in findings if f['entity'] == bucket_name]
                        if not existing:
                            findings.append(format_finding(
                                check_name="S3 PublicAccessBlock incompleto",
                                entity=bucket_name,
                                issue="PublicAccessBlock no tiene todas las protecciones activas",
                                severity="MEDIUM",
                                storage_type="S3"
                            ))
                except ClientError:
                    pass  # Sin PublicAccessBlock configurado

            except ClientError as e:
                print(f"[!] Error verificando bucket {bucket_name}: {e}")

    except Exception as e:
        print(f"[!] Error en check_public_buckets: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_buckets_without_versioning():
    """
    Detecta buckets S3 sin versioning habilitado.

    Returns:
        list: Lista de hallazgos
    """
    session = get_session()
    client = session.client('s3')
    findings = []

    try:
        print("[*] Verificando buckets sin versioning...")

        response = client.list_buckets()

        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']

            try:
                versioning = client.get_bucket_versioning(Bucket=bucket_name)
                status = versioning.get('Status', 'Disabled')

                if status != 'Enabled':
                    findings.append(format_finding(
                        check_name="S3 sin Versioning",
                        entity=bucket_name,
                        issue="Bucket sin versioning habilitado (riesgo de pérdida de datos)",
                        severity="MEDIUM",
                        storage_type="S3"
                    ))

            except ClientError as e:
                print(f"[!] Error verificando versioning en {bucket_name}: {e}")

    except Exception as e:
        print(f"[!] Error en check_buckets_without_versioning: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_buckets_without_encryption():
    """
    Detecta buckets S3 sin cifrado SSE-KMS habilitado.

    Returns:
        list: Lista de hallazgos
    """
    session = get_session()
    client = session.client('s3')
    findings = []

    try:
        print("[*] Verificando buckets sin cifrado SSE-KMS...")

        response = client.list_buckets()

        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']

            try:
                encryption = client.get_bucket_encryption(Bucket=bucket_name)
                rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])

                has_kms = False
                for rule in rules:
                    apply = rule.get('ApplyServerSideEncryptionByDefault', {})
                    if apply.get('SSEAlgorithm') == 'aws:kms':
                        has_kms = True
                        break

                if not has_kms:
                    # Verificar si al menos tiene SSE-S3
                    has_s3 = False
                    for rule in rules:
                        apply = rule.get('ApplyServerSideEncryptionByDefault', {})
                        if apply.get('SSEAlgorithm') == 'AES256':
                            has_s3 = True
                            break

                    if not has_s3:
                        findings.append(format_finding(
                            check_name="S3 sin Cifrado",
                            entity=bucket_name,
                            issue="Bucket sin cifrado habilitado (ni SSE-S3 ni SSE-KMS)",
                            severity="HIGH",
                            storage_type="S3"
                        ))
                    else:
                        findings.append(format_finding(
                            check_name="S3 sin SSE-KMS",
                            entity=bucket_name,
                            issue="Bucket usa SSE-S3 pero no SSE-KMS (recomendado para datos sensibles)",
                            severity="LOW",
                            storage_type="S3"
                        ))

            except ClientError as e:
                if 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
                    findings.append(format_finding(
                        check_name="S3 sin Cifrado",
                        entity=bucket_name,
                        issue="Bucket sin configuración de cifrado",
                        severity="HIGH",
                        storage_type="S3"
                    ))
                else:
                    print(f"[!] Error verificando cifrado en {bucket_name}: {e}")

    except Exception as e:
        print(f"[!] Error en check_buckets_without_encryption: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_object_lock_disabled():
    """
    Detecta buckets S3 críticos sin Object Lock habilitado.

    Returns:
        list: Lista de hallazgos
    """
    session = get_session()
    client = session.client('s3')
    findings = []

    try:
        print("[*] Verificando Object Lock en buckets...")

        response = client.list_buckets()

        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']

            # Solo verificar buckets que parezcan de backup/críticos
            critical_keywords = ['backup', 'archive', 'log', 'audit', 'compliance']
            if not any(keyword in bucket_name.lower() for keyword in critical_keywords):
                continue

            try:
                object_lock = client.get_object_lock_configuration(Bucket=bucket_name)
                # Si llega aquí, tiene Object Lock pero verificar si está enabled
                status = object_lock.get('ObjectLockConfiguration', {}).get('Status', 'Disabled')
                if status != 'Enabled':
                    findings.append(format_finding(
                        check_name="S3 Object Lock deshabilitado",
                        entity=bucket_name,
                        issue="Bucket crítico sin Object Lock habilitado (WORM protection)",
                        severity="MEDIUM",
                        storage_type="S3"
                    ))
            except ClientError as e:
                if 'ObjectLockConfigurationNotFoundError' in str(e):
                    findings.append(format_finding(
                        check_name="S3 sin Object Lock",
                        entity=bucket_name,
                        issue="Bucket crítico sin Object Lock configurado",
                        severity="MEDIUM",
                        storage_type="S3"
                    ))
                else:
                    pass  # Ignorar otros errores

            except Exception:
                pass  # Bucket no soporta Object Lock (necesita versioning)

    except Exception as e:
        print(f"[!] Error en check_object_lock_disabled: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_all_s3():
    """
    Función combinada para ejecutar todos los checks de S3.
    """
    all_findings = []

    findings = check_public_buckets()
    all_findings.extend(findings)

    findings = check_buckets_without_versioning()
    all_findings.extend(findings)

    findings = check_buckets_without_encryption()
    all_findings.extend(findings)

    findings = check_object_lock_disabled()
    all_findings.extend(findings)

    return all_findings