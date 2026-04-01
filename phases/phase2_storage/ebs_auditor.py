"""
AWS EBS Security Auditor - Fase 2: Storage Security
Detecta configuraciones inseguras en volúmenes EBS y snapshots
"""
import sys, os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from botocore.exceptions import ClientError
from core.aws_session import get_session, get_account_id
from core.reporter import format_finding


def check_unencrypted_volumes(regions=None):
    """
    Detecta volúmenes EBS sin cifrado habilitado.

    Returns:
        list: Lista de hallazgos
    """
    if regions is None:
        regions = ['us-east-1']  # Solo región principal por defecto

    session = get_session()
    findings = []

    try:
        print("[*] Verificando volúmenes EBS sin cifrado...")

        for region in regions:
            try:
                ec2_client = session.client('ec2', region_name=region)

                # Verificar volúmenes
                paginator = ec2_client.get_paginator('describe_volumes')
                for page in paginator.paginate():
                    for volume in page.get('Volumes', []):
                        if not volume.get('Encrypted', False):
                            findings.append(format_finding(
                                check_name="EBS sin Cifrado",
                                entity=volume['VolumeId'],
                                issue=f"Volumen EBS sin cifrado en {region}",
                                severity="HIGH",
                                storage_type="EBS",
                                region=region,
                                size_gb=volume.get('Size', 'N/A')
                            ))

            except ClientError as e:
                print(f"[!] Error en región {region}: {e}")
            except Exception as e:
                print(f"[!] Error inesperado en región {region}: {e}")

    except Exception as e:
        print(f"[!] Error en check_unencrypted_volumes: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_public_snapshots(regions=None):
    """
    Detecta snapshots EBS públicos (compartidos con todos).

    Returns:
        list: Lista de hallazgos
    """
    if regions is None:
        regions = ['us-east-1']  # Solo región principal por defecto

    session = get_session()
    account_id = get_account_id(session)
    findings = []

    try:
        print("[*] Verificando snapshots EBS públicos...")

        for region in regions:
            try:
                ec2_client = session.client('ec2', region_name=region)

                # Verificar snapshots propios
                paginator = ec2_client.get_paginator('describe_snapshots')
                for page in paginator.paginate(OwnerIds=[account_id]):
                    for snapshot in page.get('Snapshots', []):
                        snapshot_id = snapshot['SnapshotId']

                        # Verificar permisos del snapshot
                        try:
                            attrs = ec2_client.describe_snapshot_attribute(
                                SnapshotId=snapshot_id,
                                Attribute='createVolumePermission'
                            )

                            create_perms = attrs.get('CreateVolumePermissions', [])
                            for perm in create_perms:
                                if perm.get('Group') == 'all':
                                    findings.append(format_finding(
                                        check_name="EBS Snapshot Público",
                                        entity=snapshot_id,
                                        issue=f"Snapshot EBS público (compartido con todos) en {region}",
                                        severity="CRITICAL",
                                        storage_type="EBS",
                                        region=region,
                                        volume_id=snapshot.get('VolumeId', 'N/A')
                                    ))
                                    break

                        except ClientError:
                            pass  # Sin permisos para verificar

            except ClientError as e:
                print(f"[!] Error en región {region}: {e}")
            except Exception as e:
                print(f"[!] Error inesperado en región {region}: {e}")

    except Exception as e:
        print(f"[!] Error en check_public_snapshots: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_all_ebs():
    """
    Función combinada para ejecutar todos los checks de EBS.
    """
    all_findings = []

    findings = check_unencrypted_volumes()
    all_findings.extend(findings)

    findings = check_public_snapshots()
    all_findings.extend(findings)

    return all_findings