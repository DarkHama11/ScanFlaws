"""
AWS EC2 Security Auditor - Fase 3: Compute Security
Detecta configuraciones inseguras en instancias EC2 y recursos relacionados
"""
import sys, os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from botocore.exceptions import ClientError
from core.aws_session import get_session, get_account_id
from core.reporter import format_finding

# Puertos sensibles que no deberían estar abiertos a 0.0.0.0/0
SENSITIVE_PORTS = {
    22: 'SSH',
    3389: 'RDP',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    27017: 'MongoDB',
    6379: 'Redis',
    9200: 'Elasticsearch',
    8080: 'HTTP-Alt',
    1433: 'MSSQL'
}


def check_security_groups_open_to_internet(regions=None):
    """
    Detecta Security Groups con reglas inbound que permiten 0.0.0.0/0 en puertos sensibles.

    Returns:
        list: Lista de hallazgos
    """
    if regions is None:
        regions = ['us-east-1']

    session = get_session()
    findings = []

    try:
        print("[*] Verificando Security Groups abiertos a internet...")

        for region in regions:
            try:
                ec2_client = session.client('ec2', region_name=region)

                # Obtener todos los security groups
                paginator = ec2_client.get_paginator('describe_security_groups')
                for page in paginator.paginate():
                    for sg in page.get('SecurityGroups', []):
                        sg_id = sg['GroupId']
                        sg_name = sg['GroupName']

                        for rule in sg.get('IpPermissions', []):
                            from_port = rule.get('FromPort')
                            to_port = rule.get('ToPort')

                            for ip_range in rule.get('IpRanges', []):
                                cidr = ip_range.get('CidrIp', '')

                                if cidr == '0.0.0.0/0':
                                    # Verificar si es puerto sensible
                                    if from_port in SENSITIVE_PORTS:
                                        port_name = SENSITIVE_PORTS[from_port]
                                        findings.append(format_finding(
                                            check_name="SG Puerto sensible abierto",
                                            entity=f"{sg_name} ({sg_id})",
                                            issue=f"Puerto {from_port} ({port_name}) abierto a 0.0.0.0/0",
                                            severity="CRITICAL",
                                            compute_type="EC2",
                                            region=region,
                                            port=from_port,
                                            cidr=cidr
                                        ))
                                    # Rango de puertos que incluye sensibles
                                    elif from_port is None or to_port is None:
                                        findings.append(format_finding(
                                            check_name="SG Todos los puertos abiertos",
                                            entity=f"{sg_name} ({sg_id})",
                                            issue="Security Group permite todo el tráfico inbound desde 0.0.0.0/0",
                                            severity="CRITICAL",
                                            compute_type="EC2",
                                            region=region,
                                            cidr=cidr
                                        ))

            except ClientError as e:
                print(f"[!] Error en región {region}: {e}")
            except Exception as e:
                print(f"[!] Error inesperado en región {region}: {e}")

    except Exception as e:
        print(f"[!] Error en check_security_groups_open_to_internet: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_instances_without_ssm(regions=None):
    """
    Detecta instancias EC2 sin SSM Agent instalado/activo.

    Returns:
        list: Lista de hallazgos
    """
    if regions is None:
        regions = ['us-east-1']

    session = get_session()
    findings = []

    try:
        print("[*] Verificando instancias sin SSM Agent...")

        for region in regions:
            try:
                ec2_client = session.client('ec2', region_name=region)
                ssm_client = session.client('ssm', region_name=region)

                # Obtener instancias en ejecución
                paginator = ec2_client.get_paginator('describe_instances')
                for page in paginator.paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]):
                    for reservation in page.get('Reservations', []):
                        for instance in reservation.get('Instances', []):
                            instance_id = instance['InstanceId']
                            instance_name = 'N/A'

                            # Buscar nombre en tags
                            for tag in instance.get('Tags', []):
                                if tag['Key'] == 'Name':
                                    instance_name = tag['Value']
                                    break

                            # Verificar si la instancia está registrada en SSM
                            try:
                                ssm_response = ssm_client.describe_instance_information(
                                    Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
                                )
                                instances_ssm = ssm_response.get('InstanceInformationList', [])

                                if not instances_ssm or instances_ssm[0].get('PingStatus') != 'Online':
                                    findings.append(format_finding(
                                        check_name="EC2 sin SSM Agent",
                                        entity=f"{instance_name} ({instance_id})",
                                        issue="Instancia sin SSM Agent activo (gestión remota insegura)",
                                        severity="MEDIUM",
                                        compute_type="EC2",
                                        region=region,
                                        instance_type=instance.get('InstanceType', 'N/A')
                                    ))

                            except ClientError:
                                # Si no tiene permisos para SSM, asumir que no está instalado
                                findings.append(format_finding(
                                    check_name="EC2 sin SSM Agent",
                                    entity=f"{instance_name} ({instance_id})",
                                    issue="No se pudo verificar SSM Agent (posiblemente no instalado)",
                                    severity="LOW",
                                    compute_type="EC2",
                                    region=region
                                ))

            except ClientError as e:
                print(f"[!] Error en región {region}: {e}")
            except Exception as e:
                print(f"[!] Error inesperado en región {region}: {e}")

    except Exception as e:
        print(f"[!] Error en check_instances_without_ssm: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_unencrypted_instance_volumes(regions=None):
    """
    Detecta volúmenes EBS adjuntos a instancias EC2 sin cifrado.

    Returns:
        list: Lista de hallazgos
    """
    if regions is None:
        regions = ['us-east-1']

    session = get_session()
    findings = []

    try:
        print("[*] Verificando volúmenes de instancias sin cifrado...")

        for region in regions:
            try:
                ec2_client = session.client('ec2', region_name=region)

                # Obtener volúmenes adjuntos
                paginator = ec2_client.get_paginator('describe_volumes')
                for page in paginator.paginate(Filters=[{'Name': 'status', 'Values': ['in-use']}]):
                    for volume in page.get('Volumes', []):
                        if not volume.get('Encrypted', False):
                            volume_id = volume['VolumeId']

                            # Buscar instancia asociada
                            instance_id = 'N/A'
                            if volume.get('Attachments'):
                                instance_id = volume['Attachments'][0].get('InstanceId', 'N/A')

                            findings.append(format_finding(
                                check_name="Volumen EC2 sin cifrado",
                                entity=f"{volume_id} -> {instance_id}",
                                issue="Volumen EBS adjunto a instancia sin cifrado",
                                severity="HIGH",
                                compute_type="EC2",
                                region=region,
                                volume_size=volume.get('Size', 'N/A')
                            ))

            except ClientError as e:
                print(f"[!] Error en región {region}: {e}")
            except Exception as e:
                print(f"[!] Error inesperado en región {region}: {e}")

    except Exception as e:
        print(f"[!] Error en check_unencrypted_instance_volumes: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_public_amis(regions=None):
    """
    Detecta AMIs propias que son públicas (compartidas con todos).

    Returns:
        list: Lista de hallazgos
    """
    if regions is None:
        regions = ['us-east-1']

    session = get_session()
    account_id = get_account_id(session)
    findings = []

    try:
        print("[*] Verificando AMIs públicas propias...")

        for region in regions:
            try:
                ec2_client = session.client('ec2', region_name=region)

                # Obtener AMIs propias
                paginator = ec2_client.get_paginator('describe_images')
                for page in paginator.paginate(Owners=[account_id]):
                    for image in page.get('Images', []):
                        image_id = image['ImageId']
                        image_name = image.get('Name', 'N/A')

                        # Verificar permisos de lanzamiento
                        attrs = ec2_client.describe_image_attribute(
                            ImageId=image_id,
                            Attribute='launchPermission'
                        )

                        launch_perms = attrs.get('LaunchPermissions', [])
                        for perm in launch_perms:
                            if perm.get('Group') == 'all':
                                findings.append(format_finding(
                                    check_name="AMI Pública",
                                    entity=f"{image_name} ({image_id})",
                                    issue="AMI propia compartida públicamente (cualquiera puede lanzar instancias)",
                                    severity="HIGH",
                                    compute_type="EC2",
                                    region=region,
                                    image_state=image.get('State', 'N/A')
                                ))
                                break

            except ClientError as e:
                print(f"[!] Error en región {region}: {e}")
            except Exception as e:
                print(f"[!] Error inesperado en región {region}: {e}")

    except Exception as e:
        print(f"[!] Error en check_public_amis: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_all_ec2():
    """
    Función combinada para ejecutar todos los checks de EC2.
    """
    all_findings = []

    findings = check_security_groups_open_to_internet()
    all_findings.extend(findings)

    findings = check_instances_without_ssm()
    all_findings.extend(findings)

    findings = check_unencrypted_instance_volumes()
    all_findings.extend(findings)

    findings = check_public_amis()
    all_findings.extend(findings)

    return all_findings