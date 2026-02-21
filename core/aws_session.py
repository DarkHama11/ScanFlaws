"""
Gestor centralizado de sesiones AWS - ScanFlaws Core
"""
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError


def get_session(profile_name=None, region_name=None):
    """
    Crea una sesión boto3 reutilizable.

    Args:
        profile_name: Nombre del perfil en ~/.aws/credentials (opcional)
        region_name: Región AWS (opcional, usa la configurada por defecto)

    Returns:
        boto3.Session object
    """
    try:
        return boto3.Session(
            profile_name=profile_name,
            region_name=region_name
        )
    except (NoCredentialsError, PartialCredentialsError) as e:
        print(f"[!] Error de credenciales AWS: {e}")
        print("[*] Ejecuta 'aws configure' o configura tus variables de entorno")
        raise


def get_iam_client(session=None, region_name=None):
    """Obtiene cliente IAM"""
    if session is None:
        session = get_session(region_name=region_name)
    return session.client('iam')


def get_sts_client(session=None, region_name=None):
    """Obtiene cliente STS para identificar cuenta/región"""
    if session is None:
        session = get_session(region_name=region_name)
    return session.client('sts')


def get_s3_client(session=None, region_name=None):
    """Obtiene cliente S3"""
    if session is None:
        session = get_session(region_name=region_name)
    return session.client('s3')


def get_ec2_client(session=None, region_name=None):
    """Obtiene cliente EC2"""
    if session is None:
        session = get_session(region_name=region_name)
    return session.client('ec2')


def get_account_id(session=None):
    """Obtiene el ID de la cuenta AWS actual"""
    if session is None:
        session = get_session()
    sts = session.client('sts')
    return sts.get_caller_identity()['Account']


def get_current_region(session=None):
    """Obtiene la región actual de la sesión"""
    if session is None:
        session = get_session()
    return session.region_name