"""
AWS IAM Access Analyzer - Detecta recursos compartidos externamente
Fase 1: Identity Security - Módulo Avanzado
"""
import sys, os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from botocore.exceptions import ClientError
from core.aws_session import get_session
from core.reporter import format_finding

# Regiones AWS donde verificar Access Analyzer
AWS_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-central-1',
    'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1',
    'sa-east-1'
]


def check_access_analyzer_findings(regions=None):
    """
    Verifica hallazgos de IAM Access Analyzer en múltiples regiones.
    Detecta recursos compartidos con entidades externas a tu cuenta.

    Returns:
        list: Lista de hallazgos
    """
    if regions is None:
        regions = AWS_REGIONS

    findings = []

    print("[*] Verificando IAM Access Analyzer...")

    for region in regions:
        try:
            session = get_session(region_name=region)
            client = session.client('accessanalyzer', region_name=region)

            # Listar analizadores activos
            analyzers = client.list_analyzers()

            for analyzer in analyzers.get('analyzers', []):
                if analyzer['status'] != 'ACTIVE':
                    continue

                analyzer_name = analyzer['name']
                analyzer_arn = analyzer['arn']  # ✅ CORRECCIÓN: Obtener el ARN

                # Obtener hallazgos activos
                paginator = client.get_paginator('list_findings')
                for page in paginator.paginate(analyzerArn=analyzer_arn):  # ✅ CORRECCIÓN: Usar analyzerArn
                    for finding in page.get('findings', []):
                        if finding['status'] in ['ACTIVE', 'ARCHIVED']:
                            findings.append(format_finding(
                                check_name="Access Analyzer",
                                entity=finding.get('resource', 'N/A'),
                                issue=f"Recurso compartido externamente ({finding.get('resourceType', 'N/A')})",
                                severity="HIGH",
                                region=region,
                                analyzer=analyzer_name,
                                principal=finding.get('principal', {}).get('AWS', 'N/A'),
                                finding_id=finding.get('id', 'N/A')
                            ))

        except ClientError as e:
            if 'AccessAnalyzer' not in str(e):
                print(f"[!] Error en región {region}: {e}")
        except Exception as e:
            print(f"[!] Error inesperado en región {region}: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_access_analyzer_enabled(regions=None):
    """
    Verifica si IAM Access Analyzer está habilitado en las regiones.

    Returns:
        list: Lista de hallazgos (regiones sin analyzer activo)
    """
    if regions is None:
        regions = AWS_REGIONS[:5]  # Solo primeras 5 para no hacer lento

    findings = []

    print("[*] Verificando si Access Analyzer está habilitado...")

    for region in regions:
        try:
            session = get_session(region_name=region)
            client = session.client('accessanalyzer', region_name=region)

            analyzers = client.list_analyzers()
            active_analyzers = [a for a in analyzers.get('analyzers', []) if a['status'] == 'ACTIVE']

            if not active_analyzers:
                findings.append(format_finding(
                    check_name="Access Analyzer deshabilitado",
                    entity=region,
                    issue="No hay analizadores activos en esta región",
                    severity="MEDIUM",
                    region=region
                ))

        except ClientError as e:
            print(f"[!] Error verificando región {region}: {e}")
        except Exception as e:
            print(f"[!] Error inesperado en región {region}: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_access_analyzer_findings_multi_region():
    """
    Función combinada para ejecutar todos los checks de Access Analyzer.
    Esta es la función que se llama desde main.py
    """
    all_findings = []

    # Check 1: Hallazgos activos
    findings = check_access_analyzer_findings()
    all_findings.extend(findings)

    # Check 2: Analyzer habilitado (solo regiones principales)
    findings = check_access_analyzer_enabled()
    all_findings.extend(findings)

    return all_findings