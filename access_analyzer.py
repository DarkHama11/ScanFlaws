import boto3
from botocore.exceptions import ClientError


def get_enabled_regions():
    try:
        ec2 = boto3.client('ec2', region_name='us-east-1')
        regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
        return regions
    except Exception as e:
        print(f"[!] No se pudieron obtener regiones: {e}")
        return []


def check_access_analyzer_findings_in_region(region, current_account):
    findings = []
    try:
        client = boto3.client('accessanalyzer', region_name=region)
        analyzers = client.list_analyzers().get('analyzers', [])
        if not analyzers:
            return findings

        for analyzer in analyzers:
            paginator = client.get_paginator('list_findings')
            try:
                for page in paginator.paginate(analyzerArn=analyzer['arn']):
                    for f in page.get('findings', []):
                        if f.get('status') != 'ACTIVE':
                            continue

                        principal = f.get('principal', {})
                        is_external = False

                        if principal == "*":
                            is_external = True
                        elif isinstance(principal, dict):
                            aws_principal = principal.get("AWS")
                            if aws_principal:
                                if isinstance(aws_principal, str):
                                    aws_principal = [aws_principal]
                                for arn in aws_principal:
                                    if arn != "*" and not arn.startswith(f"arn:aws:iam::{current_account}:"):
                                        is_external = True
                                        break

                        if is_external:
                            findings.append({
                                "region": region,
                                "resource": f.get('resource', 'Unknown'),
                                "action": ", ".join(f.get('action', []))[:60],
                                "principal": str(principal)[:70]
                            })
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code not in ('ValidationException', 'ResourceNotFoundException'):
                    print(f"[!] Error listando hallazgos en {region}: {e}")
                continue

    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            print(f"[!] Acceso denegado en región {region} (faltan permisos)")
    except Exception as e:
        print(f"[!] Error inesperado en región {region}: {e}")

    return findings


def check_access_analyzer_findings_multi_region():
    try:
        sts = boto3.client('sts')
        current_account = sts.get_caller_identity()['Account']
    except Exception as e:
        print(f"[!] No se pudo obtener la cuenta actual: {e}")
        return []

    regions = get_enabled_regions()
    all_findings = []
    print(f"[+] Escaneando IAM Access Analyzer en {len(regions)} regiones...")
    for region in regions:
        region_findings = check_access_analyzer_findings_in_region(region, current_account)
        all_findings.extend(region_findings)
    return all_findings