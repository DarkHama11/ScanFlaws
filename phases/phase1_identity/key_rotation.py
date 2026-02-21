"""
Detección avanzada de rotación de Access Keys
Fase 1: Identity Security - Módulo Avanzado
"""
import sys, os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError
import csv
from io import StringIO
import time

from core.aws_session import get_iam_client
from core.reporter import format_finding


def check_keys_without_rotation(max_days=90):
    """
    Detecta usuarios con access keys activas que no han sido rotadas
    en más de `max_days` días.

    Returns:
        list: Lista de hallazgos
    """
    client = get_iam_client()
    findings = []

    try:
        print("[*] Verificando claves sin rotación adecuada...")

        # Generar credential report
        client.generate_credential_report()

        # Esperar a que esté disponible
        for _ in range(10):
            try:
                report = client.get_credential_report()
                break
            except ClientError as e:
                if 'ReportNotPresent' in str(e) or 'ReportExpired' in str(e):
                    time.sleep(1)
                    continue
                raise
        else:
            print("[!] No se pudo obtener el credential report")
            return findings

        # Parsear CSV
        rows = list(csv.DictReader(StringIO(report['Content'].decode())))
        now = datetime.now(timezone.utc)

        for row in rows:
            if row['user'] == '<root_account>':
                continue

            username = row['user']

            for key_num in ['1', '2']:
                if row[f'access_key_{key_num}_active'] == 'true':
                    last_rotated = row[f'access_key_{key_num}_last_rotated']
                    last_used = row[f'access_key_{key_num}_last_used_date']

                    # Caso 1: Clave nunca usada pero activa (riesgo alto)
                    if last_used == 'N/A':
                        findings.append(format_finding(
                            check_name="Clave nunca usada",
                            entity=username,
                            issue="Access Key activa pero NUNCA usada (posible credencial olvidada)",
                            severity="HIGH",
                            extra_data={
                                "key_id": row[f'access_key_{key_num}_access_key_id'],
                                "recommendation": "Desactivar o eliminar si no es necesaria"
                            }
                        ))

                    # Caso 2: Clave sin rotar en > max_days
                    elif last_rotated not in ['N/A', 'no_information']:
                        try:
                            rotated_date = datetime.fromisoformat(last_rotated.replace('Z', '+00:00'))
                            days_since_rotation = (now - rotated_date).days

                            if days_since_rotation > max_days:
                                findings.append(format_finding(
                                    check_name="Clave sin rotación",
                                    entity=username,
                                    issue=f"Access Key sin rotar por {days_since_rotation} días (>{max_days})",
                                    severity="MEDIUM",
                                    extra_data={
                                        "key_id": row[f'access_key_{key_num}_access_key_id'],
                                        "days_since_rotation": days_since_rotation,
                                        "recommendation": "Rotar credencial inmediatamente"
                                    }
                                ))
                        except Exception:
                            pass

    except Exception as e:
        print(f"[!] Error en check de rotación de claves: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_keys_never_used():
    """
    Detecta access keys activas que nunca han sido utilizadas.

    Returns:
        list: Lista de hallazgos
    """
    client = get_iam_client()
    findings = []

    try:
        print("[*] Verificando claves nunca utilizadas...")

        client.generate_credential_report()

        for _ in range(10):
            try:
                report = client.get_credential_report()
                break
            except ClientError as e:
                if 'ReportNotPresent' in str(e) or 'ReportExpired' in str(e):
                    time.sleep(1)
                    continue
                raise
        else:
            return findings

        rows = list(csv.DictReader(StringIO(report['Content'].decode())))

        for row in rows:
            if row['user'] == '<root_account>':
                continue

            username = row['user']

            for key_num in ['1', '2']:
                if row[f'access_key_{key_num}_active'] == 'true':
                    if row[f'access_key_{key_num}_last_used_date'] == 'N/A':
                        findings.append(format_finding(
                            check_name="Clave nunca usada",
                            entity=username,
                            issue="Access Key activa pero nunca utilizada",
                            severity="HIGH",
                            extra_data={
                                "key_id": row[f'access_key_{key_num}_access_key_id'],
                                "recommendation": "Desactivar o eliminar si no es necesaria"
                            }
                        ))

    except Exception as e:
        print(f"[!] Error en check de claves nunca usadas: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_root_access_keys():
    """
    Detecta si la cuenta root tiene access keys activas (CRÍTICO).

    Returns:
        list: Lista de hallazgos
    """
    client = get_iam_client()
    findings = []

    try:
        print("[*] Verificando access keys de root...")

        client.generate_credential_report()

        for _ in range(10):
            try:
                report = client.get_credential_report()
                break
            except ClientError as e:
                if 'ReportNotPresent' in str(e) or 'ReportExpired' in str(e):
                    time.sleep(1)
                    continue
                raise
        else:
            return findings

        rows = list(csv.DictReader(StringIO(report['Content'].decode())))

        for row in rows:
            if row['user'] == '<root_account>':
                if row['access_key_1_active'] == 'true' or row['access_key_2_active'] == 'true':
                    findings.append(format_finding(
                        check_name="Root con access keys",
                        entity="<root_account>",
                        issue="Cuenta root tiene access keys activas (CRÍTICO)",
                        severity="CRITICAL",
                        extra_data={
                            "recommendation": "Eliminar access keys de root inmediatamente y usar IAM users"
                        }
                    ))

    except Exception as e:
        print(f"[!] Error en check de root access keys: {e}")

    print(f"[+] Check completado: {len(findings)} hallazgos")
    return findings


def check_all_key_rotation():
    """
    Función combinada para ejecutar todos los checks de rotación de claves.
    """
    all_findings = []

    findings = check_keys_without_rotation()
    all_findings.extend(findings)

    findings = check_keys_never_used()
    all_findings.extend(findings)

    findings = check_root_access_keys()
    all_findings.extend(findings)

    return all_findings