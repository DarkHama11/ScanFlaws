"""
Generador de reportes - ScanFlaws Core
Soporta: Tabla consola, JSON, CSV
"""
from tabulate import tabulate
import json
import csv
from datetime import datetime


def print_table(findings, headers=["Check", "Entidad", "Detalle", "Severidad"]):
    """Imprime hallazgos en formato de tabla"""
    if not findings:
        print("[+] ✅ No se encontraron hallazgos.")
        return

    print(tabulate(findings, headers=headers, tablefmt="grid"))


def export_to_json(findings, filename=None):
    """Exporta hallazgos a JSON"""
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scanflaws_report_{timestamp}.json"

    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)

    print(f"[+] Reporte JSON exportado: {filename}")
    return filename


def export_to_csv(findings, filename=None):
    """Exporta hallazgos a CSV"""
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scanflaws_report_{timestamp}.csv"

    if not findings:
        print("[!] No hay hallazgos para exportar.")
        return None

    # ✅ CORRECCIÓN: Recopilar TODOS los fieldnames posibles de todos los hallazgos
    all_fieldnames = set()
    for finding in findings:
        if isinstance(finding, dict):
            all_fieldnames.update(finding.keys())

    # Ordenar fieldnames (campos principales primero)
    priority_fields = ['check', 'entity', 'issue', 'severity', 'timestamp']
    ordered_fieldnames = [f for f in priority_fields if f in all_fieldnames]
    ordered_fieldnames.extend(sorted(all_fieldnames - set(priority_fields)))

    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=ordered_fieldnames, extrasaction='ignore')
        writer.writeheader()
        for row in findings:
            if isinstance(row, dict):
                # ✅ CORRECCIÓN: Filtrar solo los campos que están en fieldnames
                filtered_row = {k: v for k, v in row.items() if k in ordered_fieldnames}
                writer.writerow(filtered_row)
            else:
                writer.writerow(dict(zip(ordered_fieldnames, row)))

    print(f"[+] Reporte CSV exportado: {filename}")
    return filename


def format_finding(check_name, entity, issue, severity="MEDIUM", **kwargs):
    """
    Crea un diccionario de hallazgo estandarizado.

    Args:
        check_name: Nombre del check
        entity: Usuario, rol, recurso, etc.
        issue: Descripción del problema
        severity: CRITICAL, HIGH, MEDIUM, LOW
        **kwargs: Campos adicionales (extra_data, recommendation, etc.)

    Returns:
        dict: Hallazgo estandarizado
    """
    finding = {
        "check": check_name,
        "entity": entity,
        "issue": issue,
        "severity": severity,
        "timestamp": datetime.now().isoformat()
    }

    # Agregar campos adicionales si existen
    finding.update(kwargs)

    return finding