"""
Generador de reportes - ScanFlaws Core
Soporta: Tabla consola, JSON, CSV con Security Hardening
"""
from tabulate import tabulate
import json
import csv
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

# 🔐 Security Hardening Imports
from core.security import sanitize_for_log, is_safe_input
from core.file_handler import save_json_safe, generate_safe_filename, sanitize_path, BASE_OUTPUT_DIR
from core.logger import get_logger
from core.scan_result import ScanResult, ScanFinding, Severity

logger = get_logger(__name__)


def print_table(
        findings: List[Union[Dict, ScanFinding]],
        headers: List[str] = None,
        max_rows: Optional[int] = None
):
    """
    Imprime hallazgos en formato de tabla con sanitización.

    Args:
        findings: Lista de hallazgos (dict o ScanFinding)
        headers: Encabezados de la tabla
        max_rows: Límite de filas a mostrar (None = todas)
    """
    if headers is None:
        headers = ["Check", "Entidad", "Detalle", "Severidad"]

    if not findings:
        print("[+] ✅ No se encontraron hallazgos.")
        return

    # Preparar datos para tabla
    table_data = []
    for i, finding in enumerate(findings):
        if max_rows and i >= max_rows:
            break

        if isinstance(finding, ScanFinding):
            row = [
                finding.check_name,
                finding.entity,
                finding.issue,
                finding.severity.value
            ]
        elif isinstance(finding, dict):
            row = [
                finding.get('check', 'N/A'),
                finding.get('entity', 'N/A'),
                finding.get('issue', 'N/A'),
                finding.get('severity', 'N/A')
            ]
        else:
            row = list(finding) if isinstance(finding, (list, tuple)) else [str(finding)]

        # 🔐 Sanitizar datos sensibles antes de mostrar
        table_data.append([sanitize_for_log(str(cell)) for cell in row])

    # Mostrar tabla
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

    if max_rows and len(findings) > max_rows:
        print(f"\n[ℹ️] Mostrando {max_rows} de {len(findings)} hallazgos. Ver reportes para detalles completos.")


def export_to_json(
        findings: List[Union[Dict, ScanFinding]],
        filename: Optional[str] = None,
        directory: Optional[Union[str, Path]] = None,
        include_metadata: bool = True
) -> Optional[str]:
    """
    Exporta hallazgos a JSON de forma segura.

    Args:
        findings: Lista de hallazgos a exportar
        filename: Nombre opcional del archivo (se genera uno seguro si es None)
        directory: Directorio opcional (default: BASE_OUTPUT_DIR)
        include_metadata: Si True, incluye timestamp y metadatos

    Returns:
        str: Ruta del archivo exportado o None si falla
    """
    try:
        # 🔐 Sanitizar datos sensibles antes de exportar
        sanitized_findings = []
        for f in findings:
            if isinstance(f, ScanFinding):
                sanitized_findings.append(f.to_dict())
            elif isinstance(f, dict):
                sanitized_findings.append(sanitize_for_log(f))
            else:
                sanitized_findings.append(sanitize_for_log(str(f)))

        # Preparar payload
        payload = {'findings': sanitized_findings}

        if include_metadata:
            payload.update({
                'exported_at': datetime.now().isoformat(),
                'total_findings': len(findings),
                'severity_summary': _calculate_severity_summary(findings),
                'scanflaws_version': '3.0-hardened'
            })

        # 🔐 Generar nombre seguro y guardar
        if filename is None:
            filename = generate_safe_filename('scanflaws_report', 'json')
        elif not filename.endswith('.json'):
            filename = f"{filename}.json"

        # Validar que el filename es seguro
        if not is_safe_input(filename.replace('.json', ''), allow_special=['_', '-']):
            logger.warning(f"Nombre de archivo inseguro rechazado: {filename}")
            filename = generate_safe_filename('scanflaws_report', 'json')

        # Determinar directorio
        if directory is None:
            directory = BASE_OUTPUT_DIR
        elif isinstance(directory, str):
            directory = Path(directory)

        # 🔐 Guardar usando file_handler seguro
        filepath = save_json_safe(data=payload, filename=filename, directory=directory)

        logger.info(f"Reporte JSON exportado: {filepath.name} ({len(findings)} hallazgos)")
        return str(filepath)

    except Exception as e:
        logger.error(f"Error exportando JSON: {e}")
        return None


def export_to_csv(
        findings: List[Union[Dict, ScanFinding]],
        filename: Optional[str] = None,
        directory: Optional[Union[str, Path]] = None,
        fieldnames: Optional[List[str]] = None
) -> Optional[str]:
    """
    Exporta hallazgos a CSV de forma segura.

    Args:
        findings: Lista de hallazgos a exportar
        filename: Nombre opcional del archivo
        directory: Directorio opcional
        fieldnames: Columnas a exportar (auto-detectadas si None)

    Returns:
        str: Ruta del archivo exportado o None si falla
    """
    if not findings:
        logger.info("No hay hallazgos para exportar a CSV")
        return None

    try:
        # 🔐 Sanitizar y preparar datos
        sanitized_findings = []
        all_fieldnames = set()

        for f in findings:
            if isinstance(f, ScanFinding):
                row = f.to_dict()
            elif isinstance(f, dict):
                row = sanitize_for_log(f)
            else:
                row = {'data': sanitize_for_log(str(f))}

            sanitized_findings.append(row)
            all_fieldnames.update(row.keys())

        # Determinar fieldnames
        if fieldnames is None:
            priority_fields = ['check', 'entity', 'issue', 'severity', 'timestamp']
            ordered_fieldnames = [f for f in priority_fields if f in all_fieldnames]
            ordered_fieldnames.extend(sorted(all_fieldnames - set(priority_fields)))
        else:
            ordered_fieldnames = fieldnames

        # 🔐 Generar nombre seguro
        if filename is None:
            filename = generate_safe_filename('scanflaws_report', 'csv')
        elif not filename.endswith('.csv'):
            filename = f"{filename}.csv"

        if not is_safe_input(filename.replace('.csv', ''), allow_special=['_', '-']):
            logger.warning(f"Nombre de archivo inseguro rechazado: {filename}")
            filename = generate_safe_filename('scanflaws_report', 'csv')

        # Determinar directorio
        if directory is None:
            directory = BASE_OUTPUT_DIR
        elif isinstance(directory, str):
            directory = Path(directory)

        directory.mkdir(parents=True, exist_ok=True)
        filepath = sanitize_path(directory / filename, base_dir=directory)

        # Escribir CSV con encoding UTF-8
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(
                f,
                fieldnames=ordered_fieldnames,
                extrasaction='ignore',
                quoting=csv.QUOTE_MINIMAL
            )
            writer.writeheader()
            for row in sanitized_findings:
                # 🔐 Filtrar solo campos válidos y sanitizar valores
                filtered_row = {
                    k: sanitize_for_log(str(v)) if v is not None else ''
                    for k, v in row.items()
                    if k in ordered_fieldnames
                }
                writer.writerow(filtered_row)

        logger.info(f"Reporte CSV exportado: {filepath.name} ({len(findings)} hallazgos)")
        return str(filepath)

    except Exception as e:
        logger.error(f"Error exportando CSV: {e}")
        return None


def export_to_markdown(
        findings: List[Union[Dict, ScanFinding]],
        filename: Optional[str] = None,
        directory: Optional[Union[str, Path]] = None,
        title: str = "ScanFlaws Security Report"
) -> Optional[str]:
    """
    Exporta hallazgos a Markdown para documentación.

    Args:
        findings: Lista de hallazgos
        filename: Nombre opcional
        directory: Directorio opcional
        title: Título del reporte

    Returns:
        str: Ruta del archivo o None
    """
    try:
        # 🔐 Generar nombre seguro
        if filename is None:
            filename = generate_safe_filename('scanflaws_report', 'md')
        elif not filename.endswith('.md'):
            filename = f"{filename}.md"

        if directory is None:
            directory = BASE_OUTPUT_DIR
        elif isinstance(directory, str):
            directory = Path(directory)

        directory.mkdir(parents=True, exist_ok=True)
        filepath = sanitize_path(directory / filename, base_dir=directory)

        # Preparar contenido Markdown
        lines = [
            f"# {title}",
            "",
            f"**Generado:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Total hallazgos:** {len(findings)}",
            "",
        ]

        # Resumen por severidad
        summary = _calculate_severity_summary(findings)
        lines.append("## 📊 Resumen por Severidad")
        lines.append("")
        lines.append("| Severidad | Cantidad |")
        lines.append("|-----------|----------|")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = summary.get(severity, 0)
            if count > 0:
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': '🔵'}.get(severity, '⚪')
                lines.append(f"| {emoji} {severity} | {count} |")
        lines.append("")

        # Detalles de hallazgos
        lines.append("## 📋 Detalles de Hallazgos")
        lines.append("")

        for i, finding in enumerate(findings, 1):
            if isinstance(finding, ScanFinding):
                f_dict = finding.to_dict()
            else:
                f_dict = sanitize_for_log(finding) if isinstance(finding, dict) else {'issue': str(finding)}

            severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': '🔵'}.get(
                f_dict.get('severity', 'INFO'), '⚪'
            )

            lines.append(f"### {i}. {sanitize_for_log(f_dict.get('check', 'N/A'))}")
            lines.append(f"- **Entidad:** `{sanitize_for_log(f_dict.get('entity', 'N/A'))}`")
            lines.append(f"- **Severidad:** {severity_emoji} {f_dict.get('severity', 'N/A')}")
            lines.append(f"- **Problema:** {sanitize_for_log(f_dict.get('issue', 'N/A'))}")

            if f_dict.get('recommendation'):
                lines.append(f"- **Recomendación:** {sanitize_for_log(f_dict['recommendation'])}")
            if f_dict.get('cve_id'):
                lines.append(f"- **CVE:** [{f_dict['cve_id']}](https://nvd.nist.gov/vuln/detail/{f_dict['cve_id']})")
            lines.append("")

        # Footer
        lines.append("---")
        lines.append(f"*Reporte generado por ScanFlaws v3.0-hardened*")

        # Guardar archivo
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

        logger.info(f"Reporte Markdown exportado: {filepath.name}")
        return str(filepath)

    except Exception as e:
        logger.error(f"Error exportando Markdown: {e}")
        return None


def export_scan_result(
        result: ScanResult,
        formats: List[str] = None,
        directory: Optional[Union[str, Path]] = None
) -> Dict[str, Optional[str]]:
    """
    Exporta un ScanResult completo a múltiples formatos.

    Args:
        result: Objeto ScanResult a exportar
        formats: Lista de formatos ['json', 'csv', 'md'] (default: todos)
        directory: Directorio de salida

    Returns:
        Dict con rutas de archivos exportados
    """
    if formats is None:
        formats = ['json', 'csv', 'md']

    exported = {}
    findings = result.findings

    if 'json' in formats:
        exported['json'] = export_to_json(
            findings,
            filename=f"scanflaws_{result.phase}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            directory=directory
        )

    if 'csv' in formats:
        exported['csv'] = export_to_csv(
            findings,
            filename=f"scanflaws_{result.phase}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            directory=directory
        )

    if 'md' in formats:
        exported['md'] = export_to_markdown(
            findings,
            filename=f"scanflaws_{result.phase}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            directory=directory,
            title=f"ScanFlaws Report - {result.phase}"
        )

    logger.info(f"Exportados {len([v for v in exported.values() if v])} formatos para fase {result.phase}")
    return exported


def _calculate_severity_summary(findings: List[Union[Dict, ScanFinding]]) -> Dict[str, int]:
    """Calcula resumen de hallazgos por severidad."""
    summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

    for f in findings:
        severity = None
        if isinstance(f, ScanFinding):
            severity = f.severity.value
        elif isinstance(f, dict):
            severity = f.get('severity', '').upper()

        if severity in summary:
            summary[severity] += 1

    return summary


def format_finding(
        check_name: str,
        entity: str,
        issue: str,
        severity: str = "MEDIUM",
        **kwargs
) -> Dict[str, Any]:
    """
    Crea un diccionario de hallazgo estandarizado (backward compatible).

    Args:
        check_name: Nombre del check
        entity: Usuario, rol, recurso, etc.
        issue: Descripción del problema
        severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
        **kwargs: Campos adicionales

    Returns:
        dict: Hallazgo estandarizado y sanitizado
    """
    # Validar severidad
    valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    if severity.upper() not in valid_severities:
        logger.warning(f"Severidad no válida '{severity}', usando MEDIUM")
        severity = 'MEDIUM'

    finding = {
        "check": sanitize_for_log(str(check_name)),
        "entity": sanitize_for_log(str(entity)),
        "issue": sanitize_for_log(str(issue)),
        "severity": severity.upper(),
        "timestamp": datetime.now().isoformat()
    }

    # Agregar campos adicionales sanitizados
    for key, value in kwargs.items():
        finding[key] = sanitize_for_log(value) if isinstance(value, str) else value

    return finding


def create_scan_finding(
        check_name: str,
        entity: str,
        issue: str,
        severity: Union[str, Severity],
        recommendation: Optional[str] = None,
        cve_id: Optional[str] = None,
        **extra_data
) -> ScanFinding:
    """
    Crea un objeto ScanFinding tipo dataclass (nuevo estándar).

    Args:
        check_name: Nombre del check
        entity: Entidad afectada
        issue: Descripción del problema
        severity: Severidad (string o enum Severity)
        recommendation: Recomendación de remediación
        cve_id: ID de CVE si aplica
        **extra_data: Datos adicionales

    Returns:
        ScanFinding: Objeto estructurado con scoring de riesgo
    """
    # Convertir severity a enum si es string
    if isinstance(severity, str):
        severity = Severity[severity.upper()]

    return ScanFinding(
        check_name=check_name,
        entity=entity,
        issue=issue,
        severity=severity,
        recommendation=recommendation,
        cve_id=cve_id,
        extra_data=extra_data
    )