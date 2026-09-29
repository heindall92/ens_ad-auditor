"""Roadmap coverage. A row is comprobado only after that check actually ran."""
from __future__ import annotations

from typing import Dict, List

from app.models import CoverageCheck

# id, area (ES). Order matches the audit surface.
CATALOG: List[tuple[str, str]] = [
    ("kerberos", "Kerberos"),
    ("delegacion", "Delegación"),
    ("adcs", "AD CS"),
    ("smb", "Firma SMB"),
    ("politica", "Política de contraseñas"),
    ("krbtgt", "krbtgt"),
    ("privilegiadas", "Cuentas privilegiadas"),
    ("ldap", "LDAP"),
    ("confianza", "Confianza, cuota y LAPS"),
    ("acl", "ACL y rutas de control"),
    ("gpo", "GPO"),
    ("secretos", "Atributos con secreto"),
    ("monitorizacion", "Monitorización"),
    ("tiering", "Tiering"),
    ("entra", "Híbrido Entra ID"),
]

UNAVAILABLE = {
    "tiering": (
        "No comprobado. Hace falta el equipo donde inició sesión la cuenta "
        "privilegiada. No se afirma un inicio de sesión en un puesto."
    ),
    "entra": (
        "No comprobado. No hay conector de tenant. No se inventa un directorio "
        "de Entra ID."
    ),
}


def empty_coverage() -> List[CoverageCheck]:
    return [
        CoverageCheck(
            id=check_id,
            area=area,
            status="no_comprobado",
            detail="Sin enumeración autorizada. Esta fila no se simula.",
        )
        for check_id, area in CATALOG
    ]


def index_coverage(checks: List[CoverageCheck]) -> Dict[str, CoverageCheck]:
    return {item.id: item for item in checks}


def mark(checks: List[CoverageCheck], check_id: str, status: str, detail: str) -> None:
    found = index_coverage(checks)
    item = found[check_id]
    item.status = status
    item.detail = detail
