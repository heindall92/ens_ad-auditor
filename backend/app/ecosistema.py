"""
Adapter from GRC alerts to the "yrd-ecosistema" exchange envelope (version 1).

The envelope is the common JSON format of the author's GRC tools (CTEM-Nexus,
Rosetta, ENS Compliance Studio, KAIROS, ARGOS, Norvik). Type "hallazgos":
``datos`` holds the alerts exactly as the JSON report emits them, so CTEM-Nexus
turns them into identity findings with ATT&CK techniques and attack paths.

Same honesty rule as the Studio adapter: an empty list yields an empty envelope
and findings marked is_sample are skipped.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from app.models import GRCAlert
from app.report import counts_by_risk

FORMATO = "yrd-ecosistema"
VERSION = 1
HERRAMIENTA = "ens-ad-auditor"


def build_ecosistema(
    alerts: List[GRCAlert],
    domain: Optional[str] = None,
    app_version: str = "",
    now: Optional[datetime] = None,
) -> dict:
    """Return a "hallazgos" envelope. Empty alerts → empty ``datos``."""
    live = [a for a in alerts if not a.finding.is_sample]
    generado = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    return {
        "format": FORMATO,
        "version": VERSION,
        "origen": {
            "herramienta": HERRAMIENTA,
            "version": app_version,
            "generado": generado.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "tipo": "hallazgos",
        "proyecto": domain or "Active Directory",
        "datos": [a.model_dump(mode="json") for a in live],
        "resumen": {
            "domain": domain,
            "is_sample": False,
            "total_alerts": len(live),
            "counts_by_risk": counts_by_risk(live),
            "da_path": sum(1 for a in live if a.da_path),
        },
    }
