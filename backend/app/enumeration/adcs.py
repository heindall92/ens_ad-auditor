"""
AD CS enumeration (ESC1-ESC8).

SCAFFOLD: returns SAMPLE findings. A real implementation would use certipy-ad
('certipy find') to enumerate CAs and certificate templates and evaluate the
ESC1-ESC8 conditions.
"""
from __future__ import annotations

from typing import List

from app.models import Finding, FindingType

MODULE = "enumeration.adcs"


def enumerate() -> List[Finding]:
    """Return SAMPLE AD CS-related findings (demo data)."""
    return [
        Finding(
            finding_type=FindingType.ADCS_ESC,
            title="[DEMO] Plantilla de certificado vulnerable (ESC1)",
            target="Template: CorpWebServer @ corp-CA",
            detail=(
                "La plantilla 'CorpWebServer' permite ENROLLEE_SUPPLIES_SUBJECT "
                "con EKU 'Client Authentication' y derechos de inscripción para "
                "'Domain Users' (ESC1): cualquier usuario puede emitir un "
                "certificado suplantando a Domain Admin."
            ),
            evidence="[SAMPLE] certipy find -> [!] ESC1 Vulnerable (demo).",
            source_module=MODULE,
            subtype="ESC1",
            is_sample=True,
        ),
        Finding(
            finding_type=FindingType.ADCS_ESC,
            title="[DEMO] CA con EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6)",
            target="CA: corp-CA",
            detail=(
                "La CA tiene habilitado EDITF_ATTRIBUTESUBJECTALTNAME2, "
                "permitiendo especificar un SAN arbitrario en cualquier "
                "solicitud (ESC6) y por tanto suplantar a cualquier principal."
            ),
            evidence="[SAMPLE] certipy find -> [!] ESC6 Enabled (demo).",
            source_module=MODULE,
            subtype="ESC6",
            is_sample=True,
        ),
        Finding(
            finding_type=FindingType.ADCS_ESC,
            title="[DEMO] Inscripción web AD CS vulnerable a NTLM relay (ESC8)",
            target="http://ca01.corp.example.local/certsrv",
            detail=(
                "El endpoint de Web Enrollment acepta autenticación NTLM sobre "
                "HTTP sin EPA, permitiendo retransmitir la autenticación de un "
                "controlador de dominio y obtener un certificado a su nombre (ESC8)."
            ),
            evidence="[SAMPLE] certipy find -> [!] ESC8 Web Enrollment HTTP (demo).",
            source_module=MODULE,
            subtype="ESC8",
            is_sample=True,
        ),
    ]
