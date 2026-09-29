"""Unit tests for live enumerators using in-memory LDAP rows."""
from app.enumeration import kerberos
from app.enumeration.adcs import _findings_from_output
from app.models import FindingType


class FakeSession:
    domain = "lab.test"

    def __init__(self, rows):
        self._rows = rows

    def search(self, ldap_filter, attributes, search_base=None, with_sd=False):
        return list(self._rows)


def test_kerberos_empty_directory_yields_nothing():
    assert kerberos.enumerate(FakeSession([])) == []


def test_kerberos_flags_spn_and_preauth():
    rows = [
        {
            "sAMAccountName": "svc_sql",
            "userAccountControl": 0x200,
            "servicePrincipalName": ["MSSQLSvc/db.lab.test:1433"],
            "msDS-SupportedEncryptionTypes": 0x4,
        },
        {
            "sAMAccountName": "jdoe",
            "userAccountControl": 0x200 | 0x400000,
            "servicePrincipalName": [],
            "msDS-SupportedEncryptionTypes": 0,
        },
        {
            "sAMAccountName": "WS01$",
            "userAccountControl": 0x1000,
            "servicePrincipalName": ["HOST/ws01.lab.test"],
            "msDS-SupportedEncryptionTypes": 0x4,
        },
    ]
    findings = kerberos.enumerate(FakeSession(rows))
    types = {f.finding_type for f in findings}
    assert FindingType.KERBEROASTING in types
    assert FindingType.ASREP_ROASTING in types
    assert all(f.is_sample is False for f in findings)
    assert all("lab.test" in f.target for f in findings)
    assert not any("corp.example.local" in (f.target + f.detail) for f in findings)


def test_adcs_parser_emits_every_esc_key_certipy_returns():
    data = {
        "Certificate Authorities": {
            "0": {
                "CA Name": "LAB-CA",
                "DNS Name": "ca.lab.test",
                "[!] Vulnerabilities": {
                    "ESC8": "Web Enrollment is enabled",
                    "ESC11": "RPC encryption not required",
                },
            }
        },
        "Certificate Templates": {
            "0": {
                "Template Name": "VulnWeb",
                "Certificate Authorities": ["LAB-CA"],
                "[!] Vulnerabilities": {"ESC1": "Enrollee supplies subject"},
            }
        },
    }
    findings = _findings_from_output(data)
    subtypes = {f.subtype for f in findings}
    assert subtypes == {"ESC1", "ESC8", "ESC11"}
    assert all(f.is_sample is False for f in findings)
