"""Coverage, ACL classification, cleartext presence and GPO text. No network."""
from app.enumeration.acl import GENERIC_ALL, WRITE_DACL, ADS_RIGHT_DS_CONTROL_ACCESS, GUID_GET_CHANGES, GUID_GET_CHANGES_ALL, classify_ace, enumerate as enumerate_acl
from app.enumeration.gpo_text import parse_gpt, saw_event_audit
from app.enumeration.secrets import enumerate as enumerate_secrets
from app.models import FindingType


class EmptySearch:
    domain = "lab.test"
    base_dn = "DC=lab,DC=test"

    def search(self, ldap_filter, attributes, search_base=None, with_sd=False):
        return []


class RowSearch:
    domain = "lab.test"
    base_dn = "DC=lab,DC=test"

    def __init__(self, rows):
        self._rows = rows

    def search(self, ldap_filter, attributes, search_base=None, with_sd=False):
        return list(self._rows)


def test_classify_ace_ignores_builtin_admin_and_needs_both_replication_rights():
    admin = "S-1-5-21-1-2-3-512"
    user = "S-1-5-21-9-9-9-1105"
    assert classify_ace(admin, GENERIC_ALL, None) is None
    assert classify_ace(user, GENERIC_ALL, None) == "generic_all"
    assert classify_ace(user, WRITE_DACL, None) == "write_dacl"
    assert classify_ace(user, ADS_RIGHT_DS_CONTROL_ACCESS, GUID_GET_CHANGES) == "get_changes"
    assert classify_ace(user, ADS_RIGHT_DS_CONTROL_ACCESS, GUID_GET_CHANGES_ALL) == "get_changes_all"
    assert classify_ace(user, 0x1, None) is None


def test_acl_without_descriptor_yields_nothing():
    session = RowSearch([{"nTSecurityDescriptor": None}])
    assert enumerate_acl(session) == []


def test_secrets_empty_search_yields_nothing():
    assert enumerate_secrets(EmptySearch()) == []


def test_secrets_reports_presence_and_skips_computers():
    rows = [
        {"sAMAccountName": "svc_backup", "distinguishedName": "CN=svc_backup,DC=lab,DC=test"},
        {"sAMAccountName": "WS01$", "distinguishedName": "CN=WS01,DC=lab,DC=test"},
    ]
    findings = enumerate_secrets(RowSearch(rows))
    assert findings
    assert all(f.finding_type is FindingType.CLEARTEXT_SECRET_ATTR for f in findings)
    assert all(f.target.endswith("@lab.test") for f in findings)
    assert all("WS01$" not in f.target for f in findings)
    blob = " ".join((f.evidence or "") + f.detail for f in findings)
    assert "present=true" in blob
    assert "secret-value" not in blob.lower()


def test_gpo_flags_weak_signature_and_explicit_zero_audit_only():
    weak = """
[Registry Values]
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RequireSecuritySignature=4,0
MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity=4,1
[Event Audit]
AuditAccountLogon = 0
AuditLogonEvents = 3
"""
    findings = parse_gpt(weak, source="GptTmpl.inf#1")
    types = {f.finding_type for f in findings}
    assert FindingType.GPO_WEAK_SETTING in types
    assert FindingType.AUDIT_POLICY_GAP in types
    audit = next(f for f in findings if f.finding_type is FindingType.AUDIT_POLICY_GAP)
    assert "AuditAccountLogon" in (audit.evidence or "")
    assert "AuditLogonEvents" not in (audit.evidence or "")

    clean = """
[Registry Values]
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RequireSecuritySignature=4,1
MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity=4,2
"""
    assert parse_gpt(clean) == []
    assert saw_event_audit([clean]) is False
    assert saw_event_audit([weak]) is True
    assert parse_gpt("[Unicode]\nUnicode=yes") == []
