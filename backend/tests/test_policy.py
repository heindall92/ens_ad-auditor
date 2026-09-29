"""Read-only policy enumerator with in-memory LDAP rows."""
from datetime import datetime, timedelta, timezone

from app.enumeration import policy
from app.models import FindingType


class FakeSession:
    def __init__(self, *, domain="lab.test", base_dn="DC=lab,DC=test", tls=False, rows=None, by_dn=None, schema_dn=None):
        self.domain = domain
        self.base_dn = base_dn
        self.tls = tls
        self.schema_dn = schema_dn
        self.config_dn = None

        class T:
            dc_host = "dc.lab.test"
            ldap_port = 389

        self.target = T()
        self._rows = rows if rows is not None else {}
        self._by_dn = by_dn if by_dn is not None else {}

    def search(self, ldap_filter, attributes, search_base=None, with_sd=False):
        key = (ldap_filter, search_base)
        if key in self._rows:
            return list(self._rows[key])
        # fallback: any stored under filter only
        for (flt, base), val in self._rows.items():
            if flt == ldap_filter and (search_base is None or base == search_base):
                return list(val)
        return []

    def get_by_dn(self, dn, attributes):
        return self._by_dn.get(dn)


def test_policy_empty_directory():
    session = FakeSession(tls=True, rows={}, by_dn={"DC=lab,DC=test": {}})
    assert policy.enumerate(session) == []


def test_machine_quota_and_lockout():
    session = FakeSession(
        by_dn={
            "DC=lab,DC=test": {
                "minPwdLength": 7,
                "maxPwdAge": timedelta(days=0),
                "pwdHistoryLength": 0,
                "lockoutThreshold": 0,
                "ms-DS-MachineAccountQuota": 10,
            }
        },
        rows={},
    )
    types = {f.finding_type for f in policy.enumerate(session)}
    assert FindingType.WEAK_PASSWORD_POLICY in types
    assert FindingType.WEAK_LOCKOUT_POLICY in types
    assert FindingType.MACHINE_ACCOUNT_QUOTA in types
    assert all(f.is_sample is False for f in policy.enumerate(session))


def test_krbtgt_old():
    old = datetime.now(timezone.utc) - timedelta(days=400)
    session = FakeSession(
        by_dn={"DC=lab,DC=test": {}},
        rows={
            ("(&(objectClass=user)(sAMAccountName=krbtgt))", None): [
                {"sAMAccountName": "krbtgt", "pwdLastSet": old}
            ]
        },
    )
    findings = policy._krbtgt(session)
    assert len(findings) == 1
    assert findings[0].finding_type is FindingType.KRBTGT_PASSWORD_AGE


def test_unsigned_ldap_session():
    session = FakeSession(tls=False, by_dn={"DC=lab,DC=test": {}}, rows={})
    kinds = {f.finding_type for f in policy._ldap_channel(session)}
    assert FindingType.LDAP_SIGNING_NOT_REQUIRED in kinds
    assert FindingType.LDAP_CHANNEL_BINDING_WEAK in kinds


def test_password_complexity_only():
    session = FakeSession(
        tls=True,
        by_dn={
            "DC=lab,DC=test": {
                "minPwdLength": 14,
                "maxPwdAge": timedelta(days=90),
                "pwdHistoryLength": 8,
                "pwdProperties": 0,
                "lockoutThreshold": 5,
            }
        },
        rows={},
    )
    findings = policy.enumerate(session)
    types = {f.finding_type for f in findings}
    assert FindingType.WEAK_PASSWORD_POLICY in types
    assert FindingType.WEAK_LOCKOUT_POLICY not in types
    evidence = next(f.evidence or "" for f in findings if f.finding_type is FindingType.WEAK_PASSWORD_POLICY)
    assert "sin complejidad" in evidence


def test_password_complexity_set_is_clean():
    session = FakeSession(
        tls=True,
        by_dn={
            "DC=lab,DC=test": {
                "minPwdLength": 14,
                "maxPwdAge": timedelta(days=90),
                "pwdHistoryLength": 8,
                "pwdProperties": policy.DOMAIN_PASSWORD_COMPLEX,
                "lockoutThreshold": 5,
            }
        },
        rows={},
    )
    assert policy.enumerate(session) == []
