"""
Enumeration modules.

Each module exposes an `enumerate()` function that returns a list of Finding
objects. In this scaffold they return realistic SAMPLE/DEMO findings so the
full pipeline (enumeration -> ENS mapping -> report) is testable end to end.

The real implementations would use the deps listed in requirements.txt
(ldap3, impacket, certipy-ad) and MUST only ever be run against systems for
which explicit written authorization exists.
"""
from . import kerberos, delegation, adcs, smb


def run_all():
    """Run every enumeration module and return the combined finding list."""
    findings = []
    findings += smb.enumerate()
    findings += kerberos.enumerate()
    findings += delegation.enumerate()
    findings += adcs.enumerate()
    return findings


__all__ = ["kerberos", "delegation", "adcs", "smb", "run_all"]
