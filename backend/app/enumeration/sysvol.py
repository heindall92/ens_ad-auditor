"""
Read GptTmpl.inf from SYSVOL. Read-only SMB. Failure means the check did not run.
"""
from __future__ import annotations

import io
from typing import List, Optional, Tuple

from app.enumeration.target import AuditTarget


def read_gpt_files(target: AuditTarget, limit: int = 12) -> Tuple[List[str], Optional[str]]:
    try:
        from impacket.smbconnection import SMBConnection
    except Exception as exc:
        return [], f"impacket no disponible: {exc}"

    conn = None
    try:
        conn = SMBConnection(target.dc_host, target.dc_host, sess_port=445, timeout=6)
        lmhash, nthash = target.impacket_hashes
        if nthash:
            conn.login(target.sam, "", domain=target.domain, lmhash=lmhash, nthash=nthash)
        else:
            conn.login(target.sam, target.password or "", domain=target.domain)
        share = "SYSVOL"
        base = f"{target.domain}/Policies/"
        try:
            entries = conn.listPath(share, base + "*")
        except Exception as exc:
            return [], f"SYSVOL no legible: {exc}"
        texts: List[str] = []
        for item in entries:
            name = item.get_longname()
            if name in {".", ".."}:
                continue
            path = f"{base}{name}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf"
            buf = io.BytesIO()
            try:
                conn.getFile(share, path, buf.write)
            except Exception:
                continue
            raw = buf.getvalue()
            if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
                text = raw.decode("utf-16", errors="ignore")
            else:
                text = raw.decode("utf-8", errors="ignore")
            if text.strip():
                texts.append(text)
            if len(texts) >= limit:
                break
        if not texts:
            return [], "SYSVOL sin GptTmpl.inf legible"
        return texts, None
    except Exception as exc:
        return [], f"SYSVOL: {exc}"
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
