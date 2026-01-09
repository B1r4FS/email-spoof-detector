from __future__ import annotations

import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import Dict, Optional, Tuple


DOMAIN = ""  # troque pelo seu domínio 


def _domain_of(addr: str) -> str:
    addr = (addr or "").strip().lower()
    if "@" in addr:
        return addr.split("@", 1)[1]
    return ""


def _parse_auth_results(header_value: str) -> Dict[str, str]:
    """
    Parse simples de Authentication-Results.
    Ex.: "mx.google.com; spf=pass ...; dkim=fail ...; dmarc=fail ..."
    """
    results = {}
    if not header_value:
        return results

    # pega tokens tipo spf=pass, dkim=fail, dmarc=pass
    for key in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{key}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
                      header_value, flags=re.IGNORECASE)
        if m:
            results[key] = m.group(1).lower()

    return results


def _read_eml(path: Path) -> "email.message.EmailMessage":
    raw = path.read_bytes()
    return BytesParser(policy=policy.default).parsebytes(raw)


def analyze_message(msg, internal_domain: str) -> Tuple[bool, str]:
    from_name, from_addr = parseaddr(msg.get("From", ""))
    rp_name, return_path = parseaddr(msg.get("Return-Path", ""))  # às vezes vem como "<x@y>"
    auth_results_raw = msg.get("Authentication-Results", "") or ""

    from_dom = _domain_of(from_addr)
    rp_dom = _domain_of(return_path)

    auth = _parse_auth_results(auth_results_raw)
    spf = auth.get("spf", "missing")
    dkim = auth.get("dkim", "missing")
    dmarc = auth.get("dmarc", "missing")

    # Heurísticas defensivas
    is_internal_from = (from_dom == internal_domain.lower())
    auth_failed = any(v in ("fail", "softfail", "permerror", "temperror") for v in (spf, dkim, dmarc))
    auth_missing = any(v == "missing" for v in (spf, dkim, dmarc))
    return_path_mismatch = (rp_dom != "" and from_dom != "" and rp_dom != from_dom)

    suspicious = False
    reasons = []

    if is_internal_from:
        # se alguém diz ser interno, eu esperaria pelo menos DMARC=pass em ambiente bem configurado
        if auth_failed:
            suspicious = True
            reasons.append(f"From interno, mas autenticação falhou (spf={spf}, dkim={dkim}, dmarc={dmarc})")
        elif auth_missing:
            suspicious = True
            reasons.append(f"From interno, mas faltam resultados de autenticação (spf={spf}, dkim={dkim}, dmarc={dmarc})")
        if return_path_mismatch:
            suspicious = True
            reasons.append(f"Return-Path não bate com From (return-path={rp_dom} vs from={from_dom})")

    summary = (
        f"From: {from_addr} (domínio: {from_dom})\n"
        f"Return-Path: {return_path} (domínio: {rp_dom})\n"
        f"Authentication-Results: spf={spf}, dkim={dkim}, dmarc={dmarc}\n"
    )

    if suspicious:
        summary += "SUSPEITO: " + " | ".join(reasons) + "\n"
    else:
        summary += "OK: sem sinais fortes de spoofing interno por estas heurísticas.\n"

    return suspicious, summary


def main():
    if len(sys.argv) < 2:
        print("Uso: python detect_spoof.py <arquivo.eml> [dominio_interno]")
        sys.exit(1)

    eml_path = Path(sys.argv[1])
    internal_domain = sys.argv[2] if len(sys.argv) >= 3 else DOMAIN

    msg = _read_eml(eml_path)
    suspicious, report = analyze_message(msg, internal_domain)
    print(report)
    sys.exit(2 if suspicious else 0)


if __name__ == "__main__":
    main()
