"""Bounded deterministic indicators. Never decompress or execute request data.

These are cautious indicators/resource limits, not complete CVE signatures or
proof of exploitation. Mutations include two URL-encoding layers and case.
"""
from __future__ import annotations
import hashlib
import json
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

MAX_BODY = 65536


@dataclass(frozen=True)
class Finding:
    event_id: str
    fingerprint: str
    rules: tuple[str, ...]
    severity: str
    source: str = "proxy"
    trust: str = "external_untrusted"

    def record(self) -> dict:
        return {"event_id": self.event_id, "fingerprint": self.fingerprint,
                "rules": list(self.rules), "severity": self.severity,
                "source": self.source, "trust": self.trust, "policy_revision": "builtin-1"}


def inspect_request(path: str, query: bytes, headers: list[tuple[bytes, bytes]], body: bytes) -> Finding | None:
    reasons = []
    hs: dict[str, list[str]] = {}
    for name, value in headers:
        hs.setdefault(name.decode("latin1").lower(), []).append(value.decode("latin1").strip())
    if len(headers) > 64 or sum(len(a) + len(b) for a, b in headers) > 16384:
        reasons.append("header-budget")
    if len(body) > MAX_BODY or len(query) > 8192 or len(path) > 4096:
        reasons.append("request-budget")
    if any(v.lower() != "identity" for v in hs.get("content-encoding", [])):
        # Conservative virtual mitigation. No vulnerable decoder in the hot path.
        reasons.append("unsupported-compressed-body")
    if len(hs.get("content-length", [])) > 1 or ("content-length" in hs and "transfer-encoding" in hs):
        reasons.append("ambiguous-framing")
    raw = (path.encode("utf8") + b"?" + query + b"\n" + body)[:MAX_BODY + 12288]
    text = raw.decode("utf8", errors="replace")
    for _ in range(2):
        text = unquote(text, errors="replace")
    text = unicodedata.normalize("NFKC", text).casefold()
    if "\x00" in text:
        reasons.append("nul-in-request")
    if "<?php" in text and any(x in text for x in ("shell_exec", "system(", "eval(", "assert(")):
        reasons.append("php-execution-indicator")
    if ("auto_prepend_file" in text or "allow_url_include" in text) and ("php://" in text or "-d" in text):
        reasons.append("php-cgi-indicator")
    if "next-action" in hs and any(x in text for x in ("__proto__", "constructor:constructor")):
        reasons.append("rsc-prototype-indicator")
    if not reasons:
        return None
    fingerprint = hashlib.sha256(raw + json.dumps(sorted(reasons)).encode()).hexdigest()
    return Finding("evt_" + fingerprint[:24], fingerprint, tuple(sorted(set(reasons))), "high")
