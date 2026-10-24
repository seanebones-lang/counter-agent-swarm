"""Bounded deterministic CISA KEV ingestion, producing advisory candidates only."""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import re
from typing import Any

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_FEED_BYTES = 8 * 1024 * 1024
MAX_VULNERABILITIES = 10_000


class IntelError(RuntimeError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IntelError("Duplicate feed key")
        result[key] = value
    return result


def _text(value: Any, limit: int) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 for c in value):
        raise IntelError("Invalid bounded feed text")
    return value


def _date(value: Any) -> str:
    value = _text(value, 10)
    try:
        if dt.date.fromisoformat(value).isoformat() != value:
            raise ValueError()
    except ValueError as exc:
        raise IntelError("Invalid advisory date") from exc
    return value


def parse_kev(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_FEED_BYTES:
        raise IntelError("Feed byte limit exceeded or feed empty")
    try:
        feed = json.loads(raw, object_pairs_hook=_unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(IntelError("Non-finite JSON")))
    except (ValueError, RecursionError) as exc:
        raise IntelError("Invalid feed JSON") from exc
    if not isinstance(feed, dict) or set(feed) != {"title", "catalogVersion", "dateReleased", "count", "vulnerabilities"}:
        raise IntelError("Unexpected KEV catalog schema")
    _text(feed["title"], 512)
    version = _text(feed["catalogVersion"], 64)
    released = _text(feed["dateReleased"], 64)
    try:
        timestamp = dt.datetime.fromisoformat(released.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError()
    except ValueError as exc:
        raise IntelError("Invalid catalog release timestamp") from exc
    rows = feed["vulnerabilities"]
    if (type(feed["count"]) is not int or not isinstance(rows, list)
            or not 0 <= feed["count"] <= MAX_VULNERABILITIES or len(rows) != feed["count"]):
        raise IntelError("Invalid catalog entry count")
    required = {"cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded",
                "shortDescription", "requiredAction", "dueDate", "knownRansomwareCampaignUse", "notes"}
    seen: set[str] = set()
    candidates: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or not required <= set(row) or set(row) - required - {"cwes"}:
            raise IntelError("Unexpected advisory schema")
        cve = _text(row["cveID"], 32)
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", cve) or cve in seen:
            raise IntelError("Invalid or duplicate CVE identifier")
        seen.add(cve)
        for field in ("vendorProject", "product", "vulnerabilityName"):
            _text(row[field], 512)
        for field in ("shortDescription", "requiredAction"):
            _text(row[field], 8192)
        if not isinstance(row["notes"], str) or len(row["notes"]) > 8192:
            raise IntelError("Invalid advisory notes")
        if row["knownRansomwareCampaignUse"] not in ("Known", "Unknown"):
            raise IntelError("Unexpected ransomware classification")
        cwes = row.get("cwes", [])
        if (not isinstance(cwes, list) or len(cwes) > 32
                or any(not isinstance(x, str) or not re.fullmatch(r"CWE-[0-9]{1,6}", x) for x in cwes)):
            raise IntelError("Invalid CWE identifiers")
        candidates.append({"cve_id": cve, "vendor": row["vendorProject"], "product": row["product"],
                           "title": row["vulnerabilityName"], "date_added": _date(row["dateAdded"]),
                           "remediation_due": _date(row["dueDate"]), "cwes": cwes,
                           "trust": "untrusted_public_advisory", "status": "review_candidate"})
    return {"schema_version": 1, "source": KEV_URL, "source_sha256": hashlib.sha256(raw).hexdigest(),
            "catalog_version": version, "date_released": released,
            "candidates": sorted(candidates, key=lambda item: item["cve_id"]),
            "automatic_promotion": False}


async def poll_kev(*, transport: httpx.AsyncBaseTransport | None = None) -> dict[str, Any]:
    """One fetch; schedule externally. No URL, credentials, or redirects accepted.

    transport is a programmatic test seam, never request/user configuration.
    No environment proxy, netrc, API credentials or model calls are used.
    """
    async def fetch() -> bytes:
        async with httpx.AsyncClient(transport=transport, timeout=httpx.Timeout(10, connect=5),
                                    follow_redirects=False, trust_env=False) as client:
            async with client.stream("GET", KEV_URL, headers={"Accept": "application/json",
                                                              "Accept-Encoding": "identity"}) as response:
                if response.status_code != 200:
                    raise IntelError("Official feed fetch failed or attempted redirect")
                if response.headers.get("content-encoding", "identity").lower() != "identity":
                    raise IntelError("Compressed feed responses are not accepted")
                kind = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if kind not in ("application/json", "application/octet-stream"):
                    raise IntelError("Unexpected feed content type")
                length = response.headers.get("content-length")
                if length is not None:
                    try:
                        if not 0 < int(length) <= MAX_FEED_BYTES:
                            raise IntelError("Declared feed exceeds byte limit")
                    except ValueError as exc:
                        raise IntelError("Invalid content length") from exc
                result = bytearray()
                async for block in response.aiter_raw(chunk_size=4096):
                    result.extend(block)
                    if len(result) > MAX_FEED_BYTES:
                        raise IntelError("Streamed feed exceeds byte limit")
                return bytes(result)
    try:
        return parse_kev(await asyncio.wait_for(fetch(), timeout=20))
    except (TimeoutError, httpx.HTTPError) as exc:
        raise IntelError("Official feed unavailable within network budget") from exc


def memory_handoff(catalog: dict[str, Any], cve_ids: list[str]) -> dict[str, Any]:
    """Bounded data-only record for a Mothership operator's memory adapter.

    It is deliberately not a native Mothership import or an instruction, and
    does not call an API, alter scopes, select tools, or activate a signature.
    """
    if (not isinstance(cve_ids, list) or len(cve_ids) > 50
            or any(not isinstance(x, str) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", x) for x in cve_ids)):
        raise IntelError("Invalid handoff selection")
    digest = catalog.get("source_sha256", "")
    if catalog.get("source") != KEV_URL or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise IntelError("Unrecognized catalog provenance")
    selected = set(cve_ids)
    records = [item for item in catalog.get("candidates", []) if item.get("cve_id") in selected]
    if len(records) != len(selected):
        raise IntelError("Selected advisory absent from catalog")
    return {"kind": "counter_swarm.intel_candidates.v1", "trust": "untrusted_public_advisory",
            "source": KEV_URL, "source_sha256": digest, "records": records,
            "instruction_authority": False, "automatic_promotion": False}
