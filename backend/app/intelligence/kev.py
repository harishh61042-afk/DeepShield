import time

import httpx

from app.core.config import settings

_cache: tuple[float, set[str]] | None = None


def load_kev(deadline: float | None = None) -> tuple[set[str], str]:
    global _cache
    if _cache and time.time() - _cache[0] < 12 * 60 * 60:
        return _cache[1], "cached"
    try:
        remaining = deadline - time.monotonic() if deadline is not None else 15
        if remaining <= 0:
            raise httpx.TimeoutException("Scan intelligence deadline reached")
        with httpx.Client(timeout=min(15, remaining), follow_redirects=False) as client:
            response = client.get(settings.cisa_kev_url)
            response.raise_for_status()
            payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Invalid KEV document")
        entries = payload.get("vulnerabilities")
        if not isinstance(entries, list):
            raise ValueError("Invalid KEV document")
        if any(not isinstance(item, dict) or not isinstance(item.get("cveID"), str) or not item["cveID"].startswith("CVE-") for item in entries):
            raise ValueError("Invalid KEV entry")
        ids = {item["cveID"] for item in entries}
        _cache = (time.time(), ids)
        return ids, "available"
    except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError):
        if _cache:
            return _cache[1], "stale"
        return set(), "unavailable"
