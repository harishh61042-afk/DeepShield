import time
import threading
import hashlib
import math
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import httpx

from app.core.config import settings
from app.models.entities import IntelligenceCache
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

ECOSYSTEMS = {"PyPI": "PyPI", "npm": "npm", "Maven": "Maven", "Go": "Go", "crates.io": "crates.io"}
_nvd_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_nvd_last_call = 0.0
_nvd_lock = threading.Lock()
_advisory_cache: dict[str, tuple[float, dict[str, Any]]] = {}
MAX_OSV_PAGES = 10
MAX_OSV_ADVISORIES_PER_COMPONENT = 5000
MAX_OSV_ADVISORIES_PER_BATCH = 10000


class IntelligenceUnavailable(RuntimeError):
    pass


def _valid_advisory(advisory: Any) -> bool:
    if not isinstance(advisory, dict) or not isinstance(advisory.get("id"), str) or not advisory["id"].strip() or len(advisory["id"]) > 100:
        return False
    for field in ("summary", "details", "published", "modified", "withdrawn"):
        if field in advisory and advisory[field] is not None and not isinstance(advisory[field], str):
            return False
    aliases = advisory.get("aliases", [])
    references = advisory.get("references", [])
    affected = advisory.get("affected")
    if not isinstance(aliases, list) or any(not isinstance(value, str) for value in aliases):
        return False
    if not isinstance(references, list) or any(not isinstance(item, dict) or not isinstance(item.get("url", ""), str) for item in references):
        return False
    if not isinstance(affected, list):
        return False
    for item in affected:
        if not isinstance(item, dict):
            return False
        package = item.get("package", {})
        ranges = item.get("ranges", [])
        if package is not None and not isinstance(package, dict):
            return False
        if isinstance(package, dict) and any(package.get(field) is not None and not isinstance(package[field], str) for field in ("name", "ecosystem", "purl")):
            return False
        if not isinstance(ranges, list):
            return False
        for range_item in ranges:
            if not isinstance(range_item, dict) or not isinstance(range_item.get("events", []), list):
                return False
            if any(not isinstance(event, dict) or any(event.get(key) is not None and not isinstance(event[key], str) for key in ("introduced", "fixed", "last_affected", "limit")) for event in range_item.get("events", [])):
                return False
    return True


def _post_with_retry(client: httpx.Client, url: str, body: dict, headers: dict | None = None, deadline: float | None = None) -> dict:
    error = None
    for attempt in range(3):
        try:
            remaining = deadline - time.monotonic() if deadline is not None else None
            if remaining is not None and remaining <= 0:
                raise IntelligenceUnavailable("Scan intelligence deadline reached")
            timeout = min(settings.osv_timeout_seconds, remaining) if remaining is not None else settings.osv_timeout_seconds
            response = client.post(url, json=body, headers=headers or {}, timeout=timeout)
            if response.status_code == 429 or response.status_code >= 500:
                if attempt < 2:
                    delay = 0.5 * (2**attempt)
                    if deadline is not None:
                        delay = min(delay, max(0, deadline - time.monotonic()))
                    if delay:
                        time.sleep(delay)
                    continue
            response.raise_for_status()
            result = response.json()
            if not isinstance(result, dict):
                raise ValueError("Unexpected service response")
            return result
        except (httpx.HTTPError, ValueError) as exc:
            error = exc
            if attempt < 2:
                delay = 0.5 * (2**attempt)
                if deadline is not None:
                    delay = min(delay, max(0, deadline - time.monotonic()))
                if delay:
                    time.sleep(delay)
    raise IntelligenceUnavailable("OSV service could not be reached") from error


def _get_advisory_with_retry(client: httpx.Client, advisory_id: str, deadline: float | None = None) -> dict:
    url = f"{settings.osv_base_url.rstrip('/')}/v1/vulns/{quote(advisory_id, safe='')}"
    error = None
    for attempt in range(3):
        try:
            remaining = deadline - time.monotonic() if deadline is not None else None
            if remaining is not None and remaining <= 0:
                raise IntelligenceUnavailable("Scan intelligence deadline reached")
            timeout = min(settings.osv_timeout_seconds, remaining) if remaining is not None else settings.osv_timeout_seconds
            response = client.get(url, timeout=timeout)
            if response.status_code == 404:
                raise IntelligenceUnavailable("OSV advisory record is no longer available")
            if response.status_code == 429 or response.status_code >= 500:
                if attempt < 2:
                    delay = 0.5 * (2**attempt)
                    if deadline is not None:
                        delay = min(delay, max(0, deadline - time.monotonic()))
                    if delay:
                        time.sleep(delay)
                    continue
            response.raise_for_status()
            result = response.json()
            if not isinstance(result, dict):
                raise ValueError("Unexpected OSV advisory response")
            return result
        except IntelligenceUnavailable:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            error = exc
            if attempt < 2:
                delay = 0.5 * (2**attempt)
                if deadline is not None:
                    delay = min(delay, max(0, deadline - time.monotonic()))
                if delay:
                    time.sleep(delay)
    raise IntelligenceUnavailable("OSV advisory details could not be retrieved") from error


def _query_rows(response: dict, expected: int) -> list[tuple[list[dict], str | None]]:
    results = response.get("results")
    if not isinstance(results, list) or len(results) != expected:
        raise IntelligenceUnavailable("OSV returned an invalid batch response")
    rows = []
    for row in results:
        if not isinstance(row, dict) or not isinstance(row.get("vulns"), list):
            raise IntelligenceUnavailable("OSV returned an invalid result row")
        vulns = row["vulns"]
        if any(
            not isinstance(item, dict)
            or not isinstance(item.get("id"), str)
            or not item["id"].strip()
            or len(item["id"]) > 100
            or (item.get("modified") is not None and not isinstance(item["modified"], str))
            for item in vulns
        ):
            raise IntelligenceUnavailable("OSV returned an invalid vulnerability reference")
        token = row.get("next_page_token")
        if token is not None and (not isinstance(token, str) or not token):
            raise IntelligenceUnavailable("OSV returned an invalid pagination token")
        rows.append((vulns, token))
    return rows


def query_components(components: list[dict], deadline: float | None = None) -> tuple[dict[int, list[dict]], str]:
    """Query exact versions, fetch full advisory records, and preserve partial-source status."""
    eligible = [(i, c) for i, c in enumerate(components) if c.get("version") and c.get("resolution") in {"resolved", "declared_unverified"} and c.get("ecosystem") in ECOSYSTEMS]
    found: dict[int, list[dict]] = {}
    if not eligible:
        return found, "unresolved"
    references_by_index: dict[int, dict[str, dict]] = {index: {} for index, _ in eligible}
    partial = False
    reference_count = 0
    with httpx.Client(timeout=settings.osv_timeout_seconds, follow_redirects=False) as client:
        for offset in range(0, len(eligible), 1000):
            batch = eligible[offset:offset + 1000]
            requests = [{"package": {"name": c["name"], "ecosystem": ECOSYSTEMS[c["ecosystem"]]}, "version": c["version"]} for _, c in batch]
            try:
                response = _post_with_retry(client, f"{settings.osv_base_url.rstrip('/')}/v1/querybatch", {"queries": requests}, deadline=deadline)
                rows = _query_rows(response, len(batch))
            except IntelligenceUnavailable:
                partial = True
                continue

            pending = []
            for position, ((index, _), (vulns, token)) in enumerate(zip(batch, rows)):
                references = references_by_index[index]
                for advisory in vulns:
                    if advisory["id"] not in references and (len(references) >= MAX_OSV_ADVISORIES_PER_COMPONENT or reference_count >= MAX_OSV_ADVISORIES_PER_BATCH):
                        partial = True
                        continue
                    if advisory["id"] not in references:
                        reference_count += 1
                    references[advisory["id"]] = advisory
                if token and len(references) < MAX_OSV_ADVISORIES_PER_COMPONENT and reference_count < MAX_OSV_ADVISORIES_PER_BATCH:
                    pending.append((position, token))
                elif token:
                    partial = True

            page_count = 0
            while pending and page_count < MAX_OSV_PAGES:
                page_count += 1
                queries = [{**requests[position], "page_token": token} for position, token in pending]
                try:
                    response = _post_with_retry(client, f"{settings.osv_base_url.rstrip('/')}/v1/querybatch", {"queries": queries}, deadline=deadline)
                    rows = _query_rows(response, len(pending))
                except IntelligenceUnavailable:
                    partial = True
                    break
                next_pending = []
                for (position, _), (vulns, token) in zip(pending, rows):
                    index = batch[position][0]
                    references = references_by_index[index]
                    for advisory in vulns:
                        if advisory["id"] not in references and (len(references) >= MAX_OSV_ADVISORIES_PER_COMPONENT or reference_count >= MAX_OSV_ADVISORIES_PER_BATCH):
                            partial = True
                            continue
                        if advisory["id"] not in references:
                            reference_count += 1
                        references[advisory["id"]] = advisory
                    if token and len(references) < MAX_OSV_ADVISORIES_PER_COMPONENT and reference_count < MAX_OSV_ADVISORIES_PER_BATCH:
                        next_pending.append((position, token))
                    elif token:
                        partial = True
                pending = next_pending
            if pending:
                partial = True

    all_ids = list(dict.fromkeys(advisory_id for refs in references_by_index.values() for advisory_id in refs))
    query_metadata_by_id = {
        advisory_id: advisory
        for refs in references_by_index.values()
        for advisory_id, advisory in refs.items()
    }
    if sum(len(refs) for refs in references_by_index.values()) > MAX_OSV_ADVISORIES_PER_BATCH:
        partial = True
        all_ids = all_ids[:MAX_OSV_ADVISORIES_PER_BATCH]
    details_by_id: dict[str, dict | None] = {}
    with httpx.Client(timeout=settings.osv_timeout_seconds, follow_redirects=False) as detail_client:
        for advisory_id in all_ids:
            cached = _advisory_cache.get(advisory_id)
            remote_modified = query_metadata_by_id.get(advisory_id, {}).get("modified")
            revision_matches = not isinstance(remote_modified, str) or cached and cached[1].get("modified") == remote_modified
            if cached and revision_matches and time.monotonic() - cached[0] < settings.intelligence_cache_hours * 3600 and _valid_advisory(cached[1]):
                details_by_id[advisory_id] = cached[1]
                continue
            try:
                advisory = _get_advisory_with_retry(detail_client, advisory_id, deadline=deadline)
            except IntelligenceUnavailable:
                advisory = None
            if not isinstance(advisory, dict) or advisory.get("id") != advisory_id or not _valid_advisory(advisory):
                partial = True
                metadata = query_metadata_by_id.get(advisory_id, {})
                stub = {"id": advisory_id}
                if isinstance(metadata.get("modified"), str):
                    stub["modified"] = metadata["modified"]
                details_by_id[advisory_id] = stub
                continue
            if advisory.get("withdrawn"):
                details_by_id[advisory_id] = None
                _advisory_cache.pop(advisory_id, None)
                continue
            _advisory_cache[advisory_id] = (time.monotonic(), advisory)
            details_by_id[advisory_id] = advisory
    if len(_advisory_cache) > 10000:
        cutoff = time.monotonic() - settings.intelligence_cache_hours * 3600
        _advisory_cache.update({key: value for key, value in _advisory_cache.items() if value[0] >= cutoff})
        while len(_advisory_cache) > 10000:
            _advisory_cache.pop(next(iter(_advisory_cache)))

    for index, references in references_by_index.items():
        found[index] = [details_by_id[advisory_id] for advisory_id in references if details_by_id.get(advisory_id) is not None]
    if not all_ids:
        return found, "unavailable" if partial else "available"
    if any(details_by_id.get(advisory_id) is None for advisory_id in all_ids):
        partial = True
    return found, "partial" if partial else "available"


def _component_key(component: dict) -> str:
    ecosystem = component.get("ecosystem")
    name = component.get("name", "")
    if ecosystem in {"PyPI", "npm", "crates.io"}:
        name = name.lower()
    raw = f"{ecosystem}|{name}|{component.get('version')}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def query_components_cached(db, components: list[dict], deadline: float | None = None) -> tuple[dict[int, list[dict]], str]:
    now = datetime.now(timezone.utc)
    eligible = [(i, c) for i, c in enumerate(components) if c.get("version") and c.get("resolution") in {"resolved", "declared_unverified"} and c.get("ecosystem") in ECOSYSTEMS]
    if not eligible:
        return {}, "unresolved"
    keys = {_component_key(c) for _, c in eligible}
    rows = db.scalars(select(IntelligenceCache).where(IntelligenceCache.source == "osv", IntelligenceCache.cache_key.in_(keys))).all()
    cache = {row.cache_key: row for row in rows}
    found: dict[int, list[dict]] = {}
    missing_by_key: dict[str, list[int]] = {}
    components_by_key: dict[str, dict] = {}
    stale_for: dict[str, list[dict]] = {}
    for index, component in eligible:
        key = _component_key(component)
        row = cache.get(key)
        payload = row.payload if row and isinstance(row.payload, dict) else {}
        advisories = payload.get("vulns", [])
        cache_valid = isinstance(advisories, list) and all(_valid_advisory(item) for item in advisories)
        if row and row.expires_at > now and cache_valid:
            found[index] = advisories
        else:
            missing_by_key.setdefault(key, []).append(index)
            components_by_key.setdefault(key, component)
            if row and cache_valid:
                stale_for[key] = advisories
    if not missing_by_key:
        return found, "cached"
    missing_keys = list(missing_by_key)
    fetched, status = query_components([components_by_key[key] for key in missing_keys], deadline=deadline)
    if status in {"available", "partial"}:
        for position, key in enumerate(missing_keys):
            advisories = fetched.get(position, [])
            for index in missing_by_key[key]:
                found[index] = advisories
            if status == "partial":
                continue
            row = cache.get(key)
            if row:
                row.payload = {"vulns": advisories}
                row.fetched_at = now
                row.expires_at = now + timedelta(hours=settings.intelligence_cache_hours)
            else:
                db.add(IntelligenceCache(source="osv", cache_key=key, payload={"vulns": advisories}, fetched_at=now, expires_at=now + timedelta(hours=settings.intelligence_cache_hours)))
        if status == "partial":
            return found, status
        try:
            db.commit()
        except IntegrityError:
            # Another worker may have inserted the same key after our initial cache read.
            db.rollback()
            rows = db.scalars(select(IntelligenceCache).where(IntelligenceCache.source == "osv", IntelligenceCache.cache_key.in_(missing_keys))).all()
            existing = {row.cache_key: row for row in rows}
            for position, key in enumerate(missing_keys):
                row = existing.get(key)
                if row:
                    row.payload = {"vulns": fetched.get(position, [])}
                    row.fetched_at = now
                    row.expires_at = now + timedelta(hours=settings.intelligence_cache_hours)
            db.commit()
        return found, "available"
    for key, indices in missing_by_key.items():
        if key in stale_for:
            for index in indices:
                found[index] = stale_for[key]
    return found, "stale" if stale_for else status


def fixed_versions(vulnerability: dict, ecosystem: str, component_name: str) -> list[str]:
    fixes = set()
    affected_rows = vulnerability.get("affected", [])
    if not isinstance(affected_rows, list):
        return []
    compare = (lambda value: value.lower()) if ecosystem in {"PyPI", "npm", "crates.io"} else (lambda value: value)
    for affected in affected_rows:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package", {})
        if not isinstance(package, dict) or not isinstance(package.get("name", ""), str) or compare(package.get("name", "")) != compare(component_name):
            continue
        if package.get("ecosystem") != ECOSYSTEMS.get(ecosystem):
            continue
        ranges = affected.get("ranges", [])
        if not isinstance(ranges, list):
            continue
        for rng in ranges:
            if not isinstance(rng, dict) or not isinstance(rng.get("events", []), list):
                continue
            for event in rng.get("events", []):
                if not isinstance(event, dict):
                    continue
                if event.get("fixed"):
                    fixes.add(str(event["fixed"]))
    return sorted(fixes)


def affected_ranges(vulnerability: dict, ecosystem: str, component_name: str) -> list[dict]:
    """Retain bounded OSV range events for findings as source evidence."""
    affected_rows = vulnerability.get("affected", [])
    if not isinstance(affected_rows, list):
        return []
    compare = (lambda value: value.lower()) if ecosystem in {"PyPI", "npm", "crates.io"} else (lambda value: value)
    output = []
    for affected in affected_rows:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package", {})
        if not isinstance(package, dict) or not isinstance(package.get("name", ""), str) or compare(package.get("name", "")) != compare(component_name):
            continue
        if package.get("ecosystem") != ECOSYSTEMS.get(ecosystem):
            continue
        ranges = affected.get("ranges", [])
        if not isinstance(ranges, list):
            continue
        for row in ranges:
            if not isinstance(row, dict) or not isinstance(row.get("events", []), list):
                continue
            events = []
            for event in row["events"]:
                if not isinstance(event, dict):
                    continue
                sanitized = {key: event[key] for key in ("introduced", "fixed", "last_affected", "limit") if isinstance(event.get(key), str)}
                if sanitized:
                    events.append(sanitized)
            if events:
                output.append({"type": str(row.get("type", "UNKNOWN"))[:40], "events": events[:100]})
        versions = affected.get("versions", [])
        if isinstance(versions, list):
            exact = [value for value in versions if isinstance(value, str) and len(value) <= 255][:500]
            if exact:
                output.append({"type": "ECOSYSTEM", "versions": exact})
    return output[:100]


def cve_ids(vulnerability: dict) -> list[str]:
    aliases = vulnerability.get("aliases", [])
    if not isinstance(aliases, list):
        aliases = []
    identifiers = {a for a in aliases if isinstance(a, str) and a.startswith("CVE-")}
    advisory_id = vulnerability.get("id")
    if isinstance(advisory_id, str) and advisory_id.startswith("CVE-"):
        identifiers.add(advisory_id)
    return sorted(identifiers)


def nvd_enrich(cve_id: str, deadline: float | None = None) -> dict[str, Any]:
    if not settings.nvd_enabled:
        return {}
    global _nvd_last_call
    cached = _nvd_cache.get(cve_id)
    if cached and time.monotonic() - cached[0] < settings.intelligence_cache_hours * 3600:
        return cached[1]
    params = {"cveId": cve_id}
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    try:
        with _nvd_lock:
            minimum_interval = 0.7 if settings.nvd_api_key else 6.2
            wait = minimum_interval - (time.monotonic() - _nvd_last_call)
            remaining = deadline - time.monotonic() if deadline is not None else None
            if remaining is not None and remaining <= max(0, wait) + 1:
                return {"_unavailable": True, "_deferred": True}
            if wait > 0:
                time.sleep(wait)
            remaining = deadline - time.monotonic() if deadline is not None else None
            if remaining is not None and remaining <= 0:
                return {"_unavailable": True, "_deferred": True}
            timeout = min(12, remaining) if remaining is not None else 12
            with httpx.Client(timeout=timeout, follow_redirects=False) as client:
                response = client.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, headers=headers)
                _nvd_last_call = time.monotonic()
                if response.status_code == 429:
                    return {"_unavailable": True}
                response.raise_for_status()
                payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("Invalid NVD response")
            records = payload.get("vulnerabilities", [])
            if not isinstance(records, list):
                raise ValueError("Invalid NVD response")
            if not records:
                _nvd_cache[cve_id] = (time.monotonic(), {})
                return {}
            first = records[0]
            if not isinstance(first, dict) or not isinstance(first.get("cve", {}), dict):
                raise ValueError("Invalid NVD record")
            cve = first.get("cve", {})
            descriptions = cve.get("descriptions", [])
            if not isinstance(descriptions, list) or any(not isinstance(item, dict) or (item.get("value") is not None and not isinstance(item["value"], str)) for item in descriptions):
                raise ValueError("Invalid NVD descriptions")
            description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
            metrics = cve.get("metrics", {})
            if not isinstance(metrics, dict):
                raise ValueError("Invalid NVD metrics")
            scores = []
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_rows = metrics.get(key, [])
                if not isinstance(metric_rows, list) or any(not isinstance(metric, dict) for metric in metric_rows):
                    raise ValueError("Invalid NVD metric list")
                for metric in metric_rows:
                    data = metric.get("cvssData", {})
                    if not isinstance(data, dict):
                        raise ValueError("Invalid NVD CVSS data")
                    score = data.get("baseScore")
                    if score is not None:
                        if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 10:
                            raise ValueError("Invalid NVD CVSS score")
                        severity = data.get("baseSeverity")
                        if severity is not None and (not isinstance(severity, str) or severity.upper() not in {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}):
                            raise ValueError("Invalid NVD CVSS severity")
                        scores.append((float(score), severity))
            score, severity = scores[0] if scores else (None, None)
            weaknesses = []
            weakness_rows = cve.get("weaknesses", [])
            if not isinstance(weakness_rows, list) or any(not isinstance(item, dict) for item in weakness_rows):
                raise ValueError("Invalid NVD weaknesses")
            for item in weakness_rows:
                descriptions = item.get("description", [])
                if not isinstance(descriptions, list) or any(not isinstance(desc, dict) for desc in descriptions):
                    raise ValueError("Invalid NVD weakness description")
                for desc in descriptions:
                    value = desc.get("value", "")
                    if not isinstance(value, str):
                        raise ValueError("Invalid NVD weakness value")
                    if value.startswith("CWE-"):
                        weaknesses.append(desc["value"])
            published, modified = cve.get("published"), cve.get("lastModified")
            if any(value is not None and not isinstance(value, str) for value in (published, modified)):
                raise ValueError("Invalid NVD dates")
            value = {"description": description, "cvss": score, "severity": severity, "cwes": sorted(set(weaknesses)), "published": published, "modified": modified}
            _nvd_cache[cve_id] = (time.monotonic(), value)
            return value
    except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError):
        return {"_unavailable": True}
