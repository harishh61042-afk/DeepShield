import re
from collections import defaultdict
from urllib.parse import unquote


SUPPORTED_CYCLONEDX_VERSIONS = {"1.4", "1.5", "1.6"}
MAX_SBOM_COMPONENTS = 20_000
MAX_SBOM_DEPENDENCIES = 100_000
PURL_ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go", "cargo": "crates.io"}
_NAME = re.compile(r"^[A-Za-z0-9._:@/+!-]{1,255}$")


class SBOMValidationError(ValueError):
    pass


def validate_cyclonedx(document: object) -> dict:
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise SBOMValidationError("Expected a CycloneDX JSON BOM")
    if document.get("specVersion") not in SUPPORTED_CYCLONEDX_VERSIONS:
        raise SBOMValidationError("Supported CycloneDX versions are 1.4, 1.5 and 1.6")
    version = document.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise SBOMValidationError("CycloneDX version must be a positive integer")
    components = document.get("components", [])
    if not isinstance(components, list) or len(components) > MAX_SBOM_COMPONENTS:
        raise SBOMValidationError("CycloneDX components must be a list with at most 20,000 entries")
    refs: set[str] = set()
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise SBOMValidationError(f"Component {index + 1} must be an object")
        name = component.get("name")
        kind = component.get("type")
        if not isinstance(name, str) or not name.strip() or len(name) > 255:
            raise SBOMValidationError(f"Component {index + 1} has an invalid name")
        if not isinstance(kind, str) or kind not in {"application", "framework", "library", "container", "operating-system", "device", "firmware", "file", "machine-learning-model", "data", "cryptographic-asset"}:
            raise SBOMValidationError(f"Component {index + 1} has an invalid CycloneDX type")
        for field, maximum in (("version", 255), ("purl", 700), ("bom-ref", 700)):
            value = component.get(field)
            if value is not None and (not isinstance(value, str) or len(value) > maximum):
                raise SBOMValidationError(f"Component {index + 1} has an invalid {field}")
        if component.get("purl") and not re.match(r"^pkg:[A-Za-z0-9.+-]+/", component["purl"]):
            raise SBOMValidationError(f"Component {index + 1} has an invalid package URL")
        ref = component.get("bom-ref")
        if ref:
            if ref in refs:
                raise SBOMValidationError("CycloneDX bom-ref values must be unique")
            refs.add(ref)
        licenses = component.get("licenses", [])
        if licenses is not None and (not isinstance(licenses, list) or len(licenses) > 100):
            raise SBOMValidationError(f"Component {index + 1} has invalid license metadata")
    dependencies = document.get("dependencies", [])
    if dependencies is not None and (not isinstance(dependencies, list) or len(dependencies) > MAX_SBOM_DEPENDENCIES):
        raise SBOMValidationError("CycloneDX dependencies exceed the supported limit")
    if isinstance(dependencies, list):
        for row in dependencies:
            if not isinstance(row, dict) or not isinstance(row.get("ref"), str) or len(row["ref"]) > 700:
                raise SBOMValidationError("CycloneDX dependency entries must contain a valid ref")
            depends_on = row.get("dependsOn", [])
            if not isinstance(depends_on, list) or len(depends_on) > MAX_SBOM_COMPONENTS or any(not isinstance(ref, str) or len(ref) > 700 for ref in depends_on):
                raise SBOMValidationError("CycloneDX dependency references are invalid")
    return document


def _purl_identity(value: str):
    match = re.fullmatch(r"pkg:([A-Za-z0-9.+-]+)/(.+)", value)
    if not match:
        return None
    ecosystem = match.group(1).lower()
    coordinate = match.group(2).split("#", 1)[0].split("?", 1)[0]
    path, separator, version = coordinate.rpartition("@")
    if not separator:
        path, version = coordinate, ""
    return f"purl:{ecosystem}:{unquote(path).lower()}", unquote(version)


def component_identity(component: dict) -> tuple[str, str]:
    purl = component.get("purl")
    parsed = _purl_identity(purl) if isinstance(purl, str) else None
    if parsed:
        return parsed
    ecosystem = component.get("type") or component.get("ecosystem") or "unknown"
    group = component.get("group") or ""
    name = component.get("name") or ""
    identity = f"{ecosystem}:{group}:{name}".casefold()
    version = component.get("version") or ""
    return identity, str(version).casefold()


def compare_components(left: list[dict], right: list[dict]) -> dict:
    old_by_identity: dict[str, list[dict]] = defaultdict(list)
    new_by_identity: dict[str, list[dict]] = defaultdict(list)
    for component in left:
        old_by_identity[component_identity(component)[0]].append(component)
    for component in right:
        new_by_identity[component_identity(component)[0]].append(component)
    added, removed, changed = [], [], []
    for identity in sorted(set(old_by_identity) | set(new_by_identity)):
        old_rows = list(old_by_identity.get(identity, []))
        new_rows = list(new_by_identity.get(identity, []))
        new_by_version: dict[str, list[dict]] = defaultdict(list)
        for row in new_rows:
            new_by_version[component_identity(row)[1]].append(row)
        unmatched_old = []
        for row in old_rows:
            version = component_identity(row)[1]
            if new_by_version[version]:
                new_by_version[version].pop()
            else:
                unmatched_old.append(row)
        unmatched_new = [row for rows in new_by_version.values() for row in rows]
        while unmatched_old and unmatched_new:
            before, after = unmatched_old.pop(0), unmatched_new.pop(0)
            changed.append({"before": before, "after": after})
        removed.extend(unmatched_old)
        added.extend(unmatched_new)
    return {"added": added, "removed": removed, "changed": changed,
            "counts": {"added": len(added), "removed": len(removed), "changed": len(changed)}}


def sbom_query_component(component: dict) -> dict | None:
    purl = component.get("purl")
    parsed = _purl_identity(purl) if isinstance(purl, str) else None
    if not parsed:
        return None
    prefix = purl[4:].split("/", 1)[0].lower()
    ecosystem = PURL_ECOSYSTEMS.get(prefix)
    name = unquote(purl[4:].split("/", 1)[1].split("?", 1)[0].split("#", 1)[0].rsplit("@", 1)[0])
    version = component.get("version") or parsed[1]
    if component.get("version") and parsed[1] and component["version"].casefold() != parsed[1].casefold():
        return None
    if not ecosystem or not isinstance(version, str) or not version.strip() or not _NAME.fullmatch(name):
        return None
    return {"name": name, "version": version, "ecosystem": ecosystem, "resolution": "resolved"}
