"""Read-only dependency manifest parsers. Uploaded code is never executed."""

import io
import json
import re
import tomllib
import zipfile
from pathlib import PurePosixPath
from urllib.parse import quote

from defusedxml import ElementTree as SafeET

MAX_TEXT_BYTES = 5 * 1024 * 1024
MAX_COMPONENTS = 20_000


class ManifestError(ValueError):
    pass


def _purl(ecosystem: str, name: str, version: str | None) -> str | None:
    if not version:
        return None
    ptype = {"PyPI": "pypi", "npm": "npm", "Maven": "maven", "Go": "golang", "crates.io": "cargo"}[ecosystem]
    normalized = name
    if ecosystem == "Maven" and ":" in name:
        group, artifact = name.split(":", 1)
        normalized = f"{quote(group, safe='.')}/{quote(artifact, safe='.-_')}"
    elif ecosystem == "npm" and name.startswith("@") and "/" in name:
        scope, package = name.split("/", 1)
        normalized = f"{quote(scope.lower(), safe='@')}/{quote(package.lower(), safe='.-_')}"
    elif ecosystem == "Go":
        # Go module paths use !-escaped lower-case letters for uppercase characters.
        escaped = "".join(f"!{char.lower()}" if char.isupper() else char for char in name)
        normalized = quote(escaped, safe="/.-_@")
    else:
        casefolded = name.lower() if ecosystem in {"PyPI", "crates.io"} else name
        normalized = quote(casefolded, safe=".-_@")
    return f"pkg:{ptype}/{normalized}@{quote(version, safe='.+-_')}"


def _component(name, version, ecosystem, manifest, directness="unknown", resolution=None, constraint=None, license=None, dependencies=None):
    name = (str(name or "").strip())
    version = str(version).strip() if version is not None else None
    resolution = resolution or ("resolved" if version else "declared_unverified")
    if not name:
        return None
    return {
        "name": name,
        "version": version,
        "version_constraint": constraint,
        "ecosystem": ecosystem,
        "purl": _purl(ecosystem, name, version),
        "directness": directness if directness in {"direct", "transitive", "unknown"} else "unknown",
        "resolution": resolution,
        "manifest": manifest[:255],
        "license": str(license)[:255] if license else None,
        "dependencies": dependencies or [],
    }


def parse_requirements(text: str, manifest: str = "requirements.txt") -> list[dict]:
    result = []
    physical = text.splitlines()
    lines = []
    carry = ""
    for raw in physical:
        raw = carry + raw.strip()
        if raw.endswith("\\"):
            carry = raw[:-1] + " "
            continue
        lines.append(raw)
        carry = ""
    if carry:
        raise ManifestError("requirements.txt ends with an incomplete line continuation")
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("--index-url", "--extra-index-url", "--trusted-host", "--find-links", "--no-index", "--require-hashes")):
            continue
        if line.startswith(("-", "\\")):
            raise ManifestError("requirements.txt contains an unsupported include, option, or editable declaration")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^]]+\])?\s*@\s*\S+", line):
            name = re.split(r"\s*@\s*", line, maxsplit=1)[0].split("[", 1)[0]
            result.append(_component(name, None, "PyPI", manifest, "direct", resolution="declared_unverified", constraint="direct URL; version unverified"))
            continue
        m = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^]]+\])?\s*(.*)", line)
        if not m:
            raise ManifestError("requirements.txt contains a declaration that could not be safely identified")
        name, spec = m.groups()
        spec = spec.split(";", 1)[0].strip()
        exact = re.fullmatch(r"={1,3}\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)", spec) if spec else None
        result.append(_component(name, exact.group(1) if exact else None, "PyPI", manifest, "direct", resolution="declared_unverified", constraint=spec or None))
        if len(result) > MAX_COMPONENTS:
            raise ManifestError("Manifest exceeds the component count limit")
    return result


def parse_package_lock(data: dict, manifest="package-lock.json") -> list[dict]:
    if not isinstance(data, dict):
        raise ManifestError("package-lock.json must contain a JSON object")
    version = data.get("lockfileVersion", 1)
    if type(version) is not int or version not in {1, 2, 3}:
        raise ManifestError(f"Unsupported npm lockfile version: {version}")
    result = []
    packages = data.get("packages")
    if packages is not None and not isinstance(packages, dict):
        raise ManifestError("package-lock.json packages must be an object")
    if isinstance(packages, dict):
        root = packages.get("", {}) or {}
        if not isinstance(root, dict):
            raise ManifestError("package-lock.json root package must be an object")

        def dependency_map(value, field):
            if value is None:
                return {}
            if not isinstance(value, dict):
                raise ManifestError(f"package-lock.json {field} must be an object")
            return value

        direct_names = set()
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            direct_names.update(dependency_map(root.get(field), field))

        # v2/v3 can carry the v1 dependency tree as a compatibility fallback.
        if packages or "dependencies" not in data:
            for path, info in packages.items():
                if not path:
                    continue
                if not isinstance(info, dict):
                    raise ManifestError("package-lock.json package entries must be objects")
                marker = "node_modules/"
                if marker not in path:
                    continue
                name = path.rsplit(marker, 1)[1]
                if not name or name.startswith("../"):
                    continue
                version_value = info.get("version")
                if version_value is not None and not isinstance(version_value, str):
                    raise ManifestError("package-lock.json package versions must be strings")
                dependency_names = set()
                for field in ("dependencies", "optionalDependencies"):
                    dependency_names.update(dependency_map(info.get(field), field))
                is_direct = name in direct_names and path == f"node_modules/{name}"
                item = _component(name, version_value, "npm", manifest, "direct" if is_direct else "transitive", license=info.get("license"))
                if item:
                    item["_lock_path"] = path
                    item["_dependency_names"] = sorted(dependency_names)
                    result.append(item)
            path_rows = {item.pop("_lock_path"): item for item in result}
            path_by_object = {id(item): path for path, item in path_rows.items()}
            for item in result:
                parent_path = path_by_object.get(id(item), "")
                names = item.pop("_dependency_names", [])
                for dependency_name in names:
                    base = parent_path
                    candidates = []
                    while base:
                        candidates.append(f"{base}/node_modules/{dependency_name}")
                        parts = base.split("/node_modules/")
                        base = parts[0] if len(parts) > 1 else ""
                    candidates.append(f"node_modules/{dependency_name}")
                    child = next((path_rows[p] for p in candidates if p in path_rows), None)
                    if child and child.get("purl"):
                        item["dependencies"].append(child["purl"])
            return result

    def walk(deps, parent=None):
        if not isinstance(deps, dict):
            raise ManifestError("package-lock.json dependencies must be an object")
        for name, info in deps.items():
            if not isinstance(info, dict):
                raise ManifestError("package-lock.json dependency entries must be objects")
            version_value = info.get("version")
            if version_value is not None and not isinstance(version_value, str):
                raise ManifestError("package-lock.json dependency versions must be strings")
            item = _component(name, version_value, "npm", manifest, "transitive" if parent else "direct", license=info.get("license"))
            if item:
                result.append(item)
                if parent is not None and item.get("purl"):
                    parent["dependencies"].append(item["purl"])
            nested = info.get("dependencies")
            if nested is not None:
                walk(nested, item)
    legacy_dependencies = data.get("dependencies", {})
    if legacy_dependencies is not None:
        walk(legacy_dependencies)
    return result


def parse_pom(data: bytes, manifest="pom.xml") -> list[dict]:
    if len(data) > MAX_TEXT_BYTES:
        raise ManifestError("pom.xml exceeds the parser size limit")
    try:
        root = SafeET.fromstring(data)
    except Exception as exc:
        raise ManifestError("Malformed or unsafe pom.xml") from exc
    ns = "{" + root.tag.split("}", 1)[0].lstrip("{") + "}" if "}" in root.tag else ""
    props = {}
    properties = root.find(f"{ns}properties")
    if properties is not None:
        for child in properties:
            props[child.tag.rsplit("}", 1)[-1]] = (child.text or "").strip()
    def resolve(value):
        if not value:
            return None
        current = value.strip()
        for _ in range(5):
            m = re.search(r"\$\{([^}]+)\}", current)
            if not m:
                break
            replacement = props.get(m.group(1))
            if replacement is None:
                return None
            current = current[:m.start()] + replacement + current[m.end():]
        return current if "${" not in current else None
    result = []
    deps = root.find(f"{ns}dependencies")
    if deps is None:
        return result
    for dep in deps.findall(f"{ns}dependency"):
        group = resolve(dep.findtext(f"{ns}groupId"))
        artifact = resolve(dep.findtext(f"{ns}artifactId"))
        version = resolve(dep.findtext(f"{ns}version"))
        scope = resolve(dep.findtext(f"{ns}scope")) or "compile"
        optional = (dep.findtext(f"{ns}optional") or "false").lower() == "true"
        if not group or not artifact:
            raise ManifestError("pom.xml contains a dependency without a resolvable groupId or artifactId")
        item = _component(f"{group}:{artifact}", version, "Maven", manifest, "direct", resolution="declared_unverified" if version else "unresolved", constraint=version)
        if item:
            item["optional"] = optional
            item["scope"] = scope
            result.append(item)
    return result


def parse_go_mod(text: str, manifest="go.mod") -> list[dict]:
    result = []
    block = False
    for raw in text.splitlines():
        indirect = "// indirect" in raw
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line == "require (":
            if block:
                raise ManifestError("go.mod contains a nested require block")
            block = True
            continue
        if line == ")" and block:
            block = False
            continue
        if line == "require" or line.startswith("require "):
            line = line[len("require "):]
            if not line:
                raise ManifestError("go.mod contains an empty require directive")
        elif not block:
            continue
        m = re.match(r"([^\s]+)\s+(v[^\s]+)", line)
        if not m:
            raise ManifestError("go.mod contains a malformed require declaration")
        module, version = m.groups()
        result.append(_component(module, version, "Go", manifest, "transitive" if indirect else "direct", resolution="declared_unverified"))
    if block:
        raise ManifestError("go.mod contains an unterminated require block")
    return result


def parse_cargo_lock(data: bytes, manifest="Cargo.lock") -> list[dict]:
    if len(data) > MAX_TEXT_BYTES:
        raise ManifestError("Cargo.lock exceeds the parser size limit")
    try:
        parsed = tomllib.loads(data.decode("utf-8-sig"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ManifestError("Malformed Cargo.lock") from exc
    packages = parsed.get("package", [])
    if not isinstance(packages, list):
        raise ManifestError("Cargo.lock package field must be an array")
    result = []
    for pkg in packages:
        if not isinstance(pkg, dict):
            raise ManifestError("Cargo.lock package entries must be tables")
        name, version = pkg.get("name"), pkg.get("version")
        dependencies = pkg.get("dependencies", [])
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise ManifestError("Cargo.lock package entries need a name and version")
        if not isinstance(dependencies, list) or any(not isinstance(dep, str) for dep in dependencies):
            raise ManifestError("Cargo.lock package dependencies must be strings")
        item = _component(name, version, "crates.io", manifest, "unknown", license=pkg.get("license"), dependencies=dependencies)
        if item:
            result.append(item)
    purls = {(item["name"], item.get("version")): item.get("purl") for item in result}
    for item in result:
        refs = []
        for raw in item.get("dependencies", []):
            parts = str(raw).split()
            if len(parts) >= 2:
                ref = purls.get((parts[0], parts[1]))
                if ref:
                    refs.append(ref)
        item["dependencies"] = sorted(set(refs))
    return result


PARSERS = {
    "requirements.txt": lambda b, n: parse_requirements(b.decode("utf-8-sig"), n),
    "package-lock.json": lambda b, n: parse_package_lock(json.loads(b), n),
    "pom.xml": parse_pom,
    "go.mod": lambda b, n: parse_go_mod(b.decode("utf-8-sig"), n),
    "cargo.lock": parse_cargo_lock,
}


def _parse_named(data: bytes, filename: str) -> list[dict]:
    key = PurePosixPath(filename.replace("\\", "/")).name.lower()
    if key not in PARSERS:
        raise ManifestError("Unsupported manifest. Supported files: requirements.txt, package-lock.json, pom.xml, go.mod, Cargo.lock, ZIP")
    if len(data) > MAX_TEXT_BYTES:
        raise ManifestError("Manifest exceeds the 5 MiB parser limit")
    try:
        parsed = PARSERS[key](data, key)
        if len(parsed) > MAX_COMPONENTS:
            raise ManifestError("Manifest exceeds the component count limit")
        return _deduplicate(parsed)
    except ManifestError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError, AttributeError, KeyError) as exc:
        raise ManifestError(f"Could not parse {key}") from exc


def parse_upload(filename: str, data: bytes, max_entries: int, max_expanded: int) -> list[dict]:
    if not data:
        raise ManifestError("The uploaded file is empty")
    if not filename.lower().endswith(".zip"):
        return _parse_named(data, filename)
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError) as exc:
        raise ManifestError("Invalid ZIP archive") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > max_entries:
            raise ManifestError("ZIP archive exceeds the entry count limit")
        expanded = sum(info.file_size for info in infos)
        if expanded > max_expanded:
            raise ManifestError("ZIP archive exceeds the expanded size limit")
        candidates = []
        for info in infos:
            path = info.filename.replace("\\", "/")
            posix = PurePosixPath(path)
            mode = (info.external_attr >> 16) & 0o170000
            if posix.is_absolute() or ".." in posix.parts or mode == 0o120000 or (posix.parts and ":" in posix.parts[0]) or any(ord(ch) < 32 for ch in path):
                raise ManifestError("ZIP contains an unsafe path or symbolic link")
            if info.is_dir():
                continue
            if posix.name.lower() in PARSERS:
                if info.file_size == 0:
                    raise ManifestError("ZIP contains an empty dependency manifest")
                if info.file_size > MAX_TEXT_BYTES:
                    raise ManifestError("A manifest in the ZIP exceeds the parser size limit")
                candidates.append(info)
        if not candidates:
            raise ManifestError("No supported dependency manifest found in ZIP")
        output = []
        actual_expanded = 0
        for info in candidates:
            # Read only the known manifest member. Nothing is extracted to disk.
            try:
                remaining = max_expanded - actual_expanded
                member_limit = min(MAX_TEXT_BYTES, remaining)
                if member_limit < 0:
                    raise ManifestError("ZIP archive exceeds the expanded size limit")
                with archive.open(info) as member:
                    body = member.read(member_limit + 1)
                    if len(body) > member_limit or member.read(1):
                        raise ManifestError("ZIP archive exceeds the expanded size limit")
                actual_expanded += len(body)
            except ManifestError:
                raise
            except (OSError, zipfile.BadZipFile, RuntimeError, EOFError) as exc:
                raise ManifestError("Could not safely read manifest from ZIP") from exc
            output.extend(_parse_named(body, info.filename))
            if len(output) > MAX_COMPONENTS:
                raise ManifestError("ZIP archive exceeds the component count limit")
        return _deduplicate(output)


def _deduplicate(components: list[dict]) -> list[dict]:
    seen = {}
    for item in components:
        normalized_name = item["name"].lower() if item["ecosystem"] in {"PyPI", "npm", "crates.io"} else item["name"]
        key = (item["ecosystem"], normalized_name, item.get("version"), item["manifest"])
        if key not in seen:
            seen[key] = item
        elif seen[key]["directness"] == "unknown" and item["directness"] != "unknown":
            seen[key]["directness"] = item["directness"]
    return list(seen.values())
