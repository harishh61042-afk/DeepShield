import uuid
from datetime import datetime, timezone


def build_sbom(project_name: str, components: list[dict]) -> dict:
    merged = {}
    for item in components:
        ref = item.get("purl") or f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, '|'.join((item['ecosystem'], item['name'], item.get('version') or '', item['manifest'])))}"
        if ref not in merged:
            merged[ref] = {**item, "_ref": ref, "_manifests": {item.get("manifest", "")}}
        else:
            merged[ref]["_manifests"].add(item.get("manifest", ""))
            merged[ref]["dependencies"] = sorted(set(merged[ref].get("dependencies", [])) | set(item.get("dependencies", [])))
    normalized = list(merged.values())
    records = []
    dependencies = []
    root_ref = f"urn:uuid:{uuid.uuid4()}"
    root_dependencies = []
    component_refs = {item["_ref"] for item in normalized}
    for item in normalized:
        ref = item["_ref"]
        row = {"type": "library", "bom-ref": ref, "name": item["name"]}
        if item.get("purl"):
            row["purl"] = item["purl"]
        if item.get("version"):
            row["version"] = item["version"]
        if item.get("license"):
            row["licenses"] = [{"license": {"name": item["license"]}}]
        row["properties"] = [
            {"name": "depshield:ecosystem", "value": item.get("ecosystem", "unknown")},
            {"name": "depshield:resolution", "value": item.get("resolution", "unknown")},
            {"name": "depshield:directness", "value": item.get("directness", "unknown")},
            {"name": "depshield:manifest", "value": ", ".join(sorted(item["_manifests"]))},
        ]
        records.append(row)
        children = [child for child in item.get("dependencies", []) if child in component_refs]
        dependencies.append({"ref": ref, "dependsOn": sorted(set(children))})
        if item.get("directness") == "direct":
            root_dependencies.append(ref)
    dependencies.insert(0, {"ref": root_ref, "dependsOn": sorted(set(root_dependencies))})
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(), "component": {"type": "application", "bom-ref": root_ref, "name": project_name}},
        "components": records,
        "dependencies": dependencies,
    }
    refs = [c["bom-ref"] for c in bom["components"]]
    if len(refs) != len(set(refs)) or bom["metadata"]["component"]["bom-ref"] in refs:
        raise ValueError("Generated CycloneDX component references are not unique")
    return bom
