from app.sbom.cyclonedx import build_sbom


def test_cyclonedx_uses_named_license_and_omits_missing_purl():
    bom = build_sbom(
        "Payments API",
        [
            {
                "name": "known-package",
                "version": "1.2.3",
                "ecosystem": "npm",
                "purl": "pkg:npm/known-package@1.2.3",
                "directness": "direct",
                "resolution": "resolved",
                "manifest": "package-lock.json",
                "license": "MIT OR Apache-2.0",
                "dependencies": [],
            },
            {
                "name": "unknown-package",
                "version": None,
                "ecosystem": "PyPI",
                "purl": None,
                "directness": "unknown",
                "resolution": "declared_unverified",
                "manifest": "requirements.txt",
                "license": None,
                "dependencies": [],
            },
        ],
    )

    components = {component["name"]: component for component in bom["components"]}
    assert components["known-package"]["licenses"] == [{"license": {"name": "MIT OR Apache-2.0"}}]
    assert "purl" not in components["unknown-package"]
    assert len({component["bom-ref"] for component in bom["components"]}) == 2
