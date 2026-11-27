import io
import struct
import zipfile

import pytest

from app.parsers.dependencies import ManifestError, parse_cargo_lock, parse_go_mod, parse_package_lock, parse_pom, parse_requirements, parse_upload


def test_requirements_distinguishes_exact_pin_from_range():
    rows = parse_requirements("Django==4.2.4\nrequests>=2.31,<3\n")
    assert rows[0]["version"] == "4.2.4"
    assert rows[0]["resolution"] == "declared_unverified"
    assert rows[1]["version"] is None
    assert rows[1]["resolution"] == "declared_unverified"


def test_package_lock_v3_keeps_nested_package_transitive():
    lock = {"lockfileVersion": 3, "packages": {"": {"dependencies": {"left-pad": "1.0.0"}}, "node_modules/left-pad": {"version": "1.0.0"}, "node_modules/parent/node_modules/left-pad": {"version": "2.0.0"}}}
    rows = parse_package_lock(lock)
    assert [row["directness"] for row in rows] == ["direct", "transitive"]
    assert rows[0]["purl"] == "pkg:npm/left-pad@1.0.0"


def test_maven_resolves_declared_properties_without_network():
    xml = b"""<project><properties><logging.version>2.14.1</logging.version></properties><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${logging.version}</version></dependency></dependencies></project>"""
    row = parse_pom(xml)[0]
    assert row["version"] == "2.14.1"
    assert row["directness"] == "direct"


def test_go_mod_marks_directness_and_version_unverified():
    rows = parse_go_mod("require (\n golang.org/x/text v0.3.2\n golang.org/x/net v0.1.0 // indirect\n)\n")
    assert rows[0]["directness"] == "direct"
    assert rows[1]["directness"] == "transitive"
    assert rows[0]["resolution"] == "declared_unverified"
    assert rows[0]["purl"] == "pkg:golang/golang.org/x/text@v0.3.2"


def test_malformed_dependency_shapes_raise_manifest_errors():
    with pytest.raises(ManifestError, match="dependencies must be an object"):
        parse_package_lock({"lockfileVersion": 3, "packages": {"node_modules/x": {"version": "1.0.0", "dependencies": ["bad"]}}})
    with pytest.raises(ManifestError, match="package field must be an array"):
        parse_cargo_lock(b"package=5\n")
    with pytest.raises(ManifestError, match="malformed require"):
        parse_go_mod("require broken-entry\n")


def test_zip_rejects_oversized_manifest_instead_of_skipping_it():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("requirements.txt", b" " * (5 * 1024 * 1024 + 1))
        archive.writestr("package-lock.json", b'{"lockfileVersion":3,"packages":{}}')
    with pytest.raises(ManifestError, match="exceeds the parser size limit"):
        parse_upload("demo.zip", stream.getvalue(), 100, 50 * 1024 * 1024)


def test_zip_actual_expansion_is_bounded_even_when_metadata_lies():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("requirements.txt", b" " * (6 * 1024 * 1024))
    payload = bytearray(stream.getvalue())
    local_header = payload.index(b"PK\x03\x04")
    central_header = payload.index(b"PK\x01\x02")
    struct.pack_into("<I", payload, local_header + 22, 1)
    struct.pack_into("<I", payload, central_header + 24, 1)

    with pytest.raises(ManifestError):
        parse_upload("demo.zip", bytes(payload), 100, 50 * 1024 * 1024)


def test_cargo_lock_version_and_unknown_directness():
    row = parse_cargo_lock(b'[[package]]\nname="time"\nversion="0.2.22"\n')[0]
    assert row["purl"] == "pkg:cargo/time@0.2.22"
    assert row["directness"] == "unknown"


def test_zip_slip_is_rejected_without_extraction():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("../requirements.txt", "Django==4.2.4")
    with pytest.raises(ManifestError, match="unsafe path"):
        parse_upload("demo.zip", stream.getvalue(), 100, 100_000)


def test_zip_size_and_entry_limits_are_enforced():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("requirements.txt", "requests==2.31.0")
    with pytest.raises(ManifestError, match="entry count"):
        parse_upload("demo.zip", stream.getvalue(), 0, 100_000)
