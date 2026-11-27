"""Build a clean, verifiable source archive in output/."""
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "output" / "DepShield_Complete_Project.zip"
EXCLUDED_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__", ".pytest_cache", ".ruff_cache", "coverage", "test-results", "playwright-report"}
EXCLUDED_NAMES = {".env", ".npmrc", ".pypirc", "credentials.json", "id_rsa", "id_ed25519", "DepShield_Complete_Project.zip"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".log", ".sqlite", ".db", ".pem", ".key", ".p12", ".pfx", ".secret"}


def should_include(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if any(part in EXCLUDED_DIRS for part in relative.parts):
        return False
    if path.name in EXCLUDED_NAMES or path.suffix.lower() in EXCLUDED_SUFFIXES:
        return False
    if path.name.startswith(".env.") and path.name != ".env.example":
        return False
    return path.is_file()


def main():
    DEST.parent.mkdir(parents=True, exist_ok=True)
    included = sorted(path for path in ROOT.rglob("*") if should_include(path) and not path.is_relative_to(DEST.parent))
    with ZipFile(DEST, "w", compression=ZIP_DEFLATED, compresslevel=8) as archive:
        for path in included:
            archive.write(path, path.relative_to(ROOT).as_posix())
    with ZipFile(DEST, "r") as archive:
        bad = archive.testzip()
        names = archive.namelist()
        if bad:
            raise SystemExit(f"Archive integrity check failed at {bad}")
        if any(
            any(part == ".env" or (part.startswith(".env.") and part != ".env.example") for part in Path(name).parts)
            or any(part in EXCLUDED_DIRS for part in Path(name).parts)
            or name.endswith((".pem", ".key", ".p12", ".pfx", ".secret"))
            for name in names
        ):
            raise SystemExit("Archive includes a forbidden path")
    print(f"Created {DEST}")
    print(f"Included {len(included)} files; integrity check passed.")


if __name__ == "__main__":
    main()
