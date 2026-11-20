"""Package source and retained evidence without credentials, caches or Git metadata."""
import hashlib
import json
import re
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT.parent / "ai-threat-scenario-generator-release-candidate.zip"
DOWNLOADS_OUTPUT = Path("/home/prashant/Downloads/ai-threat-scenario-generator-release-candidate.zip")
BRAIN_OUTPUT = Path("/home/prashant/.gemini/antigravity/brain/d85a6bac-64da-4f4b-8e33-8050cf9cda49/ai-threat-scenario-generator.zip")

INCLUDE = {
    "src",
    "tests",
    "docs",
    "data",
    "specs",
    "reports",
    "config",
    "deployment",
    "ui",
    "scripts",
    "fixtures",
    "packages",
    "guidelines",
}
ROOT_FILES = {
    "README.md",
    "DELIVERY_STATUS.md",
    "requirements.txt",
    "pytest.ini",
    "Dockerfile",
    "docker-compose.yml",
    "ruff.toml",
}
EXCLUDE = {
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".git",
    ".pytest_cache",
    ".ruff_cache",
    "secrets",
    ".test_session",
}

files = []
for path in sorted(ROOT.rglob("*")):
    rel = path.relative_to(ROOT)
    if not path.is_file() or path.is_symlink():
        continue
    if rel.parts[0] not in INCLUDE and str(rel) not in ROOT_FILES:
        continue
    if any(part in EXCLUDE or part.startswith(".env") for part in rel.parts):
        continue
    if path.suffix in {".pyc", ".pyo", ".pem", ".key"}:
        continue
    raw = path.read_bytes()
    # Abort without printing potential credentials.
    if re.search(rb"AIza[0-9A-Za-z_-]{35}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", raw):
        raise RuntimeError("Credential-like material detected; inspect locally before packaging")
    files.append((rel.as_posix(), raw))

manifest = {
    "delivery_status": "audited_release_candidate_verified",
    "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in files},
}

manifest_json = json.dumps(manifest, indent=2) + "\n"

# Write manifest to repository root
(ROOT / "PACKAGE_MANIFEST.json").write_text(manifest_json, encoding="utf-8")

# Build primary ZIP archive
with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED) as archive:
    for name, raw in files:
        archive.writestr("ai-threat-scenario-generator/" + name, raw)
    archive.writestr("ai-threat-scenario-generator/PACKAGE_MANIFEST.json", manifest_json)

# Validate archive integrity
with zipfile.ZipFile(OUTPUT) as archive:
    assert archive.testzip() is None
    for name, expected in manifest["files"].items():
        assert hashlib.sha256(archive.read("ai-threat-scenario-generator/" + name)).hexdigest() == expected

# Copy to deliverable locations
if DOWNLOADS_OUTPUT.parent.exists():
    shutil.copy2(OUTPUT, DOWNLOADS_OUTPUT)

if BRAIN_OUTPUT.parent.exists():
    shutil.copy2(OUTPUT, BRAIN_OUTPUT)

print(
    json.dumps(
        {
            "archive": str(OUTPUT),
            "downloads_archive": str(DOWNLOADS_OUTPUT),
            "brain_archive": str(BRAIN_OUTPUT),
            "files": len(files) + 1,
            "bytes": OUTPUT.stat().st_size,
            "sha256": hashlib.sha256(OUTPUT.read_bytes()).hexdigest(),
        },
        indent=2,
    )
)
