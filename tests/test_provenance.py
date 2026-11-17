"""
Provenance and upstream source intelligence tests.
"""
import json
from pathlib import Path

import yaml

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent

def test_atlas_and_aiid_sources():
    atlas_file = WORKSPACE_ROOT / "data" / "sources" / "ATLAS-2026.10.yaml"
    aiid_file = WORKSPACE_ROOT / "data" / "sources" / "aiid_incidents.json"
    assert atlas_file.exists()
    assert aiid_file.exists()

    with open(atlas_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert data["version"] == "2026.10"
    assert data["format_version"] == "6.1.0"
    assert len(data["case_studies"]) >= 20

    with open(aiid_file, "r", encoding="utf-8") as f:
        incidents = json.load(f)
    assert len(incidents) >= 10
