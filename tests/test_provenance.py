"""
Provenance, upstream source intelligence, and change management tests (GEN 01, GEN 05).
"""
import json
from pathlib import Path

import yaml
from src.generator.change_manager import ChangeManager

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


def test_source_evidence_dossier():
    """Verify that authoritative claim-to-scenario source evidence is present and valid."""
    dossier_path = WORKSPACE_ROOT / "data" / "sources" / "source_evidence_dossier.json"
    assert dossier_path.exists()

    with open(dossier_path, "r", encoding="utf-8") as f:
        dossier = json.load(f)

    assert dossier["atlas_release"]["version"] == "v2026.10"
    assert len(dossier["verified_incidents"]) >= 10
    assert len(dossier["atlas_technique_catalog"]) >= 24

    # Ensure all 5 primary verified incidents are documented
    incident_ids = {inc["incident_id"] for inc in dossier["verified_incidents"]}
    for req_id in ["AIID-INC-0352", "AIID-INC-0420", "AIID-INC-0473", "AIID-INC-1497", "AIID-INC-1680"]:
        assert req_id in incident_ids


def test_scenario_review_ledger():
    """Verify that all 20 scenarios have formal review records in the ledger."""
    ledger_path = WORKSPACE_ROOT / "specs" / "scenario_review_ledger.json"
    assert ledger_path.exists()

    with open(ledger_path, "r", encoding="utf-8") as f:
        ledger = json.load(f)

    assert len(ledger["scenarios"]) == 20
    for s in ledger["scenarios"]:
        assert s["review"]["status"] == "approved"
        assert s["review"]["checklist"]["independent_stream_assertions_complete"] is True


def test_change_manager_audit():
    """Verify the automated change manager audits all 20 specs without invalidations."""
    manager = ChangeManager(WORKSPACE_ROOT)
    audit = manager.audit_change_status()
    assert audit["status"] == "PASS"
    assert audit["total_specs"] == 20
    assert audit["verified_specs"] == 20
    assert len(audit["invalidations"]) == 0
