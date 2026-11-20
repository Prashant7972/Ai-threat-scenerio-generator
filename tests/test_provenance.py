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

    with open(atlas_file, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert data["version"] == "2026.10"
    assert data["format_version"] == "6.1.0"
    assert len(data["case_studies"]) >= 20

    with open(aiid_file, encoding="utf-8") as f:
        incidents = json.load(f)
    assert len(incidents) >= 10


def test_source_evidence_dossier():
    """Verify that authoritative claim-to-scenario source evidence is present and valid."""
    dossier_path = WORKSPACE_ROOT / "data" / "sources" / "source_evidence_dossier.json"
    assert dossier_path.exists()

    with open(dossier_path, encoding="utf-8") as f:
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

    with open(ledger_path, encoding="utf-8") as f:
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


def test_change_manager_detects_tampering_and_invalidates(tmp_path):
    """GEN 05: Verify that modifying a spec compares against reviewed hash and invalidates."""
    import shutil
    # Copy workspace structure to tmp_path
    specs_copy = tmp_path / "specs"
    shutil.copytree(WORKSPACE_ROOT / "specs", specs_copy)

    # Tamper with one spec file
    sample_spec = next(specs_copy.glob("*/*.yaml"))
    orig_text = sample_spec.read_text()
    sample_spec.write_text(orig_text + "\n# TAMPERED UNREVIEWED CHANGE\n")

    manager = ChangeManager(tmp_path)
    audit = manager.audit_change_status()
    assert audit["status"] == "FAIL"
    assert sample_spec.stem in audit["invalidations"]
    tampered_entry = next(r for r in audit["details"] if r["spec_id"] == sample_spec.stem)
    assert tampered_entry["status"] == "INVALIDATED"
    assert tampered_entry["current_sha256"] != tampered_entry["reviewed_sha256"]


def test_source_grounding_quotas_and_dual_atlas_hashes():
    """GEN 01, GEN 04: Verify source quotas and dual ATLAS hashes."""
    import hashlib
    # 1. Verify bundled ATLAS extract hash
    atlas_path = WORKSPACE_ROOT / "data" / "sources" / "ATLAS-2026.10.yaml"
    extract_sha256 = hashlib.sha256(atlas_path.read_bytes()).hexdigest()
    assert extract_sha256 == "4d08692d2881e7ba4ff4725113e25cbcd5f7f0dedad0cdd2999b34a2f61fb4ba"

    # 2. Verify dossier records both upstream canonical and local extract hashes
    dossier_path = WORKSPACE_ROOT / "data" / "sources" / "source_evidence_dossier.json"
    dossier = json.loads(dossier_path.read_text(encoding="utf-8"))
    assert dossier["atlas_release"]["canonical_upstream_asset_sha256"] == "ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d"
    assert dossier["atlas_release"]["bundled_local_extract_sha256"] == extract_sha256

    # 3. Verify quotas and claim-to-source grounding across all 20 scenario specifications
    aiid_specs = []
    aiid_incidents = set()
    atlas_technique_specs = []
    adaptation_specs = []

    for spec_file in sorted((WORKSPACE_ROOT / "specs").glob("*/*.yaml")):
        data = yaml.safe_load(spec_file.read_text())
        sid = spec_file.stem
        facts = data.get("source_facts", [])
        assert len(facts) >= 1, f"Spec {sid} must have at least one source fact"
        for f in facts:
            assert f.get("claim_id"), f"Spec {sid} fact missing claim_id"
            assert f.get("source_ref"), f"Spec {sid} fact missing source_ref"
            assert f.get("passage"), f"Spec {sid} fact missing citation passage"

        refs = {r["record_id"]: r for r in data.get("source_refs", [])}
        for f in facts:
            assert f["source_ref"] in refs, f"Spec {sid} fact references unlisted source_ref: {f['source_ref']}"

        claim_sources = {f["source_ref"] for f in facts}
        spec_aiid = [s for s in claim_sources if s.startswith("AIID")]
        if spec_aiid:
            aiid_specs.append(sid)
            aiid_incidents.update(spec_aiid)

        spec_atlas_techs = [s for s in claim_sources if s.startswith("AML.T")]
        if spec_atlas_techs or any(r.startswith("AML.T") for r in refs):
            atlas_technique_specs.append(sid)

        if data.get("origin_type") == "adaptation":
            adaptation_specs.append(sid)
            assert len(data.get("generated_assumptions", [])) >= 1, f"Adaptation {sid} requires explicit assumptions"

    # Client Quotas: >= 10 specs referencing AIID across >= 5 incidents
    assert len(aiid_specs) >= 10, f"Expected >= 10 specs referencing AIID, got {len(aiid_specs)}"
    assert len(aiid_incidents) >= 5, f"Expected >= 5 AIID incidents, got {len(aiid_incidents)}"

    # Client Quotas: >= 10 specs referencing ATLAS technique definitions
    assert len(atlas_technique_specs) >= 10, f"Expected >= 10 specs referencing ATLAS technique definitions, got {len(atlas_technique_specs)}"
    assert len(adaptation_specs) >= 10, f"Expected >= 10 adaptation specs, got {len(adaptation_specs)}"

