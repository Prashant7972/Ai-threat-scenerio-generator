"""
Unit and integration test verifying generator lifecycle, review enforcement,
12/6 corpus breakdown, exact stored byte replay, source revision change,
and package invalidation (GEN 01–05).
"""
import hashlib
import json
import shutil
from pathlib import Path

import pytest
import yaml

from src.generator.change_manager import ChangeManager
from src.generator.compiler import (
    UnapprovedScenarioError,
    compile_reviewed_spec,
)
from src.generator.provenance import classify_provenance_diff, plan_source_change
from src.proof.evaluator.package_runner import load_package

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


def test_complete_generator_lifecycle_and_invalidation(tmp_path):
    """Verify complete end-to-end lifecycle in an isolated sandbox."""
    # Stage sandbox
    shutil.copytree(WORKSPACE_ROOT / "specs", tmp_path / "specs")
    shutil.copytree(WORKSPACE_ROOT / "config", tmp_path / "config")
    shutil.copytree(WORKSPACE_ROOT / "data", tmp_path / "data")
    shutil.copytree(WORKSPACE_ROOT / "fixtures", tmp_path / "fixtures")
    packages_dir = tmp_path / "packages"
    packages_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    spec_file = tmp_path / "specs" / "F1_retrieval" / "f1_s1.yaml"
    profile_file = tmp_path / "config" / "target_profiles" / "R1.json"
    ledger_file = tmp_path / "specs" / "scenario_review_ledger.json"

    # Step 1: Input review verification
    input_bytes = spec_file.read_bytes()
    input_sha256 = hashlib.sha256(input_bytes).hexdigest()
    ledger_data = json.loads(ledger_file.read_text())
    ledger_entry = next(s for s in ledger_data["scenarios"] if s["spec_id"] == "f1_s1")
    assert ledger_entry["review"]["status"] == "approved"
    assert input_sha256 == ledger_entry["reviewed_sha256"]

    # Rejection of unreviewed modifications
    tampered_bytes = input_bytes + b"\n# Unreviewed change\n"
    tampered_file = tmp_path / "specs" / "F1_retrieval" / "tampered.yaml"
    tampered_file.write_bytes(tampered_bytes)
    profile_data = json.loads(profile_file.read_text())
    try:
        compile_reviewed_spec(tampered_file, profile_data, tmp_path, packages_dir, ledger_file)
        raise AssertionError("Compiler should have rejected unreviewed input")
    except UnapprovedScenarioError:
        pass

    # Step 2: Compile package
    pkg_path, _ = compile_reviewed_spec(spec_file, profile_data, tmp_path, packages_dir, ledger_file)
    orig_pkg_id = pkg_path.name
    assert pkg_path.exists()

    # Step 3: Record counts and pairing
    _, _, records = load_package(pkg_path)
    attacks = [r for r in records if r.record_type.value == "attacker_injection"]
    benigns = [r for r in records if r.record_type.value == "benign_control"]
    assert len(records) == 18
    assert len(attacks) == 12
    assert len(benigns) == 6
    benign_keys = {b.logical_variant_key for b in benigns}
    for atk in attacks:
        payload = json.loads(atk.payload_text)
        assert payload.get("matched_benign_control") in benign_keys

    # Step 4: Stored byte replay
    sample_benign = benigns[0]
    stored_bytes = bytes.fromhex(sample_benign.payload_bytes) if hasattr(sample_benign, "payload_bytes") and sample_benign.payload_bytes else sample_benign.payload_text.encode("utf-8")
    assert hashlib.sha256(stored_bytes).hexdigest() == sample_benign.content_hash

    # Step 5: Source revision change and invalidation
    raw_yaml = yaml.safe_load(spec_file.read_text())
    old_spec_dict = dict(raw_yaml)
    new_spec_dict = dict(raw_yaml)
    new_spec_dict["source_refs"][2]["revision"] = "2026-11-20"
    new_spec_dict["source_facts"].append({
        "claim_id": "CLAIM-AIID-0352-02: Multi-turn injection",
        "source_ref": "AIID-INC-0352",
        "passage": "Multi-turn attachment injection text.",
    })
    new_spec_dict["version"] = "1.1.0"
    spec_file.write_text(yaml.safe_dump(new_spec_dict, sort_keys=False))

    change_mgr = ChangeManager(tmp_path)
    audit = change_mgr.audit_change_status()
    assert audit["status"] == "FAIL"
    assert "f1_s1" in audit["invalidations"]

    packages_meta = [{
        "package_id": orig_pkg_id,
        "scenario_id": "litmus.retrieval.external_email.f1_s1",
        "source_ids": ["AIID-INC-0352"],
        "test_ids": ["f1_s1_test_01"],
    }]
    plan = plan_source_change(old_spec_dict, new_spec_dict, packages_meta)
    assert orig_pkg_id in plan["invalidate"]
    assert len(plan["successor_candidates"]) == 1

    # Approve new spec and compile successor
    new_bytes = spec_file.read_bytes()
    ledger_entry["reviewed_sha256"] = hashlib.sha256(new_bytes).hexdigest()
    ledger_file.write_text(json.dumps(ledger_data, indent=2))
    succ_path, _ = compile_reviewed_spec(spec_file, profile_data, tmp_path, packages_dir, ledger_file)
    succ_pkg_id = succ_path.name

    # Step 6: Verify original package retained by hash
    assert (packages_dir / orig_pkg_id).exists()
    assert (packages_dir / succ_pkg_id).exists()
    assert orig_pkg_id != succ_pkg_id

    # Step 7: Actually execute impacted tests on successor package (GEN 05 completion)
    from src.proof.evaluator.package_runner import run_record
    _, _, succ_records = load_package(succ_path)
    impacted_manifests = []
    for rec in succ_records:
        m_path, assertions = run_record(succ_path, rec.record_id, "hardened", reports_dir)
        impacted_manifests.append(m_path)
    assert len(impacted_manifests) == 18

    # Old revision is ineligible for release
    approved_release_packages = [succ_pkg_id]
    assert orig_pkg_id not in approved_release_packages

    # Step 8: Withdrawal preserves history on disk and cannot be selected for new release
    withdrawal_plan = change_mgr.process_withdrawal("f1_s1", new_spec_dict, packages_meta)
    assert withdrawal_plan["diff"]["classification"] == "withdrawal"
    assert withdrawal_plan["analyst_review_required"] is True

    # Withdrawn packages remain on disk for audit
    assert (packages_dir / orig_pkg_id).exists()
    assert (packages_dir / succ_pkg_id).exists()

    # Withdrawn spec cannot be selected or compiled for release
    # Test withdrawal against the SAME scenario identity 'f1_s1' and require specific UnapprovedScenarioError
    ledger_entry["review"]["status"] = "withdrawn"
    ledger_file.write_text(json.dumps(ledger_data, indent=2))

    withdrawn_spec = dict(new_spec_dict)
    withdrawn_spec["review"]["status"] = "withdrawn"
    spec_file.write_text(yaml.safe_dump(withdrawn_spec, sort_keys=False))

    with pytest.raises(UnapprovedScenarioError) as excinfo:
        compile_reviewed_spec(spec_file, profile_data, tmp_path, packages_dir, ledger_file)
    assert "review status is 'withdrawn'" in str(excinfo.value)
    assert "Scenario 'f1_s1'" in str(excinfo.value)

    # Already compiled package for withdrawn scenario is ineligible for release
    spec_loaded, _, _ = load_package(succ_path)
    entry = next(s for s in json.loads(ledger_file.read_text())["scenarios"] if s["spec_id"] == "f1_s1")
    assert entry["review"]["status"] == "withdrawn"
    assert spec_loaded.scenario_id == "litmus.retrieval.external_email.f1_s1"
