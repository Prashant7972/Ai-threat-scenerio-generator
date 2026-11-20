"""
Priority 1 Verification (GEN 02, EVAL 03):
Verify that the release manifest (config/release_packages.json) pins exactly 20 approved package hashes,
and that two independent extractions produce the exact identical 1,040-attempt plan against the same package hashes,
regardless of filesystem modification times (mtimes).
"""
import json
import os
import shutil
import time
from pathlib import Path

from src.proof.evaluator.compiled_suite import plan_packages
from src.proof.evaluator.package_runner import load_package

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


def test_release_packages_manifest_integrity():
    manifest_file = WORKSPACE_ROOT / "config" / "release_packages.json"
    assert manifest_file.exists(), "Release manifest config/release_packages.json must exist"

    manifest = json.loads(manifest_file.read_text())
    assert manifest["release_version"] == "1.0.0"
    assert manifest["review_status"] == "APPROVED_FOR_RELEASE"
    assert manifest["reviewer"] == "Juby"
    assert manifest["total_scenarios"] == 20
    assert len(manifest["approved_package_hashes"]) == 20
    assert len(manifest["packages"]) == 20

    packages_dir = WORKSPACE_ROOT / "packages"
    approved_hashes = set(manifest["approved_package_hashes"])
    assert len(approved_hashes) == 20

    # Verify that each approved package exists, loads cleanly, and has 18 records
    for pkg_meta in manifest["packages"]:
        pkg_hash = pkg_meta["package_hash"]
        assert pkg_hash in approved_hashes
        pkg_dir = packages_dir / pkg_hash
        assert pkg_dir.exists(), f"Approved package directory {pkg_hash} must exist"

        spec, profile, records = load_package(pkg_dir)
        assert spec.spec_id == pkg_meta["spec_id"]
        assert spec.scenario_id == pkg_meta["scenario_id"]
        assert profile.id == pkg_meta["target_profile"]
        assert len(records) == 18
        assert pkg_meta["status"] == "APPROVED_FOR_RELEASE"


def test_two_clean_extractions_produce_identical_1040_plan(tmp_path):
    """Verify that two clean extractions with differing mtimes produce the identical 1,040 plan."""
    manifest_file = WORKSPACE_ROOT / "config" / "release_packages.json"
    manifest = json.loads(manifest_file.read_text())
    approved_hashes = manifest["approved_package_hashes"]

    # Extraction A
    dir_a = tmp_path / "extraction_A"
    dir_a_packages = dir_a / "packages"
    dir_a_packages.mkdir(parents=True)
    dir_a_config = dir_a / "config"
    dir_a_config.mkdir(parents=True)
    shutil.copy(manifest_file, dir_a_config / "release_packages.json")

    for h in approved_hashes:
        shutil.copytree(WORKSPACE_ROOT / "packages" / h, dir_a_packages / h)

    # Extraction B
    dir_b = tmp_path / "extraction_B"
    dir_b_packages = dir_b / "packages"
    dir_b_packages.mkdir(parents=True)
    dir_b_config = dir_b / "config"
    dir_b_config.mkdir(parents=True)
    shutil.copy(manifest_file, dir_b_config / "release_packages.json")

    for h in approved_hashes:
        shutil.copytree(WORKSPACE_ROOT / "packages" / h, dir_b_packages / h)

    # Scramble mtimes in Extraction B to verify mtime-independence
    now = time.time()
    for idx, h in enumerate(reversed(approved_hashes)):
        pkg_dir = dir_b_packages / h
        # Set completely arbitrary, reversed mtimes
        os.utime(pkg_dir, (now - idx * 3600, now - idx * 3600))

    # Resolve packages using the release manifest for both
    manifest_a = json.loads((dir_a_config / "release_packages.json").read_text())
    packages_a = [dir_a_packages / h for h in manifest_a["approved_package_hashes"]]
    packages_a.sort(key=lambda p: str(p.name))

    manifest_b = json.loads((dir_b_config / "release_packages.json").read_text())
    packages_b = [dir_b_packages / h for h in manifest_b["approved_package_hashes"]]
    packages_b.sort(key=lambda p: str(p.name))

    plan_a = plan_packages(packages_a)
    plan_b = plan_packages(packages_b)

    assert len(plan_a) == 1040
    assert len(plan_b) == 1040

    # Assert exact byte-for-byte plan equality across attempts
    for attempt_a, attempt_b in zip(plan_a, plan_b, strict=True):
        assert attempt_a["attempt_number"] == attempt_b["attempt_number"]
        assert attempt_a["package_sha256"] == attempt_b["package_sha256"]
        assert attempt_a["scenario_id"] == attempt_b["scenario_id"]
        assert attempt_a["record_id"] == attempt_b["record_id"]
        assert attempt_a["record_type"] == attempt_b["record_type"]
        assert attempt_a["canonical"] == attempt_b["canonical"]
        assert attempt_a["build"] == attempt_b["build"]
        assert attempt_a["repetition"] == attempt_b["repetition"]
