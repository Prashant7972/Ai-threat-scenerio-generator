"""Automated Change Classification and Test Invalidation Engine (GEN 05).

Provides dependency tracking, change classification, trial manifest invalidation,
and impacted-test scheduling whenever a scenario specification, fixture, or source changes.
"""
import hashlib
import json
from pathlib import Path
from typing import Any

from .provenance import plan_source_change, save_change_plan


class ChangeManager:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir.resolve()
        self.specs_dir = self.root_dir / "specs"
        self.ledger_path = self.specs_dir / "scenario_review_ledger.json"
        self.change_history_dir = self.root_dir / "reports" / "change_history"
        self.change_history_dir.mkdir(parents=True, exist_ok=True)

    def compute_spec_hash(self, spec_path: Path) -> str:
        return hashlib.sha256(spec_path.read_bytes()).hexdigest()

    def audit_change_status(self) -> dict[str, Any]:
        """Audit current scenario specifications against the review ledger."""
        if not self.ledger_path.exists():
            return {"status": "ERROR", "error": "Missing scenario_review_ledger.json"}

        with open(self.ledger_path, encoding="utf-8") as f:
            ledger = json.load(f)

        ledger_specs = {s["spec_id"]: s for s in ledger.get("scenarios", [])}
        audit_results: list[dict[str, Any]] = []
        invalidations: list[str] = []

        for yaml_path in sorted(self.specs_dir.glob("*/*.yaml")):
            spec_id = yaml_path.stem
            current_hash = self.compute_spec_hash(yaml_path)
            entry = ledger_specs.get(spec_id)

            if not entry:
                audit_results.append({
                    "spec_id": spec_id,
                    "status": "UNTRACKED",
                    "file": str(yaml_path.relative_to(self.root_dir))
                })
                invalidations.append(spec_id)
                continue

            reviewed_hash = entry.get("reviewed_sha256")
            if not reviewed_hash or current_hash != reviewed_hash:
                audit_results.append({
                    "spec_id": spec_id,
                    "status": "INVALIDATED",
                    "current_sha256": current_hash,
                    "reviewed_sha256": reviewed_hash,
                    "review_status": entry.get("review", {}).get("status", "unknown"),
                    "file": str(yaml_path.relative_to(self.root_dir))
                })
                invalidations.append(spec_id)
            else:
                audit_results.append({
                    "spec_id": spec_id,
                    "status": "VERIFIED_UNCHANGED",
                    "current_sha256": current_hash,
                    "reviewed_sha256": reviewed_hash,
                    "review_status": entry.get("review", {}).get("status", "unknown")
                })

        overall_status = "PASS" if not invalidations and len(audit_results) == 20 else "FAIL"
        return {
            "status": overall_status,
            "total_specs": len(audit_results),
            "verified_specs": len([r for r in audit_results if r["status"] == "VERIFIED_UNCHANGED"]),
            "invalidations": invalidations,
            "details": audit_results
        }

    def process_specification_diff(
        self,
        spec_id: str,
        old_spec: dict[str, Any],
        new_spec: dict[str, Any] | None,
        associated_packages: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Classify a specification diff, generate an invalidation plan, and record to append-only history."""
        plan = plan_source_change(old_spec, new_spec, associated_packages)
        saved_path = save_change_plan(plan, self.change_history_dir)
        plan["saved_plan_file"] = str(saved_path)
        return plan

    def process_mechanism_or_mitigation_change(
        self,
        spec_id: str,
        old_spec: dict[str, Any],
        new_spec: dict[str, Any],
        associated_packages: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Classify a mechanism or mitigation change, invalidate affected packages, create successor candidates, and log impacted test runs."""
        return self.process_specification_diff(spec_id, old_spec, new_spec, associated_packages)

    def process_withdrawal(
        self,
        spec_id: str,
        old_spec: dict[str, Any],
        associated_packages: list[dict[str, Any]],
        reason: str = "Withdrawn by security analyst",
    ) -> dict[str, Any]:
        """Process scenario withdrawal: preserves package history, creates withdrawal change plan, and triggers analyst review."""
        withdrawn_spec = dict(old_spec)
        withdrawn_spec["withdrawn"] = True
        withdrawn_spec["withdrawal_reason"] = reason
        return self.process_specification_diff(spec_id, old_spec, withdrawn_spec, associated_packages)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Scenario Change Management & Invalidation Engine (GEN 05)")
    parser.add_argument("--check", action="store_true", help="Audit scenario specs against ledger")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent.parent
    manager = ChangeManager(root)
    result = manager.audit_change_status()
    if args.check:
        print(f"Audit Status: {result['status']} ({result['verified_specs']}/{result['total_specs']} verified)")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
