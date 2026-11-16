"""Explicit-input compiler. Source approval is supplied by an analyst, never inferred.

This validates bindings and stored evidence, not the truth of a source claim.
The legacy catalog remains available only as an unverified prototype.
"""
from datetime import datetime
from pathlib import Path
import hashlib
import json
import shutil
import tempfile
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .contract import MinimumScenarioContract, InjectionSurface
from .harness_generator import SafeHarnessPackage
from .boundary_variants import materialize_boundary_records, PARAMETER_SCHEMA


class TargetProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    capabilities: list[str]
    surfaces: dict[InjectionSurface, list[str]]
    predicates: dict[str, bool]
    builds: dict[str, str]


class ScenarioSpec(MinimumScenarioContract):
    model_config = ConfigDict(extra="forbid")
    workflow_stages: list[str] = Field(min_length=1)
    trust_boundary: str = Field(min_length=1)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode()


def local_bytes(root: Path, uri: str) -> bytes:
    """Only local files below the input root; no URLs, traversal or escaping symlinks."""
    path = (root / uri).resolve()
    if Path(uri).is_absolute() or ".." in Path(uri).parts or ":" in uri or not path.is_relative_to(root.resolve()):
        raise ValueError(f"Fixture/evidence must be local to the input directory: {uri}")
    if not path.is_file():
        raise ValueError(f"Missing fixture/evidence: {uri}")
    return path.read_bytes()


def compile_pattern(pattern: dict, profile_data: dict, root: Path) -> tuple[ScenarioSpec, dict]:
    """Compile {scenario, evidence} against one exact versioned target profile.

    Evidence entries bind record_id/revision/claim_ids to a local snapshot hash.
    A review decision is explicit input; this function does not create approval.
    """
    if set(pattern) != {"scenario", "evidence"}:
        raise ValueError("Pattern requires exactly scenario and evidence")
    raw = pattern["scenario"]
    required = set(MinimumScenarioContract.model_fields) - {"injection_surface"}
    missing = required - raw.keys()
    if missing:
        raise ValueError(f"Missing scenario inputs: {sorted(missing)}")
    spec = ScenarioSpec.model_validate(raw)
    profile = TargetProfile.model_validate(profile_data)
    if spec.target_profile.model_dump() != {"id": profile.id, "version": profile.version}:
        raise ValueError("TargetProfile id/version mismatch")
    if spec.review.status != "approved" or not spec.review.reviewer.strip():
        raise ValueError("An explicitly approved pattern with a named reviewer is required")
    stamp = datetime.fromisoformat(spec.review.timestamp.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("Review timestamp must include a timezone")
    for name in ("scenario_id", "version", "legitimate_goal", "attacker_goal", "trust_boundary", "severity_rationale"):
        if not getattr(spec, name).strip():
            raise ValueError(f"Empty required input: {name}")
    if not all(s.strip() for s in spec.workflow_stages):
        raise ValueError("Empty workflow stage")
    if not spec.preconditions or any(profile.predicates.get(p) is not True for p in spec.preconditions):
        raise ValueError("Unsupported or unsatisfied precondition")
    allowed = profile.surfaces.get(spec.injection_surface)
    if not allowed or not spec.allowed_mutation_scope or not set(spec.allowed_mutation_scope) <= set(allowed):
        raise ValueError("Unsupported surface or mutation scope")
    if spec.attacker_access.surface != spec.injection_surface.value:
        raise ValueError("Attacker access surface must match injection_surface")
    if set(profile.builds) != {"vulnerable", "hardened"} or any(
        len(v) != 71 or not v.startswith("sha256:") or any(c not in "0123456789abcdef" for c in v[7:])
        for v in profile.builds.values()
    ):
        raise ValueError("Both target builds require sha256 content pins")
    if not spec.source_refs or not spec.source_facts:
        raise ValueError("Source references and claims are required")
    evidence = pattern["evidence"]
    indexed = {(e["record_id"], e["revision"]): e for e in evidence}
    if len(indexed) != len(evidence):
        raise ValueError("Duplicate evidence source revision")
    claims = set()
    for ref in spec.source_refs:
        item = indexed.get((ref.record_id, ref.revision))
        if not item or item.get("locator") != ref.locator:
            raise ValueError(f"Missing matching source evidence: {ref.record_id}")
        if digest(local_bytes(root, item["snapshot_uri"])) != item["sha256"]:
            raise ValueError("Source snapshot hash mismatch")
        claims.update(item["claim_ids"])
    if not {f.claim_id for f in spec.source_facts} <= claims:
        raise ValueError("Source facts have no matching evidence claim")
    if spec.origin_type.value == "adaptation" and not spec.generated_assumptions:
        raise ValueError("Adaptations require explicit generated assumptions")
    if not spec.fixtures:
        raise ValueError("Fixtures are required")
    for fixture in spec.fixtures:
        if digest(local_bytes(root, fixture.uri)) != fixture.sha256:
            raise ValueError(f"Fixture hash mismatch: {fixture.uri}")
    if spec.benign_control.fixture_ref not in {f.uri for f in spec.fixtures}:
        raise ValueError("Benign fixture must be included among hashed fixtures")
    harness = SafeHarnessPackage(spec)
    harness.negotiate_capabilities(profile.capabilities)
    config = harness.generate_harness_config()
    config.update(target_profile=profile.model_dump(mode="json"),
                  injection_surface=spec.injection_surface.value,
                  workflow_stages=spec.workflow_stages, trust_boundary=spec.trust_boundary)
    return spec, config


def build_package(pattern: dict, profile: dict, root: Path, output: Path) -> Path:
    """Produce a content-addressed package without running generated text as code.

    Existing package bytes are verified, never replaced. This exports candidate
    variants; boundary-coverage review and model trials are separate release gates.
    """
    spec, harness = compile_pattern(pattern, profile, root)
    records = materialize_boundary_records(spec)
    files = {
        "scenario.json": canonical_bytes(spec.model_dump(mode="json")),
        "target_profile.json": canonical_bytes(profile),
        "pattern.json": canonical_bytes(pattern),
        "harness.json": canonical_bytes(harness),
        "corpus.jsonl": b"".join(canonical_bytes(r.model_dump(mode="json")).replace(b"\n", b"") + b"\n" for r in records),
    }
    for name in ("compiler.py", "contract.py", "mutations.py", "snapshot.py", "harness_generator.py", "boundary_variants.py"):
        files["generator/" + name] = Path(__file__).with_name(name).read_bytes()
    files["generator.parameters.schema.json"] = canonical_bytes(PARAMETER_SCHEMA)
    files["scenario.schema.json"] = canonical_bytes(ScenarioSpec.model_json_schema())
    files["target_profile.schema.json"] = canonical_bytes(TargetProfile.model_json_schema())
    for uri in {f.uri for f in spec.fixtures} | {e["snapshot_uri"] for e in pattern["evidence"]}:
        files["inputs/" + Path(uri).as_posix()] = local_bytes(root, uri)
    manifest = {name: digest(data) for name, data in files.items()}
    files["manifest.json"] = canonical_bytes(manifest)
    package_id = digest(files["manifest.json"])
    output.mkdir(parents=True, exist_ok=True)
    destination = output / package_id
    if destination.exists():
        actual_files = {str(p.relative_to(destination)) for p in destination.rglob('*') if p.is_file()}
        if actual_files != set(files):
            raise ValueError("Cached package file inventory was modified")
        if any(not (destination / n).is_file() or (destination / n).read_bytes() != data for n, data in files.items()):
            raise ValueError("Cached package was modified; refusing to overwrite")
        return destination
    staging = Path(tempfile.mkdtemp(prefix=".compile-", dir=output))
    try:
        for name, data in files.items():
            path = staging / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        staging.rename(destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return destination
