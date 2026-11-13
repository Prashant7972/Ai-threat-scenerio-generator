"""
Immutable Trial Manifest Generator (EVAL 03).
Saves complete execution receipts, tool-graphs, telemetry, and assertions.
"""
from typing import Dict, Any
from pathlib import Path
import json
import hashlib
from src.generator.contract import TelemetryRecord, LitmusRecord
from .assertions import AssertionResults

def create_trial_manifest(
    telemetry: Any,
    record: LitmusRecord,
    assertions: AssertionResults,
    manifest_dir: Path
) -> Path:
    """
    Creates an immutable JSON trial manifest file.
    """
    if hasattr(telemetry, "build_telemetry_record"):
        t_rec = telemetry.build_telemetry_record()
    else:
        t_rec = telemetry

    manifest_data: Dict[str, Any] = {
        "trial_id": t_rec.trial_id,
        "spec_id": t_rec.spec_id,
        "logical_variant_key": t_rec.logical_variant_key,
        "record_id": record.record_id,
        "content_hash": record.content_hash,
        "attack_family": record.attack_family.value,
        "target_surface": record.target_surface.value,
        "target_build": t_rec.target_build,
        "seed": t_rec.seed,
        "model_turns": t_rec.model_turns,
        "total_tokens": t_rec.total_tokens,
        "wall_time_seconds": t_rec.wall_time_seconds,
        "primary_outcome": t_rec.primary_outcome.value,
        "disposition": t_rec.disposition.value if t_rec.disposition else None,
        "blocking_control_id": t_rec.blocking_control_id,
        "blocking_evidence": t_rec.blocking_evidence,
        "assertions": assertions.to_dict(),
        "tool_events": [ev.model_dump() for ev in t_rec.tool_events],
        "renderer_requests": t_rec.renderer_requests,
        "canary_hits": t_rec.canary_hits,
        "state_diffs": t_rec.state_diffs,
    }

    manifest_json = json.dumps(manifest_data, indent=2, sort_keys=True)
    manifest_hash = hashlib.sha256(manifest_json.encode("utf-8")).hexdigest()
    manifest_data["manifest_sha256"] = manifest_hash

    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / f"{telemetry.trial_id}.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2, sort_keys=True)

    return manifest_path
