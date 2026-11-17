"""
CLI Interface for the Scenario Generator & Compiler.
"""
import argparse
import json
from pathlib import Path

from src.generator.auto_generator import (
    LITMUS_OUTPUT,
    SPECS_DIR,
    export_all_scenario_yamls,
    generate_litmus_corpus,
)
from src.generator.contract import LitmusRecord, RecordType


def verify_corpus(path: Path = LITMUS_OUTPUT) -> bool:
    if not path.exists():
        raise FileNotFoundError(f"Corpus file not found: {path}")

    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(LitmusRecord.model_validate_json(line))

    assert len(records) == 360, f"Expected 360 records, found {len(records)}"
    attacks = [r for r in records if r.record_type == RecordType.ATTACKER_INJECTION]
    benigns = [r for r in records if r.record_type in (RecordType.BENIGN_CONTROL, RecordType.LEGITIMATE_USER_TASK)]
    quotes = [r for r in records if "quote" in r.logical_variant_key]

    assert len(attacks) == 240, f"Expected 240 attacks, found {len(attacks)}"
    assert len(benigns) == 120, f"Expected 120 benigns, found {len(benigns)}"
    assert len(quotes) == 20, f"Expected 20 benign quotations, found {len(quotes)}"

    hashes = {r.content_hash for r in records}
    assert len(hashes) == 360, f"Expected 360 unique content hashes, got {len(hashes)}"

    print(f"VERIFIED: 360 records ({len(attacks)} attacks, {len(benigns)} benigns). Unique SHA-256 hashes: {len(hashes)}.")
    return True

def main():
    parser = argparse.ArgumentParser(description="AI Threat Scenario Generator CLI")
    parser.add_argument("--compile-specs", action="store_true", help="Compile the 20 scenario contract YAMLs into specs/")
    parser.add_argument("--generate", action="store_true", help="Compile specs and materialize 360-record Litmus corpus")
    parser.add_argument("--verify", action="store_true", help="Verify 360-record Litmus corpus")
    parser.add_argument("--pattern", type=Path, help="Explicit approved pattern JSON")
    parser.add_argument("--target-profile", type=Path, help="Versioned target profile JSON")
    parser.add_argument("--output", type=Path, help="Content-addressed package output directory")
    args = parser.parse_args()

    if args.pattern or args.target_profile or args.output:
        if not all((args.pattern, args.target_profile, args.output)):
            parser.error("--pattern, --target-profile and --output must be supplied together")
        if args.generate or args.compile_specs or args.verify:
            parser.error("Explicit compilation cannot be combined with legacy catalog commands")
        from .compiler import build_package
        destination = build_package(json.loads(args.pattern.read_text()),
                                    json.loads(args.target_profile.read_text()),
                                    args.pattern.parent, args.output)
        print(f"Compiled candidate package: {destination}")
        print("Compilation is not source verification or release acceptance.")
    elif args.compile_specs:
        export_all_scenario_yamls(SPECS_DIR)
        print(f"Compiled 20 MinimumScenarioContract YAMLs into {SPECS_DIR}")
    elif args.verify:
        verify_corpus()
    else:
        export_all_scenario_yamls(SPECS_DIR)
        h = generate_litmus_corpus(LITMUS_OUTPUT)
        print(f"Compiled 20 specs and materialized 360-record Litmus corpus to {LITMUS_OUTPUT}.")
        print(f"Corpus SHA-256: {h}")
        verify_corpus()

if __name__ == "__main__":
    main()
