"""
Unit tests for the 360-record Litmus corpus.
"""
from pathlib import Path
import pytest
from src.generator.contract import LitmusRecord, RecordType, InjectionSurface
from src.generator.auto_generator import generate_litmus_corpus, LITMUS_OUTPUT

def test_corpus_exists_and_has_360_records():
    assert LITMUS_OUTPUT.exists()
    records = []
    with open(LITMUS_OUTPUT, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(LitmusRecord.model_validate_json(line))
                
    assert len(records) == 360
    attacks = [r for r in records if r.record_type == RecordType.ATTACKER_INJECTION]
    benigns = [r for r in records if r.record_type in (RecordType.BENIGN_CONTROL, RecordType.LEGITIMATE_USER_TASK)]
    quotes = [r for r in records if "quote" in r.logical_variant_key]

    assert len(attacks) == 240
    assert len(benigns) == 120
    assert len(quotes) == 20

    # Verify injection surfaces are distributed across valid types
    surfaces = {r.injection_surface for r in records}
    assert len(surfaces) >= 7

def test_corpus_content_hashes_and_determinism(tmp_path):
    records = []
    with open(LITMUS_OUTPUT, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(LitmusRecord.model_validate_json(line))

    hashes = {r.content_hash for r in records}
    assert len(hashes) == 360

    # Test exact replayability
    tmp_out = tmp_path / "replay.jsonl"
    h = generate_litmus_corpus(tmp_out, seed=42)
    
    import hashlib
    with open(LITMUS_OUTPUT, "rb") as f:
        expected_hash = hashlib.sha256(f.read()).hexdigest()
    assert h == expected_hash
