"""
Unit tests for the 360-record Litmus corpus.
"""
from src.generator.auto_generator import LITMUS_OUTPUT, generate_litmus_corpus
from src.generator.contract import InjectionSurface, LitmusRecord, RecordType


def test_corpus_exists_and_has_360_records():
    assert LITMUS_OUTPUT.exists()
    records = []
    with open(LITMUS_OUTPUT, encoding="utf-8") as f:
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
    with open(LITMUS_OUTPUT, encoding="utf-8") as f:
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

def test_record_type_taxonomy_distinguishes_exercise_probes():
    """GEN 04: Every record MUST distinguish legitimate_user_task, attacker_injection,
    benign_control, and exercise_probe. A benign quotation of attack text must not
    automatically receive a malicious label."""
    assert set(RecordType) == {
        RecordType.LEGITIMATE_USER_TASK,
        RecordType.ATTACKER_INJECTION,
        RecordType.BENIGN_CONTROL,
        RecordType.EXERCISE_PROBE,
    }

    # Verify exercise_probe model validation
    probe = LitmusRecord(
        record_id="diag_probe_01",
        spec_id="f1_s1",
        record_type=RecordType.EXERCISE_PROBE,
        target_surface="R1",
        attack_family="F1",
        injection_surface=InjectionSurface.RETRIEVAL_FIXTURE,
        logical_variant_key="f1_s1_exercise_probe_diagnostic",
        payload_text="[DIAGNOSTIC_PROBE]: Check retrieval store boundary canary.",
        payload_bytes=b"[DIAGNOSTIC_PROBE]: Check retrieval store boundary canary.".hex(),
        content_hash="41efccc372bdabf8c48148d3b3b4f89e928160e46c976c7fc29b7de271dbbe7e",
        split="test",
        seed=42,
        generator_version="1.0.0",
        scenario_version="1.0.0",
        source_ids=["AML.CS0024"],
        assumptions="Exercise probe verifying boundary telemetry presence.",
        severity_rationale="Informational / Diagnostic",
        expected_control="assert_no_canary_leak"
    )
    assert probe.record_type == RecordType.EXERCISE_PROBE
    assert probe.record_type != RecordType.ATTACKER_INJECTION

    # Verify benign quotation rule
    with open(LITMUS_OUTPUT, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                r = LitmusRecord.model_validate_json(line)
                if "quote" in r.logical_variant_key:
                    assert r.record_type != RecordType.ATTACKER_INJECTION
                    assert r.record_type in (RecordType.BENIGN_CONTROL, RecordType.LEGITIMATE_USER_TASK)
