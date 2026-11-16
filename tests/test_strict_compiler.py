"""Adversarial validation tests; approvals below are test fixtures, not real reviews."""
import copy
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.generator.auto_generator import compile_all_scenarios
from src.generator.compiler import build_package, compile_pattern
from src.generator.boundary_variants import DIMENSIONS, materialize_boundary_records
from src.generator.contract import BudgetsContract, LitmusRecord
from src.generator.snapshot import materialize_spec_records


@pytest.fixture
def inputs(tmp_path):
    spec = compile_all_scenarios()[0].model_dump(mode='json')
    spec.update(workflow_stages=['retrieve', 'summarize', 'render'],
                trust_boundary='Retrieved text cannot authorize renderer requests',
                review={'status': 'approved', 'reviewer': 'unit-test-only', 'timestamp': '2026-11-16T00:00:00Z'},
                origin_type='adaptation')
    spec['attacker_access']['surface'] = 'retrieval_fixture'
    spec['generator'] = {'id': 'boundary_carrier_v1', 'version': '1.0.0', 'parameters': {}}
    spec['variants'] = {'dimensions': DIMENSIONS, 'selection_method': 'full_factorial', 'seed': 42}
    (tmp_path / 'attack.txt').write_text('synthetic fixture')
    (tmp_path / 'benign.txt').write_text('synthetic meeting at 10')
    spec['fixtures'] = [dict(uri=name, sha256=hashlib.sha256((tmp_path / name).read_bytes()).hexdigest())
                        for name in ('attack.txt', 'benign.txt')]
    spec['benign_control']['fixture_ref'] = 'benign.txt'
    (tmp_path / 'source.txt').write_text('Unit-test source, no incident support claimed.')
    spec['source_refs'] = [dict(record_id='test-source', revision='1', locator='test:source')]
    spec['source_facts'] = [dict(claim_id='test-claim')]
    evidence = [dict(record_id='test-source', revision='1', locator='test:source',
                     claim_ids=['test-claim'], snapshot_uri='source.txt',
                     sha256=hashlib.sha256((tmp_path / 'source.txt').read_bytes()).hexdigest())]
    profile = dict(id='R1', version='1.0.0',
                   capabilities=['email_retrieval', 'document_retrieval', 'markdown_rendering'],
                   surfaces={'retrieval_fixture': spec['attacker_access']['allowed_mutations']},
                   predicates={p: True for p in spec['preconditions']},
                   builds={'vulnerable': 'sha256:' + 'a' * 64, 'hardened': 'sha256:' + 'b' * 64})
    return dict(scenario=spec, evidence=evidence), profile, tmp_path


def test_compile_and_cache_exact_bytes(inputs):
    pattern, profile, root = inputs
    package = build_package(pattern, profile, root, root / 'packages')
    assert build_package(pattern, profile, root, root / 'packages') == package
    records = [LitmusRecord.model_validate_json(line) for line in (package / 'corpus.jsonl').read_text().splitlines()]
    assert len(records) == 18
    assert len({r.logical_variant_key for r in records}) == 18
    manifest = json.loads((package / 'manifest.json').read_text())
    assert all(hashlib.sha256((package / name).read_bytes()).hexdigest() == sha for name, sha in manifest.items())
    (package / 'corpus.jsonl').write_text('tampered')
    with pytest.raises(ValueError, match='modified'):
        build_package(pattern, profile, root, root / 'packages')


@pytest.mark.parametrize('case', ['review', 'version', 'predicate', 'scope', 'surface', 'claim', 'fixture', 'capability', 'missing', 'traversal'])
def test_rejects_inconsistent_inputs(inputs, case):
    pattern, profile, root = inputs
    s = pattern['scenario']
    if case == 'review': s['review']['status'] = 'candidate'
    if case == 'version': profile['version'] = '2.0.0'
    if case == 'predicate': profile['predicates'] = {}
    if case == 'scope': profile['surfaces'] = {}
    if case == 'surface': s['attacker_access']['surface'] = 'configuration'
    if case == 'claim': s['source_facts'] = [{'claim_id': 'invented'}]
    if case == 'fixture': (root / 'attack.txt').write_text('modified')
    if case == 'capability': profile['capabilities'] = []
    if case == 'missing': del s['legitimate_goal']
    if case == 'traversal': pattern['evidence'][0]['snapshot_uri'] = '../source.txt'
    with pytest.raises(ValueError): compile_pattern(pattern, profile, root)
    assert not (root / 'packages').exists()


def test_stored_bytes_cannot_disagree_with_hash():
    record = materialize_spec_records(compile_all_scenarios()[0])[0].model_dump(mode='json')
    record['payload_bytes'] = b'different bytes'.hex()
    with pytest.raises(ValidationError, match='Stored payload bytes'):
        LitmusRecord.model_validate(record)


@pytest.mark.parametrize('cap', ['turns', 'tool_calls', 'tokens', 'seconds'])
@pytest.mark.parametrize('value', [0, -1])
def test_budgets_must_be_positive(cap, value):
    with pytest.raises(ValidationError): BudgetsContract(**{cap: value})


def test_structured_variants_cover_real_carriers_stages_and_matched_controls(inputs):
    pattern, profile, root = inputs
    spec, _ = compile_pattern(pattern, profile, root)
    records = materialize_boundary_records(spec)
    attacks = [r for r in records if r.record_type.value == 'attacker_injection']
    benign = {r.logical_variant_key: r for r in records if r.record_type.value == 'benign_control'}
    assert len(attacks) == 12 and len(benign) == 6
    assert len({r.content_hash for r in records}) == 18
    for record in attacks:
        payload = json.loads(record.payload_text)
        control = json.loads(benign[payload['matched_benign_control']].payload_text)
        assert payload['legitimate_user_task'] == control['legitimate_user_task']
        assert payload['fixture_bindings'] == control['fixture_bindings']
        assert len(payload['workflow_inputs']) == 2
    spec.attacker_access.allowed_mutations = ['authority_claims']
    with pytest.raises(ValueError, match='mutation scope'): materialize_boundary_records(spec)


def test_runtime_replays_stored_stages_and_rejects_tampering(inputs, monkeypatch):
    from src.proof.evaluator.package_runner import run_record
    from src.proof.proxy import MockModelProxy
    pattern, profile, root = inputs
    pattern['scenario']['benign_control']['expected_task_outcome'] = {'output_contains': ['required summary is complete']}
    package = build_package(pattern, profile, root, root / 'packages')
    records = [LitmusRecord.model_validate_json(line) for line in (package / 'corpus.jsonl').read_text().splitlines()]
    benign = next(r for r in records if r.record_type.value == 'benign_control')
    # Exact replay must not call any generator, regardless of seed support.
    monkeypatch.setattr('src.generator.compiler.materialize_boundary_records', lambda *a: (_ for _ in ()).throw(AssertionError('regeneration')))
    path, result = run_record(package, benign.record_id, 'hardened', root / 'trials', MockModelProxy())
    manifest = json.loads(path.read_text())
    assert result.legitimate_task_completion is True
    assert manifest['model_turns'] == 2
    assert manifest['model_requests'][1]['prompt'].count('workflow_history') == 1
    assert len(manifest['tool_events']) == 2
    (package / 'corpus.jsonl').write_text('tampered')
    with pytest.raises(ValueError, match='hash mismatch'):
        run_record(package, benign.record_id, 'hardened', root / 'trials', MockModelProxy())
