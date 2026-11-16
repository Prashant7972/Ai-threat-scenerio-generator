"""Generator boundary tests use synthetic unit-test approvals only."""
import json
import pytest
from test_strict_compiler import inputs
from src.generator.compiler import build_package
from src.generator.mechanisms import MECHANISMS
from src.generator.harness_generator import HARNESS_TEMPLATES
from src.generator.contract import TargetSurface, LitmusRecord

@pytest.mark.parametrize('mechanism,family,app,surface,hook', MECHANISMS)
def test_twenty_mechanisms_materialize_integrity_and_matching(inputs, mechanism, family, app, surface, hook):
    pattern, profile, root = inputs
    spec = pattern['scenario']
    spec['scenario_id'] = 'test.' + mechanism
    spec['attack_family'] = family
    spec['target_profile']['id'] = app
    spec['injection_surface'] = spec['attacker_access']['surface'] = surface
    spec['attacker_access']['allowed_mutations'] = ['authority_claims','carrier_changes','multi_turn_placement','template_or_configuration_changes','context_length']
    spec['generator'] = {'id':'reviewed_mechanism_v1','version':'1.0.0','parameters':{'mechanism':mechanism}}
    profile.update(id=app, capabilities=HARNESS_TEMPLATES[TargetSurface(app)]['required_capabilities'], surfaces={surface:spec['attacker_access']['allowed_mutations']})
    package = build_package(pattern, profile, root, root / 'packages')
    records = [LitmusRecord.model_validate_json(line) for line in (package / 'corpus.jsonl').read_text().splitlines()]
    attacks = [r for r in records if r.record_type.value == 'attacker_injection']
    controls = {r.logical_variant_key:r for r in records if r.record_type.value == 'benign_control'}
    assert len(attacks) == 12 and len(controls) == 6
    assert len({r.content_hash for r in records}) == 18
    assert len([r for r in records if r.split == 'canonical']) == 2
    for record in records:
        payload = json.loads(record.payload_text)
        assert payload['mechanism'] == mechanism
        assert payload['matched_benign_control'] in controls
        assert bytes.fromhex(record.payload_bytes).decode() == record.payload_text
        if surface == 'configuration':
            assert all(s['configuration']['route'].startswith('mock://') for s in payload['workflow_inputs'])
        if hook == 'long_context':
            assert all(len(s['context_entries']) in (24,64,128) for s in payload['workflow_inputs'])
        if hook == 'split_document':
            assert all(len(s['carrier']['chunks']) == 2 for s in payload['workflow_inputs'])
        if record.record_type.value == 'benign_control' and surface in ('configuration','chat_template'):
            assert all(s['operation'] == 'noop' for s in payload['workflow_inputs'])
