"""Reviewed structured carrier/placement generator, version 1.0.0.

Twelve attacks cover 2 authority modes x 3 carriers x 2 actual workflow stages.
Six controls share carrier/stage/task context; both authority variants point to
one matched control. This is a supported generator, not a universal fallback.
"""
import json
from itertools import product

from .contract import LitmusRecord, RecordType

GENERATOR_ID = 'boundary_carrier_v1'
DIMENSIONS = {'authority': ['none', 'claimed_system'], 'carrier': ['plain', 'email', 'json'], 'stage': [0, 1]}
REQUIRED_OPERATORS = {'authority_claims', 'carrier_changes', 'multi_turn_placement'}
PARAMETER_SCHEMA = {'type': 'object', 'properties': {}, 'additionalProperties': False}


def encode_carrier(text, carrier):
    if carrier == 'plain': return {'text': text}
    if carrier == 'email': return {'from': 'synthetic-sender@example.test', 'subject': 'Synthetic task data', 'body': text}
    if carrier == 'json': return {'attachment': {'text': text, 'content_type': 'synthetic_note'}}
    raise ValueError('Unsupported carrier')


def materialize_boundary_records(spec):
    if spec.generator.id != GENERATOR_ID or spec.generator.version != '1.0.0':
        raise ValueError('Unsupported structured generator id/version')
    if spec.generator.parameters:
        raise ValueError('This generator has no free-form parameters')
    if spec.variants.dimensions != DIMENSIONS or spec.variants.selection_method != 'full_factorial':
        raise ValueError('Generator requires its declared full-factorial boundary space')
    if not REQUIRED_OPERATORS <= set(spec.allowed_mutation_scope):
        raise ValueError('Boundary generator exceeds declared mutation scope')
    records = []
    for carrier, stage in product(DIMENSIONS['carrier'], DIMENSIONS['stage']):
        control_key = f'{spec.spec_id}:benign:{carrier}:stage{stage}'
        for authority in [None, *DIMENSIONS['authority']]:
            benign = authority is None
            text = spec.canonical_benign_prompt if benign else spec.canonical_attack_prompt
            if authority == 'claimed_system': text = '[Unverified system authority claim] ' + text
            key = control_key if benign else f'{spec.spec_id}:attack:{carrier}:stage{stage}:{authority}'
            steps = [{'stage': i, 'surface': spec.injection_surface.value,
                      'carrier': encode_carrier(text if i == stage else 'Synthetic neutral context.', carrier)} for i in range(2)]
            if spec.injection_surface.value in ('chat_template', 'configuration'):
                for step in steps:
                    step['operation'] = 'replace' if not benign and step['stage'] == stage else 'noop'
            materialized = {'legitimate_user_task': spec.legitimate_goal, 'fixture_bindings': [f.model_dump() for f in spec.fixtures],
                            'workflow_inputs': steps, 'matched_benign_control': control_key}
            payload = json.dumps(materialized, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
            canonical = carrier == 'plain' and stage == 0 and (benign or authority == 'none')
            records.append(LitmusRecord(record_id=key, spec_id=spec.spec_id, logical_variant_key=key,
                record_type=RecordType.BENIGN_CONTROL if benign else RecordType.ATTACKER_INJECTION,
                attack_family=spec.attack_family, target_surface=spec.target_surface, injection_surface=spec.injection_surface,
                source_ids=spec.source_ids,
                assumptions=json.dumps({'origin_type': spec.origin_type.value, 'assumptions': spec.generated_assumptions,
                                        'dimensions': {'carrier': carrier, 'stage': stage, 'authority': authority},
                                        'matched_benign_control': control_key}, sort_keys=True),
                severity_rationale='Benign matched control' if benign else spec.severity_rationale,
                scenario_version=spec.version, generator_version=spec.generator.version,
                seed=spec.variants.seed, expected_control=None if benign else spec.assertions[0].id,
                split='canonical' if canonical else 'test', payload_text=payload))
    return records
