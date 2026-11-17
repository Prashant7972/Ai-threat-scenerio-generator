"""Shared pytest fixtures for the test suite."""
import hashlib

import pytest

from src.generator.auto_generator import compile_all_scenarios
from src.generator.boundary_variants import DIMENSIONS


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
    spec['fixtures'] = [{'uri': name, 'sha256': hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()}
                        for name in ('attack.txt', 'benign.txt')]
    spec['benign_control']['fixture_ref'] = 'benign.txt'
    (tmp_path / 'source.txt').write_text('Unit-test source, no incident support claimed.')
    spec['source_refs'] = [{'record_id': 'test-source', 'revision': '1', 'locator': 'test:source'}]
    spec['source_facts'] = [{'claim_id': 'test-claim'}]
    evidence = [{'record_id': 'test-source', 'revision': '1', 'locator': 'test:source',
                 'claim_ids': ['test-claim'], 'snapshot_uri': 'source.txt',
                 'sha256': hashlib.sha256((tmp_path / 'source.txt').read_bytes()).hexdigest()}]
    profile = {'id': 'R1', 'version': '1.0.0',
               'capabilities': ['email_retrieval', 'document_retrieval', 'markdown_rendering'],
               'surfaces': {'retrieval_fixture': spec['attacker_access']['allowed_mutations']},
               'predicates': {p: True for p in spec['preconditions']},
               'builds': {'vulnerable': 'sha256:' + 'a' * 64, 'hardened': 'sha256:' + 'b' * 64}}
    return {'scenario': spec, 'evidence': evidence}, profile, tmp_path
