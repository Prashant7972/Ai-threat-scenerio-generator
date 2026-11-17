import copy
import json
from decimal import Decimal

import pytest

from src.proof.inference_gateway import GatewayRejected, InferenceGateway


@pytest.fixture
def setup(tmp_path):
    policy = {'version': 'test-1', 'provider': 'google_gemini',
              'review': {'status': 'approved', 'reviewer': 'unit-test-only'},
              'max_cost_usd': 1,
              'models': {'test-model': {'input_per_million_usd': 1, 'output_per_million_usd': 2,
                                       'pricing_source': 'test fixture', 'pricing_checked_at': '2026-11-16'}}}
    request = {'model': 'test-model', 'payload': {'contents': [{'parts': [{'text': 'synthetic request'}]}],
                                               'generationConfig': {'maxOutputTokens': 256}}}
    calls = []
    def send(model, payload):
        calls.append(model)
        return {'modelVersion': 'test-version', 'usageMetadata': {'promptTokenCount': 10, 'totalTokenCount': 20}}
    gateway = InferenceGateway(policy, 'test-provider-key', 't' * 32, tmp_path / 'receipts', send)
    return gateway, request, calls, tmp_path


def test_exact_allowlist_and_receipts(setup):
    gateway, request, calls, root = setup
    _response, receipt = gateway.generate(request, 't' * 32)
    assert calls == ['test-model'] and receipt['actual_cost_usd'] == '0.00003'
    assert gateway.spent == Decimal('0.00003')
    saved = next(p for p in (root / 'receipts').glob('*.json') if not p.name.endswith('.reserved.json')).read_text()
    assert 'test-provider-key' not in saved and 'synthetic request' not in saved


@pytest.mark.parametrize('change', ['model', 'url', 'code', 'remote_file', 'token', 'cap', 'unreviewed'])
def test_rejections_happen_before_upstream(setup, change):
    gateway, request, calls, root = setup
    token = 't' * 32
    if change == 'model': request['model'] = 'unapproved-model'
    if change == 'url': request['url'] = 'https://example.test'
    if change == 'code': request['payload']['tools'] = [{'codeExecution': {}}]
    if change == 'remote_file': request['payload']['contents'][0]['parts'] = [{'fileData': {'fileUri': 'https://example.test'}}]
    if change == 'token': token = 'wrong'
    if change == 'cap': gateway.cap = Decimal('0.0000001')
    if change == 'unreviewed':
        policy = copy.deepcopy(gateway.policy); policy['review']['status'] = 'candidate'
        with pytest.raises(GatewayRejected): InferenceGateway(policy, 'key', 't' * 32, root / 'other')
        return
    with pytest.raises(GatewayRejected): gateway.generate(request, token)
    assert not calls


def test_failed_request_keeps_reservation_and_history(setup):
    gateway, request, _calls, root = setup
    def failed(*args): raise RuntimeError('upstream failure')
    gateway.sender = failed
    with pytest.raises(RuntimeError): gateway.generate(request, 't' * 32)
    assert gateway.spent > 0
    receipt = json.loads(next(p for p in (root / 'receipts').glob('*.json') if not p.name.endswith('.reserved.json')).read_text())
    assert receipt['status'] == 'infrastructure_error' and receipt['actual_cost_usd'] is None
    with pytest.raises(GatewayRejected, match='fresh budget session'):
        InferenceGateway(gateway.policy, 'key', 't' * 32, root / 'receipts')


def test_trial_client_never_forwards_provider_key_or_changes_policy(setup, monkeypatch):
    import httpx

    from src.proof.gateway_client import GatewayModelProxy
    from src.proof.proxy import TelemetryCollector
    gateway, _request, _calls, _root = setup
    policy = gateway.policy
    class Client:
        def __init__(self, **kwargs):
            assert kwargs['follow_redirects'] is False and kwargs['trust_env'] is False
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def post(self, url, headers, json):
            assert url == 'http://inference-proxy:8080/generate'
            assert headers == {'Authorization': 'Bearer ' + 't'*32}
            body, receipt = gateway.generate(json, 't'*32)
            body['candidates'] = [{'content': {'parts': [{'text': 'synthetic answer'}]}}]
            return httpx.Response(200, json={'response': body, 'receipt': receipt})
    monkeypatch.setattr(httpx, 'Client', Client)
    proxy = GatewayModelProxy(policy, 'test-model', 't'*32)
    telemetry = TelemetryCollector('test', 'test', 'test', 'hardened', 42)
    result = proxy.generate_turn('task', 'system', [], telemetry)
    assert result == {'type': 'content', 'text': 'synthetic answer'}
    assert telemetry.model_requests[0]['gateway_receipt']['actual_cost_usd'] == '0.00003'
    estimate = proxy.estimate_cost(1040)
    assert Decimal(estimate['upper_bound_cost_usd']) == Decimal('41.6')


def test_trial_deployment_has_no_provider_credential_or_egress_network():
    from pathlib import Path

    import yaml
    config = yaml.safe_load(Path('deployment/compose.yaml').read_text())
    trial = config['services']['trial']
    assert trial['networks'] == ['trial_internal']
    assert config['networks']['trial_internal']['internal'] is True
    assert 'provider_key' not in trial.get('secrets', [])
    assert not trial.get('ports') and trial['read_only'] is True
    assert 'ALL' in trial['cap_drop']
    assert config['services']['inference-proxy']['secrets'] == ['provider_key', 'gateway_token']


def test_deployment_rejects_unpinned_image():
    import runpy
    validate = runpy.run_path('deployment/validate_configuration.py')['validate']
    with pytest.raises(ValueError, match='sha256 image digest'):
        validate({'SCENARIO_IMAGE': 'python:latest'})
