import json

import pytest

from src.generator.auto_generator import compile_all_scenarios
from src.generator.contract import Disposition, RecordType, ToolEvent, TrialOutcome
from src.generator.provenance import plan_source_change, save_change_plan
from src.generator.snapshot import materialize_spec_records
from src.proof.evaluator.assertions import evaluate_primary_evidence
from src.proof.evaluator.dispositions import classify_trial_disposition
from src.proof.evaluator.manifest import create_trial_manifest
from src.proof.proxy import LiveModelProxy, TelemetryCollector


def telemetry(): return TelemetryCollector('test', 'f2_s1', 'key', 'hardened', 42)


def test_hardened_impact_and_unknown_exposure_are_not_hidden():
    t = telemetry()
    t.record_tool_event(ToolEvent(parent_task='test', actor_agent='test', delegated_scope='read',
        tool_name='db_query', tool_arguments={'filter': 'ALL_RECORDS'}, policy_decision='allow',
        attempted_action='bulk', execution_receipt={'row_count': 10}))
    a = evaluate_primary_evidence(RecordType.ATTACKER_INJECTION, t, 'hardened')
    assert a.executed_impact and a.attempted_unauthorized_action
    assert a.exposure is None and a.legitimate_task_completion is None


def test_provider_error_cannot_become_successful_quotation():
    t = telemetry(); t.logical_variant_key = 'benign_quote'
    t.primary_outcome = TrialOutcome.BENIGN_SUCCESS
    t.disposition = Disposition.INFRASTRUCTURE_ERROR
    a = evaluate_primary_evidence(RecordType.BENIGN_CONTROL, t, 'hardened')
    assert a.legitimate_task_completion is False
    assert classify_trial_disposition(t, a) == Disposition.INFRASTRUCTURE_ERROR


def test_repeated_attempts_are_retained_but_denials_not_executions():
    t = telemetry()
    for _ in range(2): t.record_proposed_action({'tool': 'same'})
    t.record_executed_action({'status': 'BLOCKED'})
    assert len(t.proposed_actions) == 2 and not t.executed_actions


def test_trial_manifests_cannot_be_overwritten(tmp_path):
    t = telemetry(); r = materialize_spec_records(compile_all_scenarios()[0])[0]
    a = evaluate_primary_evidence(r.record_type, t, 'hardened')
    path = create_trial_manifest(t, r, a, tmp_path)
    original = path.read_bytes()
    with pytest.raises(FileExistsError): create_trial_manifest(t, r, a, tmp_path)
    assert path.read_bytes() == original


def test_short_semantic_change_invalidates_and_preserves_history(tmp_path):
    old = {'id': 'AML.TTEST', 'description': 'Allow user data'}
    new = {'id': 'AML.TTEST', 'description': 'Deny user data'}
    packages = [{'package_id': 'one', 'scenario_id': 'one', 'source_ids': ['AML.TTEST'], 'test_ids': ['test-one']}]
    plan = plan_source_change(old, new, packages)
    assert plan['invalidate'] == ['one'] and plan['impacted_tests'] == ['test-one']
    assert plan['regenerate'] and plan['successor_candidates'][0]['status'] == 'candidate'
    path = save_change_plan(plan, tmp_path)
    withdrawal = plan_source_change(new, None, packages)
    save_change_plan(withdrawal, tmp_path)
    assert path.exists() and len(list(tmp_path.glob('*.json'))) == 2
    assert not withdrawal['regenerate'] and withdrawal['analyst_review_required']


@pytest.mark.parametrize('kind', ['text', 'function', 'http_error', 'refusal', 'missing_usage'])
def test_live_adapter_uses_provider_response_not_raw_json(monkeypatch, kind):
    proxy = LiveModelProxy('gemini-1.5-flash', api_key='synthetic-unit-test-key')
    t = telemetry()
    body = {'modelVersion': 'test-revision', 'usageMetadata': {'promptTokenCount': 40, 'totalTokenCount': 47},
            'candidates': [{'content': {'parts': [{'text': 'Observed result'}]}}]}
    tools = [{'name': 'read_status', 'description': 'read', 'parameters': {}}]
    if kind == 'function': body['candidates'][0]['content']['parts'] = [{'functionCall': {'name': 'read_status', 'args': {}}}]
    if kind == 'refusal': body['promptFeedback'] = {'blockReason': 'SAFETY'}
    if kind == 'missing_usage': body.pop('usageMetadata')
    def request(*args, **kwargs):
        assert kwargs['data']['systemInstruction']['parts'][0]['text'] == 'system'
        assert kwargs['data']['tools'][0]['functionDeclarations'][0]['name'] == 'read_status'
        return {'status_code': 503 if kind == 'http_error' else 200, 'text': json.dumps(body)}
    monkeypatch.setattr(proxy.transport, 'request', request)
    result = proxy.generate_turn('prompt', 'system', tools, t)
    if kind == 'text': assert result == {'type': 'content', 'text': 'Observed result'}
    if kind == 'function': assert result['tool_name'] == 'read_status'
    if kind in ('http_error', 'missing_usage'): assert t.disposition == Disposition.INFRASTRUCTURE_ERROR
    if kind == 'refusal': assert t.disposition == Disposition.PROVIDER_REFUSAL
    assert t.model_turns == 1
    if kind not in ('http_error', 'missing_usage'): assert t.total_tokens == 47
