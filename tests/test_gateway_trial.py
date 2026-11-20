"""
Priority 2 Automated Test (SIM 01, SIM 03, EVAL 01–03):
Verify that live execution connects to the controlled gateway, enforces policy and token auth,
blocks direct unproxied egress, and records deployed image pin, gateway policy SHA-256, model ID,
and gateway receipt on a benign end-to-end trial.
"""
import hashlib
import json
from pathlib import Path

import httpx

from src.proof.evaluator.package_runner import load_package, run_record
from src.proof.gateway_client import GatewayModelProxy, SecurityException
from src.proof.inference_gateway import GatewayRejected, InferenceGateway

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


def test_controlled_gateway_benign_trial(tmp_path):
    receipts_dir = tmp_path / "gateway_receipts"
    receipts_dir.mkdir(parents=True)
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True)

    # 1. Pinned package from release manifest
    manifest_file = WORKSPACE_ROOT / "config" / "release_packages.json"
    release_manifest = json.loads(manifest_file.read_text())
    pkg_hash = release_manifest["approved_package_hashes"][0]
    pkg_dir = WORKSPACE_ROOT / "packages" / pkg_hash
    spec, profile, records = load_package(pkg_dir)

    # 2. Approved gateway policy
    policy_file = WORKSPACE_ROOT / "config" / "gateway-policy.json"
    policy = json.loads(policy_file.read_text())
    policy_sha256 = hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()

    client_token = "valid_token_" + "b" * 32
    selected_model = "gemini-1.5-flash"

    def mock_sender(model, payload):
        return {
            "candidates": [{
                "content": {
                    "parts": [{"text": "Meeting times: Standup at 10:00 AM complete."}],
                    "role": "model",
                },
                "finishReason": "STOP",
            }],
            "usageMetadata": {"promptTokenCount": 200, "candidatesTokenCount": 25, "totalTokenCount": 225},
        }

    gateway = InferenceGateway(
        policy=policy,
        api_key="mock-key",
        client_token=client_token,
        receipts=receipts_dir,
        sender=mock_sender,
    )

    # 3. Direct egress denial
    proxy = GatewayModelProxy(policy, selected_model, client_token)
    try:
        proxy.transport.request("GET", "https://unauthorized-domain.com")
        raise AssertionError("Direct unproxied egress should have been blocked")
    except SecurityException:
        pass

    # 4. Gateway allowlist enforcement
    try:
        gateway.generate({"model": "unapproved-model", "payload": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}}, client_token)
        raise AssertionError("Unapproved model should be rejected")
    except GatewayRejected:
        pass

    # 5. Wire trial client to gateway
    class MockClient:
        def __init__(self, **kwargs):
            assert kwargs.get("follow_redirects") is False
            assert kwargs.get("trust_env") is False
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def post(self, url, headers=None, json=None, timeout=30):
            token = headers.get("Authorization", "")[len("Bearer "):]
            body, receipt = gateway.generate(json, token)
            return httpx.Response(200, json={"response": body, "receipt": receipt}, request=httpx.Request("POST", url))

    orig_client = httpx.Client
    httpx.Client = MockClient
    try:
        benign_record = next(r for r in records if r.record_type.value == "benign_control" and r.split == "canonical")
        manifest_path, assertions = run_record(
            directory=pkg_dir,
            record_id=benign_record.record_id,
            build="hardened",
            output=reports_dir,
            proxy=proxy,
        )

        manifest_data = json.loads(manifest_path.read_text())
        assert manifest_data.get("primary_outcome") == "benign_success"
        assert manifest_data.get("assertions", {}).get("legitimate_task_completion") is True
        ctx = manifest_data.get("execution_context", {})
        assert ctx.get("target_image")
        assert ctx.get("target_build_pin") == profile.builds["hardened"]
        assert ctx.get("gateway_policy_sha256") == policy_sha256

        reqs = manifest_data.get("model_requests", [])
        assert len(reqs) >= 1
        receipt = reqs[0].get("gateway_receipt")
        assert receipt is not None
        assert receipt.get("policy_sha256") == policy_sha256
        assert receipt.get("model") == selected_model
        assert receipt.get("actual_cost_usd") is not None
    finally:
        httpx.Client = orig_client


def test_gateway_transport_rejects_altered_signature_and_mismatched_hash(tmp_path):
    policy_file = WORKSPACE_ROOT / "config" / "gateway-policy.json"
    policy = json.loads(policy_file.read_text())
    client_token = "valid_token_" + "f" * 32
    selected_model = "gemini-1.5-flash"
    proxy = GatewayModelProxy(policy, selected_model, client_token)

    import json as json_mod
    import pytest

    from src.proof.inference_gateway import compute_gateway_signature

    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{selected_model}:generateContent"
    payload = {"contents": [{"role": "user", "parts": [{"text": "hello"}]}]}
    encoded_payload = json_mod.dumps(payload, ensure_ascii=False).encode()
    req_sha = hashlib.sha256(encoded_payload).hexdigest()

    # Case 1: Altered Signature
    class AlteredSigClient:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def post(self, url, headers=None, json=None, timeout=30):
            receipt = {
                'attempt_id': 'att_001',
                'policy_sha256': hashlib.sha256(json_mod.dumps(policy, sort_keys=True).encode()).hexdigest(),
                'request_sha256': req_sha,
                'model': selected_model,
                'started_at': '2026-11-20T00:00:00Z',
                'status': 'completed',
                'actual_cost_usd': '0.00003',
                'provider_contacted': False,
                'upstream_transport': 'simulated_rules',
                'gateway_signature': '0' * 64,  # Altered / invalid signature
            }
            body = {'response': {'candidates': [{'content': {'parts': [{'text': 'ok'}]}}]}, 'receipt': receipt}
            return httpx.Response(200, json=body, request=httpx.Request("POST", url))

    orig_client = httpx.Client
    try:
        httpx.Client = AlteredSigClient
        with pytest.raises(SecurityException, match="HMAC signature verification failed"):
            proxy.transport.request("POST", endpoint, data=payload)
    finally:
        httpx.Client = orig_client

    # Case 2: Mismatched Request Hash
    class MismatchedHashClient:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def post(self, url, headers=None, json=None, timeout=30):
            receipt = {
                'attempt_id': 'att_002',
                'policy_sha256': hashlib.sha256(json_mod.dumps(policy, sort_keys=True).encode()).hexdigest(),
                'request_sha256': 'wrong_hash_' + '0' * 53,  # Mismatched!
                'model': selected_model,
                'started_at': '2026-11-20T00:00:00Z',
                'status': 'completed',
                'actual_cost_usd': '0.00003',
                'provider_contacted': False,
                'upstream_transport': 'simulated_rules',
            }
            receipt['gateway_signature'] = compute_gateway_signature(client_token, receipt)
            body = {'response': {'candidates': [{'content': {'parts': [{'text': 'ok'}]}}]}, 'receipt': receipt}
            return httpx.Response(200, json=body, request=httpx.Request("POST", url))

    try:
        httpx.Client = MismatchedHashClient
        with pytest.raises(SecurityException, match="receipt request hash mismatch"):
            proxy.transport.request("POST", endpoint, data=payload)
    finally:
        httpx.Client = orig_client
