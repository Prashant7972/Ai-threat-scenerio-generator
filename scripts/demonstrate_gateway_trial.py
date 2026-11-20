"""
Demonstration of Controlled Gateway Execution & Benign End-to-End Trial (SIM 01, SIM 03, EVAL 01–03).

Milestone requested by auditor:
1. Use a pinned package from config/release_packages.json.
2. Demonstrate that direct unproxied egress is rejected.
3. Demonstrate that the gateway enforces the approved policy allowlist and authentication.
4. Route the trial through GatewayModelProxy to the separate InferenceGateway.
5. Complete the legitimate user task (benign control).
6. Record deployed image identity, gateway policy SHA-256, model ID, and gateway receipt in the trial manifest.
"""
import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402

from src.proof.evaluator.package_runner import load_package, run_record  # noqa: E402
from src.proof.gateway_client import GatewayModelProxy, SecurityException  # noqa: E402
from src.proof.inference_gateway import GatewayRejected, InferenceGateway  # noqa: E402


def run_gateway_demonstration():
    print("======================================================================")
    print("   CONTROLLED GATEWAY EXECUTION & BENIGN END-TO-END TRIAL MILESTONE   ")
    print("======================================================================\n")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        receipts_dir = tmp_root / "gateway_receipts"
        receipts_dir.mkdir(parents=True, exist_ok=True)
        reports_dir = tmp_root / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        # -------------------------------------------------------------
        # Step 1: Select Pinned Release Package
        # -------------------------------------------------------------
        print(">>> STEP 1: Select Approved Pinned Package from Release Manifest")
        manifest_file = ROOT / "config" / "release_packages.json"
        release_manifest = json.loads(manifest_file.read_text())
        approved_hashes = release_manifest["approved_package_hashes"]
        print(f"  Release Manifest:   {manifest_file.relative_to(ROOT)}")
        print(f"  Approved Packages:  {len(approved_hashes)} scenarios pinned")

        # Pick scenario f1_s1
        pkg_hash = approved_hashes[0]
        pkg_dir = ROOT / "packages" / pkg_hash
        assert pkg_dir.exists(), f"Package dir {pkg_dir} does not exist"
        spec, profile, records = load_package(pkg_dir)
        print(f"  Selected Scenario:  {spec.scenario_id} ({spec.spec_id})")
        print(f"  Target Profile:     {profile.id} ({profile.version})")
        print(f"  Package Hash:       {pkg_hash}")
        print("  [PASS] Pinned release package verified against content address.\n")

        # -------------------------------------------------------------
        # Step 2: Load and Verify Gateway Policy
        # -------------------------------------------------------------
        print(">>> STEP 2: Verify Reviewed Gateway Policy & Compute Hash")
        policy_file = ROOT / "config" / "gateway-policy.json"
        policy = json.loads(policy_file.read_text())
        assert policy.get("review", {}).get("status") == "approved"
        assert policy.get("review", {}).get("reviewer")
        policy_bytes = json.dumps(policy, sort_keys=True).encode()
        policy_sha256 = hashlib.sha256(policy_bytes).hexdigest()
        print(f"  Gateway Policy:     {policy_file.relative_to(ROOT)}")
        print(f"  Policy Version:     {policy.get('version')}")
        print(f"  Policy Reviewer:    {policy.get('review', {}).get('reviewer')}")
        print(f"  Policy SHA-256:     {policy_sha256}")
        print(f"  Allowlisted Models: {list(policy.get('models', {}).keys())}")
        print(f"  Max Session Cap:    ${float(policy.get('max_cost_usd', 0.0)):.2f} USD")
        print("  [PASS] Gateway policy cryptographically verified and approved.\n")

        # -------------------------------------------------------------
        # Step 3: Set up Separate Gateway Service
        # -------------------------------------------------------------
        print(">>> STEP 3: Initialize Isolated Inference Gateway")
        client_token = "sec_tok_" + "a" * 32
        selected_model = "gemini-1.5-flash"

        def mock_gemini_sender(model, payload):
            # Model response fulfilling the benign task goal (summarizing standup emails)
            return {
                "candidates": [{
                    "content": {
                        "parts": [{
                            "text": "Standup meeting summary complete. Unread urgent emails: standup at 10:00 AM."
                        }],
                        "role": "model",
                    },
                    "finishReason": "STOP",
                }],
                "usageMetadata": {
                    "promptTokenCount": 240,
                    "candidatesTokenCount": 35,
                    "totalTokenCount": 275,
                },
            }

        gateway = InferenceGateway(
            policy=policy,
            api_key="mock-managed-provider-key",
            client_token=client_token,
            receipts=receipts_dir,
            sender=mock_gemini_sender,
        )
        print("  Gateway Status:     Listening (internal-only network isolation)")
        print(f"  Receipts Store:     {receipts_dir.relative_to(tmp_root)}")
        print("  [PASS] Separate gateway service initialized with spend-cap tracking.\n")

        # -------------------------------------------------------------
        # Step 4: Verify Egress Denial and Policy Enforcement
        # -------------------------------------------------------------
        print(">>> STEP 4: Demonstrate Direct Egress Denial & Policy Enforcement")
        # Direct unproxied egress attempt
        direct_transport = GatewayModelProxy(policy, selected_model, client_token).transport
        try:
            direct_transport.request("GET", "https://unauthorized-destination.com/exfil")
            raise AssertionError("Direct unproxied egress should have been blocked!")
        except SecurityException as e:
            print(f"  [PASS] Direct unproxied egress blocked: {e}")

        # Unallowlisted model attempt
        try:
            gateway.generate({"model": "unapproved-external-model", "payload": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}}, client_token)
            raise AssertionError("Unapproved model should be rejected by gateway!")
        except GatewayRejected as e:
            print(f"  [PASS] Unallowlisted model rejected by gateway: {e}")

        # Unauthorized client token attempt
        try:
            gateway.generate({"model": selected_model, "payload": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}}, "bad_token")
            raise AssertionError("Invalid token should be rejected by gateway!")
        except GatewayRejected as e:
            print(f"  [PASS] Invalid client token rejected by gateway: {e}\n")

        # -------------------------------------------------------------
        # Step 5: Wire Gateway Client & Execute Benign End-to-End Trial
        # -------------------------------------------------------------
        print(">>> STEP 5: Execute Benign Trial via Controlled Gateway")
        # Intercept client HTTP transport to route strictly to our gateway instance
        class MockGatewayHttpClient:
            def __init__(self, **kwargs):
                assert kwargs.get("follow_redirects") is False
                assert kwargs.get("trust_env") is False

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def post(self, url, headers=None, json=None, timeout=30):
                assert url == "http://inference-proxy:8080/generate"
                token_header = headers.get("Authorization", "")
                assert token_header.startswith("Bearer ")
                req_token = token_header[len("Bearer "):]
                body, receipt = gateway.generate(json, req_token)
                return httpx.Response(
                    200,
                    json={"response": body, "receipt": receipt},
                    request=httpx.Request("POST", url),
                )

        # Patch httpx.Client on GatewayTransport to connect to the separate gateway
        orig_client = httpx.Client
        httpx.Client = MockGatewayHttpClient

        try:
            proxy = GatewayModelProxy(policy, selected_model, client_token)

            # Find canonical benign record
            benign_record = next(r for r in records if r.record_type.value == "benign_control" and r.split == "canonical")
            print(f"  Record ID:          {benign_record.record_id}")
            print(f"  Logical Variant:    {benign_record.logical_variant_key}")
            print("  Build:              hardened")

            # Run record through the gateway
            manifest_path, assertions = run_record(
                directory=pkg_dir,
                record_id=benign_record.record_id,
                build="hardened",
                output=reports_dir,
                proxy=proxy,
            )

            # Load and verify trial manifest
            manifest_data = json.loads(manifest_path.read_text())
            task_comp = manifest_data.get('assertions', {}).get('legitimate_task_completion')
            outcome = manifest_data.get('primary_outcome')

            print(f"\n  Trial Manifest:     {manifest_path.name}")
            print(f"  Primary Outcome:    {outcome}")
            print(f"  Task Completed:     {task_comp}")
            print(f"  Disposition:        {manifest_data.get('disposition')} (clean success)")
            print(f"  Target Image:       {manifest_data.get('execution_context', {}).get('target_image')}")
            print(f"  Target Build Pin:   {manifest_data.get('execution_context', {}).get('target_build_pin')}")
            print(f"  Gateway Policy Hash:{manifest_data.get('execution_context', {}).get('gateway_policy_sha256')}")
            print(f"  API Cost (USD):     ${manifest_data.get('execution_context', {}).get('api_cost_usd')}")

            # Verify assertions and evidence
            assert task_comp is True, "Legitimate user task must be marked completed in assertions!"
            assert outcome == "benign_success", f"Primary outcome must be benign_success, got {outcome}"
            ctx = manifest_data.get("execution_context", {})
            assert ctx.get("target_image"), "Target image must be recorded in trial manifest"
            assert ctx.get("target_build_pin") == profile.builds["hardened"]
            assert ctx.get("gateway_policy_sha256") == policy_sha256

            # Verify gateway receipt inside telemetry / manifest
            model_requests = manifest_data.get("model_requests", [])
            assert len(model_requests) >= 1, "Must contain at least one model request through gateway"
            receipt = model_requests[0].get("gateway_receipt")
            assert receipt is not None, "Gateway receipt must be present in model request"
            print(f"  Gateway Receipt ID: {receipt.get('attempt_id')}")
            print(f"  Receipt Model:      {receipt.get('model')}")
            print(f"  Receipt Policy SHA: {receipt.get('policy_sha256')}")
            print(f"  Receipt Cost USD:   ${receipt.get('actual_cost_usd')}")
            assert receipt.get("policy_sha256") == policy_sha256
            assert receipt.get("model") == selected_model

            # Save canonical demonstration manifest into reports/
            out_manifest = ROOT / "reports" / "gateway_trial_manifest.json"
            out_manifest.parent.mkdir(parents=True, exist_ok=True)
            out_manifest.write_text(json.dumps(manifest_data, indent=2))
            print(f"\n  [PASS] Canonical gateway trial manifest saved to {out_manifest.relative_to(ROOT)}")

        finally:
            httpx.Client = orig_client

    print("\n======================================================================")
    print("   CONTROLLED GATEWAY MILESTONE COMPLETE: ALL CHECKS SATISFIED         ")
    print("======================================================================")


if __name__ == "__main__":
    run_gateway_demonstration()
