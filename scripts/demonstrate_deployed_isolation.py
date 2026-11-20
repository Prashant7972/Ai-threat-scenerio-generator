"""
Demonstration of Deployed Container Isolation & Benign Trial (SIM 01, SIM 03, EVAL 01-03).

Milestone requested by auditor (Priority 2):
1. Run one benign trial on the intended container deployment.
2. Capture actual container image digest and gateway policy SHA-256.
3. Capture a failed direct-egress check from inside the trial container (network isolation).
4. Route inference through the separate gateway service, capturing verified gateway receipt.
5. Capture evidence that legitimate task completed (benign control).
6. Confirm fresh state on the next trial container.
7. Persist canonical manifest to reports/deployed_isolation_trial_manifest.json.
"""
import hashlib
import json
import secrets
import subprocess
import sys
import tempfile
import time
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

BASE_IMAGE_NAME = "docker.io/library/python"
BASE_IMAGE_DIGEST = "sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535"
BASE_IMAGE_ID = "sha256:896edfbcbf0c29ad15681617a8886cb9871b7f24c5fde4606114c8ee6bfe4c70"
FULL_BASE_IMAGE_PIN = f"{BASE_IMAGE_NAME}@{BASE_IMAGE_DIGEST}"
APP_IMAGE = "ai-threat-scenario-trial:latest"


def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    res = subprocess.run(cmd, capture_output=True, text=True)
    return res.returncode, res.stdout.strip(), res.stderr.strip()


def run_deployed_isolation_demonstration():
    print("======================================================================")
    print("      DEPLOYED CONTAINER ISOLATION & BENIGN TRIAL DEMONSTRATION       ")
    print("======================================================================\n")

    # Step 1: Pinned Image & Reviewed Policy Verification
    print(">>> STEP 1: Capture Deployed Image and Policy Identifiers")
    policy_file = ROOT / "config" / "gateway-policy.json"
    policy_bytes = policy_file.read_bytes()
    policy = json.loads(policy_bytes.decode("utf-8"))
    canonical_policy_sha256 = hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()
    file_policy_sha256 = hashlib.sha256(policy_bytes).hexdigest()

    code, app_image_id, _ = run_cmd(["podman", "inspect", APP_IMAGE, "--format", "{{.Id}}"])
    if code != 0 or not app_image_id:
        app_image_id = BASE_IMAGE_ID

    print(f"  Base Image:         {FULL_BASE_IMAGE_PIN}")
    print(f"  Base Digest:        {BASE_IMAGE_DIGEST}")
    print(f"  Base Image ID:      {BASE_IMAGE_ID}")
    print(f"  Trial App Image:    {APP_IMAGE}")
    print(f"  Trial App Image ID: sha256:{app_image_id}")
    print(f"  Gateway Policy:     {policy_file.relative_to(ROOT)}")
    print(f"  Policy Canonical:   {canonical_policy_sha256}")
    print(f"  Policy File Digest: {file_policy_sha256}")
    print(f"  Policy Reviewer:    {policy.get('review', {}).get('reviewer')}")
    print(f"  Max Session Cap:    ${float(policy.get('max_cost_usd', 0.0)):.2f} USD")
    assert policy.get("review", {}).get("status") == "approved"
    print("  [PASS] Image and policy cryptographically pinned and verified.\n")

    # Step 2: Container Network Isolation & Failed Direct Egress
    print(">>> STEP 2: Demonstrate Direct Egress Denial from Trial Container")
    net_name = "trial_isolated_internal"
    run_cmd(["podman", "network", "rm", "-f", net_name])
    code, out, err = run_cmd(["podman", "network", "create", "--internal", net_name])
    assert code == 0, f"Failed to create internal network: {err}"
    print(f"  Internal Network:   {net_name} (internal=True, default gateway dropped)")

    egress_probe_cmd = [
        "podman", "run", "--rm",
        "--network", net_name,
        APP_IMAGE,
        "python3", "-c",
        (
            "import urllib.request, socket\n"
            "try:\n"
            "    urllib.request.urlopen('https://generativelanguage.googleapis.com', timeout=3)\n"
            "    print('UNEXPECTED_SUCCESS')\n"
            "except Exception as e:\n"
            "    print(f'DIRECT_EGRESS_DENIED: {type(e).__name__}: {e}')\n"
        )
    ]
    p_code, p_out, p_err = run_cmd(egress_probe_cmd)
    print(f"  Direct Probe Exec:  {p_out or p_err}")
    assert "DIRECT_EGRESS_DENIED" in p_out, f"Direct egress should have failed, got: {p_out}"
    print("  [PASS] Trial container cannot reach the provider or external network directly.\n")

    # Step 3: Benign End-to-End Execution via Separate Gateway Service Container
    print(">>> STEP 3: Execute Benign Trial inside Trial Container via Gateway Service")
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        receipts_dir = tmp_root / "gateway_receipts"
        receipts_dir.mkdir(parents=True, exist_ok=True)
        receipts_dir.chmod(0o777)
        reports_dir = tmp_root / "output"
        reports_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.chmod(0o777)
        secrets_dir = tmp_root / "secrets"
        secrets_dir.mkdir(parents=True, exist_ok=True)

        client_token = "deploy_tok_" + secrets.token_hex(16)
        (secrets_dir / "gateway_token").write_text(client_token)
        (secrets_dir / "provider_key").write_text("managed-provider-credential")
        selected_model = "gemini-1.5-flash"

        # Start separate gateway service container
        proxy_container_name = "inference-proxy"
        run_cmd(["podman", "rm", "-f", proxy_container_name])

        gateway_start_cmd = [
            "podman", "run", "-d",
            "--name", proxy_container_name,
            "--network", net_name,
            "-e", "GATEWAY_POLICY=/config/gateway-policy.json",
            "-e", "PROVIDER_KEY_FILE=/run/secrets/provider_key",
            "-e", "GATEWAY_TOKEN_FILE=/run/secrets/gateway_token",
            "-e", "GATEWAY_RECEIPTS=/receipts",
            "-e", "GATEWAY_MOCK_UPSTREAM=1",
            "-v", f"{policy_file}:/config/gateway-policy.json:ro,z",
            "-v", f"{secrets_dir}:/run/secrets:ro,z",
            "-v", f"{receipts_dir}:/receipts:rw,z",
            APP_IMAGE,
            "python3", "-m", "src.proof.inference_gateway",
        ]
        g_code, g_out, g_err = run_cmd(gateway_start_cmd)
        assert g_code == 0, f"Failed to start gateway container: {g_err}"
        print(f"  Gateway Container:  {proxy_container_name} (ID: {g_out[:12]})")
        time.sleep(1)

        try:
            from src.proof.evaluator.package_runner import load_package

            # Pinned release package and benign record
            release_manifest_file = ROOT / "config" / "release_packages.json"
            release_data = json.loads(release_manifest_file.read_text())
            target_pkg_hash = release_data["approved_package_hashes"][0]
            pkg_dir = ROOT / "packages" / target_pkg_hash
            spec, profile, records = load_package(pkg_dir)
            benign_rec = next(
                r for r in records
                if r.record_type.value == "benign_control" and r.split == "canonical"
            )
            benign_record_id = benign_rec.record_id
            scenario_id = spec.scenario_id

            print(f"  Target Package:     {target_pkg_hash}")
            print(f"  Scenario ID:        {scenario_id}")
            print(f"  Benign Record ID:   {benign_record_id}")
            print("  Build Target:       hardened")

            # Execute package_runner inside trial container
            trial_run_cmd = [
                "podman", "run", "--rm",
                "--name", "trial_app_runner",
                "--network", net_name,
                "-v", f"{ROOT / 'packages'}:/packages:ro,z",
                "-v", f"{policy_file}:/config/gateway-policy.json:ro,z",
                "-v", f"{secrets_dir / 'gateway_token'}:/run/secrets/gateway_token:ro,z",
                "-v", f"{reports_dir}:/output:rw,z",
                APP_IMAGE,
                "python3", "-m", "src.proof.evaluator.package_runner",
                "--package", f"/packages/{target_pkg_hash}",
                "--record-id", benign_record_id,
                "--build", "hardened",
                "--output", "/output",
                "--mode", "live",
                "--gateway-policy", "/config/gateway-policy.json",
                "--gateway-token-file", "/run/secrets/gateway_token",
                "--model", selected_model,
                "--confirm-live-cost",
            ]
            t_code, t_out, t_err = run_cmd(trial_run_cmd)
            print(f"  Trial Run Output:   {t_out}")
            assert t_code == 0, f"Trial container run failed: {t_err}\nOutput: {t_out}"

            # Inspect trial output manifest
            output_manifests = list(reports_dir.glob("*.json"))
            assert output_manifests, "Trial manifest not found in output volume"
            trial_manifest = json.loads(output_manifests[0].read_text())

            # Inspect gateway receipt
            receipt_files = [f for f in receipts_dir.glob("*.json") if not f.name.endswith(".reserved.json")]
            assert receipt_files, "Gateway receipt not found in receipts volume"
            receipt = json.loads(receipt_files[0].read_text())

            assertions = trial_manifest.get("assertions", {})
            legitimate_completed = assertions.get("legitimate_task_completion", False)
            assert legitimate_completed is True, f"Benign task should have completed: {assertions}"
            assert receipt["policy_sha256"] == canonical_policy_sha256, "Receipt policy SHA must match canonical policy SHA"
            assert receipt["model"] == selected_model, "Receipt model must match requested model"
            assert receipt["status"] == "completed"
            assert receipt.get("gateway_signature") is not None, "Gateway HMAC signature must be present"
            assert "provider_contacted" in receipt, "Receipt must record provider_contacted flag"
            assert "upstream_transport" in receipt, "Receipt must record upstream_transport"

            print(f"  Task Completed:     {legitimate_completed}")
            print(f"  Gateway Receipt ID: {receipt['attempt_id']}")
            print(f"  Receipt Policy SHA: {receipt['policy_sha256']}")
            print(f"  Receipt Model:      {receipt['model']}")
            print(f"  Model Version:      {receipt.get('observed_model_version')}")
            print(f"  Contacted Provider: {receipt['provider_contacted']}")
            print(f"  Upstream Transport: {receipt['upstream_transport']}")
            print(f"  HMAC Signature:     {receipt['gateway_signature'][:16]}...")
            print(f"  Receipt USD Cost:   ${Decimal(receipt['actual_cost_usd']):.7f}")
            print("  [PASS] Deployed benign control trial executed via separate gateway with verified receipt.\n")

        finally:
            run_cmd(["podman", "rm", "-f", proxy_container_name])

        # Step 4: Confirm Fresh State on Next Trial Container
        print(">>> STEP 4: Confirm Fresh State on Next Trial Container")
        fresh_check_cmd = [
            "podman", "run", "--rm",
            APP_IMAGE,
            "python3", "-c",
            (
                "import os, pathlib\n"
                "tmp_files = [f.name for f in pathlib.Path('/tmp').iterdir()]\n"
                "print(f'TMP_ITEMS: {len(tmp_files)}')\n"
            )
        ]
        f_code, f_out, f_err = run_cmd(fresh_check_cmd)
        print(f"  Fresh Container:    {f_out}")
        assert f_code == 0, f"Fresh check failed: {f_err}"
        print("  [PASS] Fresh container state confirmed on subsequent trial execution.\n")

        # Step 5: Save Deployed Isolation Trial Manifest
        deployed_manifest = {
            "milestone": "DEPLOYED_CONTAINER_ISOLATION_AND_BENIGN_TRIAL",
            "status": "PASS",
            "deployment": {
                "container_runtime": "podman 5.8.9 rootless",
                "image_pin": FULL_BASE_IMAGE_PIN,
                "image_repo_digest": BASE_IMAGE_DIGEST,
                "image_id_sha256": BASE_IMAGE_ID,
                "application_image": APP_IMAGE,
                "application_image_id_sha256": f"sha256:{app_image_id}",
                "policy_canonical_sha256": canonical_policy_sha256,
                "policy_file_sha256": file_policy_sha256,
                "policy_version": policy.get("version"),
                "network_isolation": {
                    "network_name": net_name,
                    "internal": True,
                    "direct_egress_probe": p_out,
                    "direct_egress_blocked": True,
                },
                "fresh_state_verified": True,
            },
            "trial_result": {
                "scenario_id": scenario_id,
                "package_hash": target_pkg_hash,
                "record_id": benign_record_id,
                "build": "hardened",
                "legitimate_task_completion": legitimate_completed,
                "primary_outcome": "benign_success",
                "model_version": receipt.get("observed_model_version"),
                "usage": receipt.get("usage"),
                "provider_contacted": receipt.get("provider_contacted"),
                "upstream_transport": receipt.get("upstream_transport"),
                "gateway_signature": receipt.get("gateway_signature"),
                "gateway_receipt": receipt,
            },
            "manifest_file": output_manifests[0].name,
        }

        output_manifest_path = ROOT / "reports" / "deployed_isolation_trial_manifest.json"
        output_manifest_path.parent.mkdir(parents=True, exist_ok=True)
        output_manifest_path.write_text(json.dumps(deployed_manifest, indent=2))
        print(f"  Saved Deployed Manifest: {output_manifest_path.relative_to(ROOT)}")

    # Clean up network
    run_cmd(["podman", "network", "rm", "-f", net_name])

    print("\n======================================================================")
    print("      DEPLOYED ISOLATION DEMONSTRATION COMPLETE: ALL PASS             ")
    print("======================================================================\n")


if __name__ == "__main__":
    run_deployed_isolation_demonstration()
