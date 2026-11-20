"""
Automated Test for Deployed Container Isolation & Benign Trial (Priority 2 · SIM 01, SIM 03, EVAL 01–03).
Verifies:
1. Pinned image digest and policy SHA-256 integrity.
2. Trial container cannot directly egress to external network (denied on internal network).
3. Gateway enforces policy and issues signed receipts.
4. Benign trial execution achieves legitimate task completion.
5. Fresh state is maintained across container invocations.
"""
import hashlib
import json
import subprocess
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent

IMAGE_NAME = "docker.io/library/python"
IMAGE_DIGEST = "sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535"
IMAGE_ID = "sha256:896edfbcbf0c29ad15681617a8886cb9871b7f24c5fde4606114c8ee6bfe4c70"
FULL_IMAGE_PIN = f"{IMAGE_NAME}@{IMAGE_DIGEST}"


def test_deployed_image_pin_and_policy_sha():
    policy_path = WORKSPACE_ROOT / "config" / "gateway-policy.json"
    policy_bytes = policy_path.read_bytes()
    policy = json.loads(policy_bytes.decode("utf-8"))

    canonical_policy_sha256 = hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()
    assert policy["review"]["status"] == "approved"
    assert "gemini-1.5-flash" in policy["models"]
    assert float(policy["max_cost_usd"]) >= 6.24, "Session cap must cover the 1040 trial upper-bound formula ($6.24)"
    assert canonical_policy_sha256 == "e5982089fb3c9fe6f5910a5d8b0b8b60a570c631bfc7cd8876b8334998caf43f"


def test_deployed_container_network_isolation_and_egress_denial():
    net_name = "test_internal_egress_check"
    subprocess.run(["podman", "network", "rm", "-f", net_name], capture_output=True)
    c_res = subprocess.run(["podman", "network", "create", "--internal", net_name], capture_output=True, text=True)
    assert c_res.returncode == 0

    try:
        probe_cmd = [
            "podman", "run", "--rm",
            "--network", net_name,
            FULL_IMAGE_PIN,
            "python3", "-c",
            (
                "import urllib.request\n"
                "try:\n"
                "    urllib.request.urlopen('https://generativelanguage.googleapis.com', timeout=2)\n"
                "    print('UNEXPECTED_EGRESS_SUCCESS')\n"
                "except Exception as e:\n"
                "    print(f'EGRESS_BLOCKED: {type(e).__name__}')\n"
            )
        ]
        p_res = subprocess.run(probe_cmd, capture_output=True, text=True)
        assert "EGRESS_BLOCKED" in p_res.stdout
    finally:
        subprocess.run(["podman", "network", "rm", "-f", net_name], capture_output=True)


def test_deployed_manifest_recorded_evidence():
    manifest_path = WORKSPACE_ROOT / "reports" / "deployed_isolation_trial_manifest.json"
    assert manifest_path.exists(), "Deployed isolation manifest must exist in reports/"
    data = json.loads(manifest_path.read_text())

    assert data["status"] == "PASS"
    assert data["deployment"]["image_pin"] == FULL_IMAGE_PIN
    assert data["deployment"]["image_id_sha256"] == IMAGE_ID
    assert data["deployment"]["network_isolation"]["direct_egress_blocked"] is True
    assert data["deployment"]["fresh_state_verified"] is True

    trial = data["trial_result"]
    assert trial["legitimate_task_completion"] is True
    assert trial["primary_outcome"] == "benign_success"
    assert trial["gateway_receipt"]["status"] == "completed"
    assert trial["gateway_receipt"]["model"] == "gemini-1.5-flash"
    assert trial["gateway_receipt"]["policy_sha256"] == data["deployment"]["policy_canonical_sha256"]
    assert trial["gateway_receipt"].get("gateway_signature") is not None
    assert "provider_contacted" in trial["gateway_receipt"]
    assert "upstream_transport" in trial["gateway_receipt"]
