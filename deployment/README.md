# Controlled inference deployment

The deployment separates the trial process from the provider credential. The trial service attaches only to an internal Docker network. The inference-proxy service attaches to that network and an egress network. No service publishes a host port. Agent HTTP requests can reach the gateway, which has one fixed upstream host and an exact reviewed model allowlist.

The gateway rejects remote file parts, arbitrary upstream URLs, provider-side execution tools, unknown models and client tokens. It uses verified TLS, disables redirects and environment proxies, reserves cost before each call, persists reservations before network activity, and retains every final receipt. Unknown usage retains the reservation. A used receipt directory cannot restart a budget session without explicit reconciliation; never delete receipts to reset a budget. Client credentials and provider credentials are separate. Neither is stored in the repository.

## Preparation

1. Choose an immutable Python base image and build `deployment/Dockerfile` with `--build-arg PYTHON_BASE=IMAGE@sha256:DIGEST`. Build/image provisioning has not been performed in this environment.
2. Pin the resulting image by digest in `SCENARIO_IMAGE`. No unpinned image is acceptable for recorded release execution.
3. Copy `config/gateway-policy.example.json` outside the repository. Add the selected model under `models`, with `input_per_million_usd`, `output_per_million_usd`, `pricing_source` and `pricing_checked_at`. Set the policy version, maximum session cost and actual reviewer approval. The example is intentionally unapproved and has no enabled models.
4. Store a provider API credential and a separate random gateway token of at least 32 characters in files outside the repository. Do not place secrets inside package/output mounts.
5. Set absolute environment paths: `GATEWAY_POLICY_PATH`, `GATEWAY_RECEIPTS_PATH`, `PACKAGES_PATH`, `TRIAL_OUTPUT_PATH`, `PROVIDER_KEY_PATH`, `GATEWAY_TOKEN_PATH`. Output and receipt directories must be writable by container UID 10001. The gateway receipt directory must be fresh for this approved budget session.
6. Run `python deployment/validate_configuration.py`, then `docker compose -f deployment/compose.yaml config` to inspect the exact configuration. Record its hash along with image IDs, policy hash and package hashes.

Use `docker compose -f deployment/compose.yaml up -d inference-proxy` to start the gateway. The trial service default is help text and does not spend provider money. Override its command to use `src.proof.evaluator.package_runner` with explicit package, record, build and output paths. The reviewed gateway policy is mounted read-only as `/config/policy.json`; for live execution use `--mode live --gateway-policy /config/policy.json --model MODEL --preflight-only`. Inspect the estimate and session cap before using `--confirm-live-cost` in place of `--preflight-only`.

The client-side adapter sends only to `http://inference-proxy:8080/generate`. Provider credentials are loaded only by the gateway from its secret mount. Actual costs and observed model versions are copied from gateway receipts into trial manifests.

## Validation still required

This session's Docker socket is inaccessible (`permission denied`), so container builds, image digests, DNS/egress probes, resource isolation and complete end-to-end provider execution have **not** been verified. The compose layout and gateway unit tests are implementation evidence, not proof of network isolation. Before release, prove that the trial container cannot reach the provider or arbitrary Internet destinations directly, confirm that only the gateway can perform approved inference, and retain the probes in the manifest.

The compiled package runtime supports R1 staged retrieval, R2 tool-response/template delivery and R3 peer/artifact/summary/template delivery. Remaining scenario-specific hooks, authoritative source mappings and the 1,040 controlled-model release run remain pending. Do not treat this deployment as a completed accepted release.
