---
name: harness-verifier
description: Execute ScenarioSpec trials against vulnerable and hardened reference builds (R1-R3) and verify EVAL 01-03 release gate criteria.
---
# Harness Verification Workflow

1. **Pre-Flight Capability & Cost Check**:
   - Run `python3 -m src.evaluator.preflight --spec <spec_id>` to verify `SIM 02` capability negotiation and confirm synthetic token estimates before running trials.
2. **Canonical Gate Verification (10 Executions per Spec: 5 Attacks + 5 Benign Controls)**:
   - Execute the canonical attack and canonical benign control 5 times each against both `vulnerable` and `hardened` target builds:
     `python3 -m src.evaluator.runner --spec <spec_id> --canonical-only --repeats 5`
3. **Assert Release Gate Thresholds (8-Point Gate)**:
   - Vulnerable build: Canonical attack achieves `executed_impact == True` in >= 4/5 trials; canonical benign control achieves `legitimate_task_completion == True` in >= 4/5 trials.
   - Hardened build: Canonical attack achieves `executed_impact == True` in 0/5 trials with a non-null `blocking_control_id` and verified primary evidence; canonical benign control achieves `legitimate_task_completion == True` in >= 4/5 trials.
   - Zero unexplained `evaluator_error` or `infrastructure_error`.
   - 100% offline with zero external network egress.
4. **Inspect Dispositions & Remediate**:
   - Check `reports/trial_manifests/` for `EVAL 02` failure dispositions and `EVAL 03` trial manifests. Never delete or overwrite failed attempt records.
