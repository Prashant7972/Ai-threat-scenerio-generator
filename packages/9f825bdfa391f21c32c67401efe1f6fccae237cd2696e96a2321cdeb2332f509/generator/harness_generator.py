"""
Harness Package Generator from Safe Templates (SIM 02).
Generates target harness configurations, fixture bindings, and assertion plans.
Engineered and validated as safe code, forbidding unreviewed arbitrary code execution.
"""
from typing import Any

from .contract import MinimumScenarioContract, TargetSurface

HARNESS_TEMPLATES = {
    TargetSurface.R1: {
        "harness_type": "rag_instrumented_harness",
        "supported_fixtures": ["synthetic_emails", "synthetic_documents"],
        "telemetry_sinks": ["markdown_renderer", "tool_events"],
        "required_capabilities": ["email_retrieval", "document_retrieval", "markdown_rendering"]
    },
    TargetSurface.R2: {
        "harness_type": "tool_approval_harness",
        "supported_fixtures": ["synthetic_database", "approval_state_store"],
        "telemetry_sinks": ["tool_events", "approval_receipts", "state_diffs"],
        "required_capabilities": ["database_query", "financial_transfer", "system_recovery_advisory"]
    },
    TargetSurface.R3: {
        "harness_type": "multi_agent_delegation_harness",
        "supported_fixtures": ["shared_artifacts", "memory_store"],
        "telemetry_sinks": ["tool_events", "delegation_receipts", "agent_memory"],
        "required_capabilities": ["multi_agent_delegation", "shared_artifact_store", "rolling_summary_memory"]
    }
}

class SafeHarnessPackage:
    def __init__(self, spec: MinimumScenarioContract):
        self.spec = spec
        self.target_surface = spec.target_surface
        self.template = HARNESS_TEMPLATES.get(self.target_surface)
        if not self.template:
            raise ValueError(f"No safe reviewed template for target surface {self.target_surface}")

    def negotiate_capabilities(self, target_capabilities: list[str]) -> bool:
        """
        Capability negotiation (SIM 02): Fails fast before running if target lacks required capabilities.
        """
        required = set(self.template["required_capabilities"])
        available = set(target_capabilities)
        missing = required - available
        if missing:
            raise ValueError(f"Capability negotiation failed: Target lacks required capabilities {missing}")
        return True

    def generate_harness_config(self) -> dict[str, Any]:
        """
        Generates bound harness configuration from reviewed safe template.
        """
        return {
            "scenario_id": self.spec.scenario_id,
            "harness_type": self.template["harness_type"],
            "target_surface": self.target_surface.value,
            "budgets": self.spec.budgets.model_dump(),
            "assertions": [a.model_dump() for a in self.spec.assertions],
            "fixtures": [f.model_dump() for f in self.spec.fixtures],
            "benign_control": self.spec.benign_control.model_dump(),
            "telemetry_sinks": self.template["telemetry_sinks"]
        }
