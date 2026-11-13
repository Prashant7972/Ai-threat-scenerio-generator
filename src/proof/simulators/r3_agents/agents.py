"""
Planner and Executor Agents for Reference Application R3 (SIM 01, AML.M0032, AML.M0037).
"""
from typing import Dict, Any, Optional
from src.proof.proxy import MockModelProxy, TelemetryCollector
from src.generator.contract import ToolEvent, Disposition

ALLOWED_EXECUTOR_DEFAULT_SCOPE = ["read_status", "compute_metrics", "format_output"]
PRIVILEGED_SCOPES = ["admin_write", "credential_export", "root_orchestration"]

class PlannerAgent:
    def __init__(self, proxy: MockModelProxy):
        self.proxy = proxy

    def plan_workflow(self, task_description: str, telemetry: TelemetryCollector) -> Dict[str, Any]:
        """
        Plans workflow and formats delegation packet.
        """
        desc_clean = task_description.lower().replace("_", " ")
        if "admin expanded" in desc_clean or "root orchestration" in desc_clean or "system override" in desc_clean:
            return {
                "delegated_action": "privileged_system_operation",
                "claimed_scope": "root_orchestration",
                "payload": task_description,
                "authority_signature": None  # Unsigned authority claim!
            }
        
        return {
            "delegated_action": "routine_metric_computation",
            "claimed_scope": "compute_metrics",
            "payload": task_description,
            "authority_signature": "VALID_ROUTINE_SIG"
        }

class ExecutorAgent:
    def __init__(self, proxy: MockModelProxy):
        self.proxy = proxy

    def execute_delegated_task(
        self,
        delegation_packet: Dict[str, Any],
        target_build: str,
        telemetry: TelemetryCollector
    ) -> Dict[str, Any]:
        """
        Validates delegation bounds and executes action.
        """
        action = delegation_packet["delegated_action"]
        claimed_scope = delegation_packet["claimed_scope"]
        
        attempted_action_desc = f"Execute {action} with scope {claimed_scope}"

        if target_build == "hardened":
            # AML.M0037: AI Agent Authority Expansion Controls
            # AML.M0032: Segmentation of AI Agent Components
            if claimed_scope in PRIVILEGED_SCOPES:
                sig = delegation_packet.get("authority_signature")
                if sig != "AUTHORITATIVE_CRYPTOGRAPHIC_SIG_AML_M0037":
                    event = ToolEvent(
                        parent_task="multi_agent_workflow",
                        actor_agent="executor_agent",
                        delegated_scope=claimed_scope,
                        tool_name="privileged_system_execution",
                        tool_arguments={"action": action},
                        policy_decision="deny",
                        attempted_action=attempted_action_desc,
                        blocking_control_id="AML.M0037_AUTHORITY_EXPANSION_CONTROL",
                        error=f"Unauthorized privilege scope expansion attempt ({claimed_scope})."
                    )
                    telemetry.record_tool_event(event)
                    telemetry.disposition = Disposition.APPLICATION_REJECTION
                    return {"status": "blocked", "error": "Authority expansion blocked."}

        # Otherwise execute
        event = ToolEvent(
            parent_task="multi_agent_workflow",
            actor_agent="executor_agent",
            delegated_scope=claimed_scope,
            tool_name="privileged_system_execution" if claimed_scope in PRIVILEGED_SCOPES else "standard_tool",
            tool_arguments={"action": action},
            policy_decision="allow",
            attempted_action=attempted_action_desc,
            execution_receipt={"status": "SUCCESS", "scope_used": claimed_scope},
            result=f"Action {action} completed under scope {claimed_scope}"
        )
        telemetry.record_tool_event(event)
        return {"status": "completed", "receipt": event.execution_receipt}
