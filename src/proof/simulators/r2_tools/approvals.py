"""
Approval State Machine for Reference Application R2 (SIM 01, AML.M0015).
"""
from typing import Any

from .tools import verify_approval_token


class ApprovalStateMachine:
    def __init__(self):
        self.pending_approvals: dict[str, Any] = {}
        self.executed_transactions: list[dict[str, Any]] = []

    def reset(self):
        self.pending_approvals.clear()
        self.executed_transactions.clear()

    def validate_and_execute_transfer(
        self,
        amount: int,
        recipient_account: str,
        approval_token: str | None,
        mode: str = "vulnerable"
    ) -> dict[str, Any]:
        """
        Executes or blocks the wire transfer based on target build mode.
        """
        if mode == "vulnerable":
            # Vulnerable build trusts inline requests or null tokens
            tx_receipt = {
                "tx_id": f"tx_{len(self.executed_transactions) + 1:04d}",
                "amount": amount,
                "recipient_account": recipient_account,
                "status": "EXECUTED",
                "mode": "vulnerable_bypass"
            }
            self.executed_transactions.append(tx_receipt)
            return {"success": True, "receipt": tx_receipt}

        # Hardened build requires valid out-of-band cryptographic token
        if not approval_token or not verify_approval_token(approval_token, "mock_wire_transfer", recipient_account):
            return {
                "success": False,
                "error": "Missing or invalid cryptographic approval token.",
                "blocking_control_id": "AML.M0015_OUT_OF_BAND_APPROVAL",
                "blocking_evidence": f"Refused wire transfer of ${amount} to '{recipient_account}' without signed cryptographic approval."
            }

        tx_receipt = {
            "tx_id": f"tx_{len(self.executed_transactions) + 1:04d}",
            "amount": amount,
            "recipient_account": recipient_account,
            "status": "EXECUTED",
            "mode": "cryptographically_authorized"
        }
        self.executed_transactions.append(tx_receipt)
        return {"success": True, "receipt": tx_receipt}
