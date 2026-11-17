"""
Memory and Shared Artifact Store for Reference Application R3 (SIM 01, Families F3 & F4).
"""
from typing import Any


class AgentMemoryStore:
    def __init__(self):
        self.rolling_summary: str = ""
        self.persistent_instructions: list[str] = []
        self.shared_artifacts: dict[str, Any] = {}

    def reset(self):
        self.rolling_summary = "Initial session established with default operator role."
        self.persistent_instructions = ["Respect user privacy", "Validate inputs before action"]
        self.shared_artifacts = {}

    def update_summary(self, new_summary: str):
        self.rolling_summary = new_summary

    def add_persistent_instruction(self, inst: str):
        self.persistent_instructions.append(inst)

    def write_artifact(self, artifact_name: str, content: Any):
        self.shared_artifacts[artifact_name] = content

    def read_artifact(self, artifact_name: str) -> Any | None:
        return self.shared_artifacts.get(artifact_name)
