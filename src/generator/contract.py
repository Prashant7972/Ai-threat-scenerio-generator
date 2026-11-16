"""
Minimum Scenario Contract and Litmus Schemas (GEN 01, GEN 04).
Strictly enforces the Rescoped Requirements schema.
"""
from typing import List, Dict, Any, Optional, Literal
from enum import Enum
from pydantic import BaseModel, Field, field_validator, model_validator
import hashlib

class OriginType(str, Enum):
    OBSERVED = "observed"
    ADAPTATION = "adaptation"

class RecordType(str, Enum):
    LEGITIMATE_USER_TASK = "legitimate_user_task"
    ATTACKER_INJECTION = "attacker_injection"
    BENIGN_CONTROL = "benign_control"
    EXERCISE_PROBE = "exercise_probe"

class AttackFamily(str, Enum):
    F1 = "F1"  # Retrieved content injection
    F2 = "F2"  # Tool misuse
    F3 = "F3"  # Multi-agent trust
    F4 = "F4"  # State and context
    F5 = "F5"  # Bundled prompt logic

class TargetSurface(str, Enum):
    R1 = "R1"  # RAG assistant
    R2 = "R2"  # Tool-using assistant
    R3 = "R3"  # Two-agent planner/executor

class InjectionSurface(str, Enum):
    # F1: Retrieved content
    RETRIEVAL_FIXTURE = "retrieval_fixture"
    # F2: Tool misuse & approvals
    TOOL_ARGUMENTS = "tool_arguments"
    TOOL_RESPONSE = "tool_response"
    APPROVAL_STATE = "approval_state"
    # F3: Multi-agent coordination
    PEER_AGENT_MESSAGE = "peer_agent_message"
    SHARED_ARTIFACT = "shared_artifact"
    # F4: State & context
    MEMORY_SUMMARY = "memory_summary"
    LONG_CONTEXT = "long_context"
    # F5: Bundled prompts & configurations
    CHAT_TEMPLATE = "chat_template"
    CONFIGURATION = "configuration"

class Disposition(str, Enum):
    PROVIDER_REFUSAL = "provider_refusal"
    APPLICATION_REJECTION = "application_rejection"
    SEPTA_BLOCK = "septa_block"
    OTHER_CONTROL_BLOCK = "other_control_block"
    RETRIEVAL_EXCLUSION = "retrieval_exclusion"
    INEFFECTIVE_PAYLOAD = "ineffective_payload"
    UNSUPPORTED_PRECONDITION = "unsupported_precondition"
    INFRASTRUCTURE_ERROR = "infrastructure_error"
    TIMEOUT = "timeout"
    BUDGET_EXHAUSTED = "budget_exhausted"
    EVALUATOR_ERROR = "evaluator_error"
    INCONCLUSIVE = "inconclusive"

class TrialOutcome(str, Enum):
    ATTACK_SUCCESS = "attack_success"
    BENIGN_SUCCESS = "benign_success"
    BLOCKED_OR_FAILED = "blocked_or_failed"

# ----------------- Minimum Scenario Contract Models (GEN 01) -----------------

class SourceRef(BaseModel):
    record_id: str
    revision: str
    locator: str

class SourceFact(BaseModel):
    claim_id: str

class AtlasMapping(BaseModel):
    id: str
    taxonomy_version: str
    method: str

class TargetProfileRef(BaseModel):
    id: str
    version: str = "1.0.0"

class AttackerAccess(BaseModel):
    surface: str
    allowed_mutations: List[str]

    @field_validator("allowed_mutations")
    @classmethod
    def validate_mutations(cls, v: List[str]) -> List[str]:
        valid_operators = {
            "authority_claims",
            "benign_task_dependency_traps",
            "multi_turn_placement",
            "carrier_changes",
            "peer_agent_relay",
            "context_length",
            "template_or_configuration_changes"
        }
        for op in v:
            if op not in valid_operators:
                raise ValueError(f"Unauthorized mutation operator '{op}'. Must be one of {valid_operators}")
        return v

class GeneratorRef(BaseModel):
    id: str
    version: str = "1.0.0"
    parameters: Dict[str, Any] = Field(default_factory=dict)

class VariantSpec(BaseModel):
    dimensions: Dict[str, Any] = Field(default_factory=dict)
    selection_method: str = "boundary_coverage"
    seed: int = 42

class FixtureRef(BaseModel):
    uri: str
    sha256: str

class AssertionContract(BaseModel):
    id: str
    event_predicate: Dict[str, Any]
    expected: Dict[str, Any]

class BenignControlContract(BaseModel):
    fixture_ref: str
    expected_task_outcome: Dict[str, Any]

class BudgetsContract(BaseModel):
    turns: int = Field(default=10, gt=0, le=10)
    tool_calls: int = Field(default=20, gt=0, le=20)
    tokens: int = Field(default=20000, gt=0, le=20000)
    seconds: int = Field(default=300, gt=0, le=300)

class ReviewContract(BaseModel):
    status: str = "candidate"
    reviewer: str = ""
    timestamp: str = ""

class MinimumScenarioContract(BaseModel):
    """
    The exact Minimum Scenario Contract defined in Rescoped Requirements GEN 01.
    """
    scenario_id: str
    version: str = "1.0.0"
    source_refs: List[SourceRef] = Field(default_factory=list)
    source_facts: List[SourceFact] = Field(default_factory=list)
    generated_assumptions: List[str] = Field(default_factory=list)
    atlas_mappings: List[AtlasMapping] = Field(default_factory=list)
    target_profile: TargetProfileRef
    legitimate_goal: str
    attacker_goal: str
    attacker_access: AttackerAccess
    preconditions: List[str] = Field(default_factory=list)
    generator: GeneratorRef = Field(default_factory=GeneratorRef)
    variants: VariantSpec = Field(default_factory=VariantSpec)
    fixtures: List[FixtureRef] = Field(default_factory=list)
    assertions: List[AssertionContract] = Field(..., min_length=1)
    benign_control: BenignControlContract
    budgets: BudgetsContract = Field(default_factory=BudgetsContract)
    review: ReviewContract = Field(default_factory=ReviewContract)

    # Operational prompt fields for concrete test materialization
    attack_family: AttackFamily
    injection_surface: InjectionSurface = InjectionSurface.RETRIEVAL_FIXTURE
    origin_type: OriginType
    canonical_attack_prompt: str
    canonical_benign_prompt: str
    severity_rationale: str = ""

    @property
    def spec_id(self) -> str:
        # e.g., 'litmus.pattern.F1-S1' -> 'F1-S1'
        return self.scenario_id.split(".")[-1] if "." in self.scenario_id else self.scenario_id

    @property
    def target_surface(self) -> TargetSurface:
        return TargetSurface(self.target_profile.id)

    @property
    def allowed_mutation_scope(self) -> List[str]:
        return self.attacker_access.allowed_mutations

    @property
    def source_ids(self) -> List[str]:
        return [ref.record_id for ref in self.source_refs]

# ----------------- Litmus Corpus & Telemetry Models (GEN 04, SIM 03) -----------------

class LitmusRecord(BaseModel):
    record_id: str
    spec_id: str
    logical_variant_key: str
    record_type: RecordType
    attack_family: AttackFamily
    target_surface: TargetSurface
    injection_surface: InjectionSurface = InjectionSurface.RETRIEVAL_FIXTURE
    source_ids: List[str]
    assumptions: str
    severity_rationale: str
    scenario_version: str = "1.0.0"
    generator_version: str = "1.0.0"
    seed: int
    expected_control: Optional[str] = None
    split: Literal["train", "test", "canonical"] = "test"
    payload_text: str
    payload_bytes: Optional[str] = None
    content_hash: str = ""

    @model_validator(mode="after")
    def compute_and_verify_hash(self) -> "LitmusRecord":
        if self.payload_bytes is None:
            self.payload_bytes = self.payload_text.encode("utf-8").hex()
        if bytes.fromhex(self.payload_bytes) != self.payload_text.encode("utf-8"):
            raise ValueError("Stored payload bytes do not match payload_text")
        calculated_hash = hashlib.sha256(self.payload_text.encode("utf-8")).hexdigest()
        if not self.content_hash:
            self.content_hash = calculated_hash
        elif self.content_hash != calculated_hash:
            raise ValueError(f"Content hash mismatch: {self.content_hash} != {calculated_hash}")
        return self

class NetworkRequestRecord(BaseModel):
    destination_host: str
    destination_port: int
    method: str
    status_code: Optional[int] = None
    latency_ms: float = 0.0
    request_bytes: int = 0
    response_bytes: int = 0
    sanitized_url: str

class ToolEvent(BaseModel):
    parent_task: str
    actor_agent: str
    delegated_scope: str
    tool_name: str
    tool_arguments: Dict[str, Any]
    policy_decision: Literal["allow", "deny", "flag"]
    attempted_action: str
    proposed_action: Optional[Dict[str, Any]] = None
    executed_action: Optional[Dict[str, Any]] = None
    execution_receipt: Optional[Dict[str, Any]] = None
    result: Optional[Any] = None
    blocking_control_id: Optional[str] = None
    error: Optional[str] = None

class TelemetryRecord(BaseModel):
    trial_id: str
    spec_id: str
    logical_variant_key: str
    target_build: Literal["vulnerable", "hardened"]
    seed: int
    injection_surface: Optional[str] = None
    exposure_observed: Optional[bool] = None
    task_completion_observed: Optional[bool] = None
    redirection_observed: Optional[bool] = None
    observation_evidence: Dict[str, Any] = Field(default_factory=dict)
    model_requests: List[Dict[str, Any]] = Field(default_factory=list)
    proposed_actions: List[Dict[str, Any]] = Field(default_factory=list)
    executed_actions: List[Dict[str, Any]] = Field(default_factory=list)
    tool_events: List[ToolEvent] = Field(default_factory=list)
    renderer_requests: List[Dict[str, Any]] = Field(default_factory=list)
    canary_hits: List[str] = Field(default_factory=list)
    state_diffs: Dict[str, Any] = Field(default_factory=dict)
    network_requests: List[NetworkRequestRecord] = Field(default_factory=list)
    budget_metrics: Dict[str, Any] = Field(default_factory=dict)
    model_turns: int = 0
    total_tokens: int = 0
    wall_time_seconds: float = 0.0
    primary_outcome: TrialOutcome
    disposition: Optional[Disposition] = None
    blocking_control_id: Optional[str] = None
    blocking_evidence: Optional[str] = None
