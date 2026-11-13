"""
Scenario Compiler & Generator Package (GEN 01–05).
The authoritative engine for threat modeling, scenario compilation, and Litmus corpus materialization.
"""
from .contract import (
    MinimumScenarioContract,
    LitmusRecord,
    RecordType,
    AttackFamily,
    TargetSurface,
    OriginType,
    Disposition,
    TrialOutcome
)
from .mutations import apply_mutation, MUTATION_OPERATORS
from .snapshot import materialize_spec_records, export_litmus_records
from .auto_generator import compile_all_scenarios, export_all_scenario_yamls, generate_litmus_corpus
from .harness_generator import SafeHarnessPackage
from .provenance import classify_provenance_diff, DiffClassification

__all__ = [
    "MinimumScenarioContract",
    "LitmusRecord",
    "RecordType",
    "AttackFamily",
    "TargetSurface",
    "OriginType",
    "Disposition",
    "TrialOutcome",
    "apply_mutation",
    "MUTATION_OPERATORS",
    "materialize_spec_records",
    "export_litmus_records",
    "compile_all_scenarios",
    "export_all_scenario_yamls",
    "generate_litmus_corpus",
    "SafeHarnessPackage",
    "classify_provenance_diff",
    "DiffClassification",
]
