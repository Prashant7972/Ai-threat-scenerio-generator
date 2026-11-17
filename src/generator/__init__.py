"""
Scenario Compiler & Generator Package (GEN 01–05).
The authoritative engine for threat modeling, scenario compilation, and Litmus corpus materialization.
"""
from .auto_generator import (
    compile_all_scenarios,
    export_all_scenario_yamls,
    generate_litmus_corpus,
)
from .contract import (
    AttackFamily,
    Disposition,
    LitmusRecord,
    MinimumScenarioContract,
    OriginType,
    RecordType,
    TargetSurface,
    TrialOutcome,
)
from .harness_generator import SafeHarnessPackage
from .mutations import MUTATION_OPERATORS, apply_mutation
from .provenance import DiffClassification, classify_provenance_diff
from .snapshot import export_litmus_records, materialize_spec_records

__all__ = [
    "MUTATION_OPERATORS",
    "AttackFamily",
    "DiffClassification",
    "Disposition",
    "LitmusRecord",
    "MinimumScenarioContract",
    "OriginType",
    "RecordType",
    "SafeHarnessPackage",
    "TargetSurface",
    "TrialOutcome",
    "apply_mutation",
    "classify_provenance_diff",
    "compile_all_scenarios",
    "export_all_scenario_yamls",
    "export_litmus_records",
    "generate_litmus_corpus",
    "materialize_spec_records",
]
