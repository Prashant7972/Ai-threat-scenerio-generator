"""
Database Exporter for Prompts & Scenarios (PostgreSQL & SQLite).
Loads the 20 Scenario Specs and all 360 Litmus Corpus Prompts into the database.
"""
import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime, timezone

from sqlalchemy import (
    create_engine,
    Column,
    String,
    Text,
    Integer,
    DateTime,
    JSON,
    ForeignKey,
    select,
    func
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

# Setup project path
ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.generator.auto_generator import compile_all_scenarios

Base = declarative_base()

class ScenarioModel(Base):
    __tablename__ = "scenarios"

    scenario_id = Column(String(128), primary_key=True)
    spec_id = Column(String(32), unique=True, nullable=False, index=True)
    attack_family = Column(String(32), nullable=False, index=True)
    version = Column(String(32), nullable=False)
    legitimate_goal = Column(Text, nullable=False)
    attacker_goal = Column(Text, nullable=False)
    canonical_attack_prompt = Column(Text, nullable=False)
    canonical_benign_prompt = Column(Text, nullable=False)
    target_profile_id = Column(String(64), nullable=False)
    review_status = Column(String(32), nullable=False)
    atlas_mappings = Column(JSON, nullable=True)
    source_refs = Column(JSON, nullable=True)
    source_facts = Column(JSON, nullable=True)
    budgets = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    prompts = relationship("PromptModel", back_populates="scenario", cascade="all, delete-orphan")


class PromptModel(Base):
    __tablename__ = "prompts"

    record_id = Column(String(128), primary_key=True)
    spec_id = Column(String(32), ForeignKey("scenarios.spec_id", ondelete="CASCADE"), nullable=False, index=True)
    attack_family = Column(String(32), nullable=False, index=True)
    record_type = Column(String(64), nullable=False, index=True)
    split = Column(String(32), nullable=False, index=True)
    payload_text = Column(Text, nullable=False)
    payload_bytes = Column(Text, nullable=False)
    content_hash = Column(String(64), unique=True, nullable=False, index=True)
    logical_variant_key = Column(String(128), unique=True, nullable=False)
    injection_surface = Column(String(64), nullable=False)
    target_surface = Column(String(32), nullable=False)
    expected_control = Column(String(128), nullable=True)
    seed = Column(Integer, nullable=False)
    assumptions = Column(Text, nullable=True)
    severity_rationale = Column(Text, nullable=True)
    source_ids = Column(JSON, nullable=True)
    scenario_version = Column(String(32), nullable=False)
    generator_version = Column(String(32), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scenario = relationship("ScenarioModel", back_populates="prompts")


def export_data(db_url: str):
    print(f"Connecting to database: {db_url.split('@')[-1] if '@' in db_url else db_url}")
    engine = create_engine(db_url, echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    try:
        # 1. Insert/Update Scenarios
        scenarios_compiled = compile_all_scenarios()
        print(f"Found {len(scenarios_compiled)} scenario specs.")
        for s in scenarios_compiled:
            spec_dict = s.model_dump(mode="json")
            spec_id = s.scenario_id.split(".")[-1]
            existing = session.get(ScenarioModel, s.scenario_id)
            if not existing:
                existing = ScenarioModel(
                    scenario_id=s.scenario_id,
                    spec_id=spec_id,
                    attack_family=s.attack_family.value if hasattr(s.attack_family, "value") else str(s.attack_family),
                    version=s.version,
                    legitimate_goal=s.legitimate_goal,
                    attacker_goal=s.attacker_goal,
                    canonical_attack_prompt=s.canonical_attack_prompt,
                    canonical_benign_prompt=s.canonical_benign_prompt,
                    target_profile_id=s.target_profile.id,
                    review_status=s.review.status,
                    atlas_mappings=spec_dict.get("atlas_mappings", []),
                    source_refs=spec_dict.get("source_refs", []),
                    source_facts=spec_dict.get("source_facts", []),
                    budgets=spec_dict.get("budgets", {}),
                )
                session.add(existing)
            else:
                existing.legitimate_goal = s.legitimate_goal
                existing.attacker_goal = s.attacker_goal
                existing.canonical_attack_prompt = s.canonical_attack_prompt
                existing.canonical_benign_prompt = s.canonical_benign_prompt
                existing.review_status = s.review.status
                existing.budgets = spec_dict.get("budgets", {})

        session.commit()
        print(f"✓ Successfully stored 20 scenarios in 'scenarios' table.")

        # 2. Insert/Update Prompts from Litmus Corpus
        corpus_path = ROOT / "data" / "litmus" / "litmus_360.jsonl"
        with open(corpus_path, encoding="utf-8") as f:
            records = [json.loads(line) for line in f]

        print(f"Found {len(records)} prompt records in {corpus_path.name}.")
        inserted_prompts = 0
        updated_prompts = 0

        for r in records:
            p = session.get(PromptModel, r["record_id"])
            if not p:
                p = PromptModel(
                    record_id=r["record_id"],
                    spec_id=r["spec_id"],
                    attack_family=r["attack_family"],
                    record_type=r["record_type"],
                    split=r["split"],
                    payload_text=r["payload_text"],
                    payload_bytes=r["payload_bytes"],
                    content_hash=r["content_hash"],
                    logical_variant_key=r["logical_variant_key"],
                    injection_surface=r["injection_surface"],
                    target_surface=r["target_surface"],
                    expected_control=r.get("expected_control"),
                    seed=r["seed"],
                    assumptions=r.get("assumptions"),
                    severity_rationale=r.get("severity_rationale"),
                    source_ids=r.get("source_ids", []),
                    scenario_version=r["scenario_version"],
                    generator_version=r["generator_version"]
                )
                session.add(p)
                inserted_prompts += 1
            else:
                p.payload_text = r["payload_text"]
                p.payload_bytes = r["payload_bytes"]
                p.content_hash = r["content_hash"]
                p.logical_variant_key = r["logical_variant_key"]
                p.seed = r["seed"]
                p.expected_control = r.get("expected_control")
                updated_prompts += 1

        session.commit()
        print(f"✓ Successfully stored prompts in 'prompts' table ({inserted_prompts} inserted, {updated_prompts} updated).")

        # 3. Validation query
        total_scenarios = session.scalar(select(func.count(ScenarioModel.scenario_id)))
        total_prompts = session.scalar(select(func.count(PromptModel.record_id)))
        attacks = session.scalar(select(func.count(PromptModel.record_id)).where(PromptModel.record_type == "attacker_injection"))
        benign = total_prompts - attacks

        print("\n--- DATABASE VERIFICATION SUMMARY ---")
        print(f"Total Scenarios: {total_scenarios}")
        print(f"Total Prompts:   {total_prompts}")
        print(f"  - Attack Injections: {attacks}")
        print(f"  - Benign Controls:   {benign}")
        print("--------------------------------------\n")

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def main():
    parser = argparse.ArgumentParser(description="Export Threat Scenarios & Prompts to PostgreSQL / SQLite")
    default_url = os.environ.get("DATABASE_URL", "sqlite:///prompts.db")
    parser.add_argument(
        "--db-url",
        default=default_url,
        help="SQLAlchemy database URL (e.g. postgresql://user:pass@localhost:5432/dbname or sqlite:///prompts.db)"
    )
    args = parser.parse_args()
    export_data(args.db_url)


if __name__ == "__main__":
    main()
