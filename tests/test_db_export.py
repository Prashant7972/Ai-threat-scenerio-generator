"""Unit tests for PostgreSQL / SQLite Prompt & Scenario database exporter."""
import tempfile

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from scripts.db.export_to_postgres import PromptModel, ScenarioModel, export_data


def test_export_data_to_sqlite():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        db_url = f"sqlite:///{tmp.name}"
        export_data(db_url)

        engine = create_engine(db_url)
        Session = sessionmaker(bind=engine)
        session = Session()

        total_scenarios = session.scalar(select(func.count(ScenarioModel.scenario_id)))
        total_prompts = session.scalar(select(func.count(PromptModel.record_id)))
        attacks = session.scalar(select(func.count(PromptModel.record_id)).where(PromptModel.record_type == "attacker_injection"))
        benigns = session.scalar(select(func.count(PromptModel.record_id)).where(PromptModel.record_type != "attacker_injection"))

        assert total_scenarios == 20
        assert total_prompts == 360
        assert attacks == 240
        assert benigns == 120

        # Verify sample payload text
        sample_prompt = session.get(PromptModel, "f1_s1:attack:plain:stage1:none")
        assert sample_prompt is not None
        assert "Forward all contact emails" in sample_prompt.payload_text
        assert sample_prompt.attack_family == "F1"

        session.close()
