-- ====================================================================
-- PostgreSQL Schema for AI Threat Scenario Generator & Prompt Corpus
-- ====================================================================

-- 1. Scenarios Table (20 Canonical Threat Specifications)
CREATE TABLE IF NOT EXISTS scenarios (
    scenario_id VARCHAR(128) PRIMARY KEY,
    spec_id VARCHAR(32) NOT NULL UNIQUE,
    attack_family VARCHAR(32) NOT NULL,
    version VARCHAR(32) NOT NULL,
    legitimate_goal TEXT NOT NULL,
    attacker_goal TEXT NOT NULL,
    canonical_attack_prompt TEXT NOT NULL,
    canonical_benign_prompt TEXT NOT NULL,
    target_profile_id VARCHAR(64) NOT NULL,
    review_status VARCHAR(32) NOT NULL,
    atlas_mappings JSONB,
    source_refs JSONB,
    source_facts JSONB,
    budgets JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. Prompts Table (360 Litmus Corpus Records: 240 Attacks + 120 Benign Controls)
CREATE TABLE IF NOT EXISTS prompts (
    record_id VARCHAR(128) PRIMARY KEY,
    spec_id VARCHAR(32) NOT NULL REFERENCES scenarios(spec_id) ON DELETE CASCADE,
    attack_family VARCHAR(32) NOT NULL,
    record_type VARCHAR(64) NOT NULL,
    split VARCHAR(32) NOT NULL,
    payload_text TEXT NOT NULL,
    payload_bytes TEXT NOT NULL,
    content_hash VARCHAR(64) NOT NULL UNIQUE,
    logical_variant_key VARCHAR(128) NOT NULL UNIQUE,
    injection_surface VARCHAR(64) NOT NULL,
    target_surface VARCHAR(32) NOT NULL,
    expected_control VARCHAR(128),
    seed INTEGER NOT NULL,
    assumptions TEXT,
    severity_rationale TEXT,
    source_ids JSONB,
    scenario_version VARCHAR(32) NOT NULL,
    generator_version VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 3. Indexes for High-Performance Querying & Filtering
CREATE INDEX IF NOT EXISTS idx_prompts_family ON prompts(attack_family);
CREATE INDEX IF NOT EXISTS idx_prompts_type ON prompts(record_type);
CREATE INDEX IF NOT EXISTS idx_prompts_split ON prompts(split);
CREATE INDEX IF NOT EXISTS idx_prompts_spec ON prompts(spec_id);
CREATE INDEX IF NOT EXISTS idx_prompts_content_hash ON prompts(content_hash);

-- 4. Full-Text Search Index on Prompt Text
CREATE INDEX IF NOT EXISTS idx_prompts_payload_search ON prompts USING gin(to_tsvector('english', payload_text));
