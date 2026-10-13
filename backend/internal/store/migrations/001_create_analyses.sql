CREATE TABLE IF NOT EXISTS analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    candidate_url TEXT NOT NULL,
    brand_name TEXT NOT NULL,
    brand_domain TEXT NOT NULL,
    impersonation_score DOUBLE PRECISION NOT NULL CHECK (impersonation_score >= 0 AND impersonation_score <= 1),
    result JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS analyses_created_at_idx ON analyses (created_at DESC);
