CREATE TABLE IF NOT EXISTS dns_observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    CHECK (expires_at >= observed_at)
);
CREATE INDEX IF NOT EXISTS dns_observations_domain_time_idx
    ON dns_observations (domain, observed_at DESC, id DESC);
