CREATE TABLE dns_predictions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID NOT NULL REFERENCES dns_observations(id),
    model_version TEXT NOT NULL CHECK (model_version ~ '^[0-9a-f]{64}$'),
    result JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (snapshot_id, model_version)
);
CREATE INDEX dns_predictions_created_idx ON dns_predictions (created_at DESC, id DESC);
