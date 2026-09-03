CREATE TABLE verification_codes (
    id          UUID PRIMARY KEY,
    email       VARCHAR(255) NOT NULL,
    code_hash   VARCHAR(64) NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    attempts    INT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Looked up by email on every /auth/verify-code call, most recent first.
CREATE INDEX idx_verification_codes_email_created_at ON verification_codes (email, created_at DESC);
