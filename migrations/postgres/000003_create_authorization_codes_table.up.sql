CREATE TABLE IF NOT EXISTS authorization_codes (
    id SERIAL PRIMARY KEY,
    code VARCHAR(255) NOT NULL UNIQUE,
    client_id VARCHAR(255) NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri VARCHAR(512) NOT NULL,
    scope TEXT NOT NULL,
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(20),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_used BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_auth_codes_code ON authorization_codes(code);
CREATE INDEX idx_auth_codes_client_id ON authorization_codes(client_id);
CREATE INDEX idx_auth_codes_user_id ON authorization_codes(user_id);
CREATE INDEX idx_auth_codes_expires_at ON authorization_codes(expires_at);
