CREATE TABLE IF NOT EXISTS scopes (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    is_default BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_consents (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    scope TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, client_id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    actor_id INTEGER,
    actor_type VARCHAR(50),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255),
    description TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) NOT NULL,
    additional_data JSONB
);

-- Insert default scopes
INSERT INTO
    scopes (name, description, is_default)
VALUES (
        'profile',
        'Access to user profile information',
        true
    ),
    (
        'email',
        'Access to user email address',
        true
    ),
    (
        'openid',
        'OpenID Connect support',
        false
    ),
    (
        'offline_access',
        'Access to refresh tokens',
        false
    );

CREATE INDEX idx_user_consents_user_id ON user_consents (user_id);

CREATE INDEX idx_user_consents_client_id ON user_consents (client_id);

CREATE INDEX idx_audit_logs_actor_id ON audit_logs (actor_id);

CREATE INDEX idx_audit_logs_resource_type_id ON audit_logs (resource_type, resource_id);

CREATE INDEX idx_audit_logs_created_at ON audit_logs (created_at);