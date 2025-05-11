CREATE TABLE IF NOT EXISTS clients (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL UNIQUE,
    client_secret VARCHAR(255) NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    description TEXT,
    client_uri VARCHAR(512),
    logo_uri VARCHAR(512),
    redirect_uris TEXT[] NOT NULL,
    grant_types VARCHAR(255)[] NOT NULL,
    response_types VARCHAR(255)[],
    scope TEXT NOT NULL,
    tos_uri VARCHAR(512),
    policy_uri VARCHAR(512),
    jwks_uri VARCHAR(512),
    jwks TEXT,
    contacts TEXT[],
    software_id VARCHAR(255),
    software_version VARCHAR(255),
    is_confidential BOOLEAN NOT NULL DEFAULT TRUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_clients_client_id ON clients(client_id);
CREATE INDEX idx_clients_owner_id ON clients(owner_id);
