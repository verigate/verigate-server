-- Add OAuth-specific fields to clients table
ALTER TABLE clients
ADD COLUMN pkce_required BOOLEAN NOT NULL DEFAULT FALSE,
ADD COLUMN token_endpoint_auth_method VARCHAR(255) NOT NULL DEFAULT 'client_secret_basic',
ADD COLUMN access_token_lifetime INTEGER NOT NULL DEFAULT 3600,
ADD COLUMN refresh_token_lifetime INTEGER NOT NULL DEFAULT 604800;

-- Add indexes for performance
CREATE INDEX idx_clients_pkce_required ON clients (pkce_required);

CREATE INDEX idx_clients_token_auth_method ON clients (token_endpoint_auth_method);