-- Remove OAuth-specific fields from clients table
DROP INDEX IF EXISTS idx_clients_token_auth_method;
DROP INDEX IF EXISTS idx_clients_pkce_required;

ALTER TABLE clients 
DROP COLUMN IF EXISTS refresh_token_lifetime,
DROP COLUMN IF EXISTS access_token_lifetime,
DROP COLUMN IF EXISTS token_endpoint_auth_method,
DROP COLUMN IF EXISTS pkce_required;
