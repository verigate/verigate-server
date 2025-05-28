// Package client provides functionality for managing OAuth clients,
// including registration, configuration, and permission management.
package client

import "time"

// CreateClientRequest represents the data required to create a new OAuth client.
// It contains all the client metadata required for OAuth 2.0 client registration.
type CreateClientRequest struct {
	ClientName                 string   `json:"client_name" binding:"required"`
	Description                string   `json:"description"`
	ClientURI                  string   `json:"client_uri"`
	LogoURI                    string   `json:"logo_uri"`
	RedirectURIs               []string `json:"redirect_uris" binding:"required,min=1"`
	GrantTypes                 []string `json:"grant_types" binding:"required,min=1"`
	ResponseTypes              []string `json:"response_types"`
	Scope                      string   `json:"scope" binding:"required"`
	TOSUri                     string   `json:"tos_uri"`
	PolicyURI                  string   `json:"policy_uri"`
	JwksURI                    string   `json:"jwks_uri"`
	Jwks                       string   `json:"jwks"`
	Contacts                   []string `json:"contacts"`
	SoftwareID                 string   `json:"software_id"`
	SoftwareVersion            string   `json:"software_version"`
	IsConfidential             bool     `json:"is_confidential"`
	PKCERequired               bool     `json:"pkce_required"`
	TokenEndpointAuthMethod    string   `json:"token_endpoint_auth_method"`
	AccessTokenLifetime        int      `json:"access_token_lifetime"`        // in seconds
	RefreshTokenLifetime       int      `json:"refresh_token_lifetime"`       // in seconds
}

// UpdateClientRequest represents the data used to update an existing OAuth client.
// All fields are optional - only non-empty fields will be updated.
type UpdateClientRequest struct {
	ClientName                 string   `json:"client_name"`
	Description                string   `json:"description"`
	ClientURI                  string   `json:"client_uri"`
	LogoURI                    string   `json:"logo_uri"`
	RedirectURIs               []string `json:"redirect_uris"`
	GrantTypes                 []string `json:"grant_types"`
	ResponseTypes              []string `json:"response_types"`
	Scope                      string   `json:"scope"`
	TOSUri                     string   `json:"tos_uri"`
	PolicyURI                  string   `json:"policy_uri"`
	JwksURI                    string   `json:"jwks_uri"`
	Jwks                       string   `json:"jwks"`
	Contacts                   []string `json:"contacts"`
	SoftwareID                 string   `json:"software_id"`
	SoftwareVersion            string   `json:"software_version"`
	PKCERequired               bool     `json:"pkce_required"`
	TokenEndpointAuthMethod    string   `json:"token_endpoint_auth_method"`
	AccessTokenLifetime        int      `json:"access_token_lifetime"`        // in seconds
	RefreshTokenLifetime       int      `json:"refresh_token_lifetime"`       // in seconds
}

// ClientResponse represents an OAuth client response returned to API consumers.
// It contains all client metadata but only includes the client secret when
// initially created (it cannot be retrieved later).
type ClientResponse struct {
	ID                         uint      `json:"id"`
	ClientID                   string    `json:"client_id"`
	ClientSecret               string    `json:"client_secret,omitempty"`
	ClientName                 string    `json:"client_name"`
	Description                string    `json:"description,omitempty"`
	ClientURI                  string    `json:"client_uri,omitempty"`
	LogoURI                    string    `json:"logo_uri,omitempty"`
	RedirectURIs               []string  `json:"redirect_uris"`
	GrantTypes                 []string  `json:"grant_types"`
	ResponseTypes              []string  `json:"response_types,omitempty"`
	Scope                      string    `json:"scope"`
	TOSUri                     string    `json:"tos_uri,omitempty"`
	PolicyURI                  string    `json:"policy_uri,omitempty"`
	IsConfidential             bool      `json:"is_confidential"`
	PKCERequired               bool      `json:"pkce_required"`
	TokenEndpointAuthMethod    string    `json:"token_endpoint_auth_method"`
	AccessTokenLifetime        int       `json:"access_token_lifetime"`        // in seconds
	RefreshTokenLifetime       int       `json:"refresh_token_lifetime"`       // in seconds
	IsActive                   bool      `json:"is_active"`
	CreatedAt                  time.Time `json:"created_at"`
	UpdatedAt                  time.Time `json:"updated_at"`
}

// ClientListResponse represents a paginated list of OAuth clients.
// It includes pagination metadata and the list of clients for the current page.
type ClientListResponse struct {
	Clients []ClientResponse `json:"clients"`  // The list of client objects for the current page
	Total   int64            `json:"total"`    // The total number of clients across all pages
	Page    int              `json:"page"`     // The current page number (1-indexed)
	PerPage int              `json:"per_page"` // The number of items per page
}
