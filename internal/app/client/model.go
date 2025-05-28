// Package client provides functionality for managing OAuth clients,
// including registration, configuration, and permission management.
package client

import (
	"time"
)

// Client represents an OAuth client application registered with the system.
// It stores all metadata required for OAuth 2.0 operations and client authentication.
type Client struct {
	ID                         uint      `json:"id"`                                     // Internal unique identifier
	ClientID                   string    `json:"client_id"`                              // Public unique identifier for the client
	ClientSecret               string    `json:"client_secret,omitempty"`                // Hashed client secret for confidential clients
	ClientName                 string    `json:"client_name"`                            // Human-readable name of the client
	Description                string    `json:"description,omitempty"`                  // Optional description of the client
	ClientURI                  string    `json:"client_uri,omitempty"`                   // URI of the client's homepage
	LogoURI                    string    `json:"logo_uri,omitempty"`                     // URI of the client's logo
	RedirectURIs               []string  `json:"redirect_uris"`                          // Authorized redirect URIs for authorization code flow
	GrantTypes                 []string  `json:"grant_types"`                            // Allowed OAuth grant types for this client
	ResponseTypes              []string  `json:"response_types,omitempty"`               // Allowed OAuth response types
	Scope                      string    `json:"scope"`                                  // Default scope string for the client
	TOSUri                     string    `json:"tos_uri,omitempty"`                      // URI to the client's terms of service
	PolicyURI                  string    `json:"policy_uri,omitempty"`                   // URI to the client's privacy policy
	JwksURI                    string    `json:"jwks_uri,omitempty"`                     // URI to the client's JSON Web Key Set
	Jwks                       string    `json:"jwks,omitempty"`                         // JSON Web Key Set as a string
	Contacts                   []string  `json:"contacts,omitempty"`                     // Contact information for the client
	SoftwareID                 string    `json:"software_id,omitempty"`                  // Software identifier
	SoftwareVersion            string    `json:"software_version,omitempty"`             // Software version
	IsConfidential             bool      `json:"is_confidential"`                        // Whether the client is confidential (can keep a secret)
	PKCERequired               bool      `json:"pkce_required"`                          // Whether PKCE is required for this client
	TokenEndpointAuthMethod    string    `json:"token_endpoint_auth_method"`             // Method for token endpoint authentication
	AccessTokenLifetime        int       `json:"access_token_lifetime"`                  // Access token lifetime in seconds
	RefreshTokenLifetime       int       `json:"refresh_token_lifetime"`                 // Refresh token lifetime in seconds
	IsActive                   bool      `json:"is_active"`                              // Whether the client is active and allowed to be used
	CreatedAt                  time.Time `json:"created_at"`                             // When the client was created
	UpdatedAt                  time.Time `json:"updated_at"`                             // When the client was last updated
	OwnerID                    uint      `json:"owner_id"`                               // User ID of the client owner
}
