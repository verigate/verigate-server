// Package token provides functionality for OAuth token management.
package token

import "time"

// TokenInfo represents concise information about a token for API responses.
type TokenInfo struct {
	ID        string    `json:"id"`         // Token identifier
	ClientID  string    `json:"client_id"`  // OAuth client identifier
	UserID    uint      `json:"user_id"`    // User the token was issued to
	Scope     string    `json:"scope"`      // Space-separated list of OAuth scopes
	ExpiresAt time.Time `json:"expires_at"` // Expiration timestamp
	CreatedAt time.Time `json:"created_at"` // Creation timestamp
	IsRevoked bool      `json:"is_revoked"` // Whether the token has been revoked
}

// TokenListResponse wraps a paginated list of tokens for API responses.
type TokenListResponse struct {
	Tokens  []TokenInfo `json:"tokens"`   // List of tokens
	Total   int64       `json:"total"`    // Total number of tokens matching the query
	Page    int         `json:"page"`     // Current page number
	PerPage int         `json:"per_page"` // Number of tokens per page
}

// TokenCreateResponse represents the data returned when creating new OAuth tokens.
// Format follows the OAuth 2.0 specification.
type TokenCreateResponse struct {
	AccessToken  string `json:"access_token"`            // JWT access token
	TokenType    string `json:"token_type"`              // Always "Bearer"
	ExpiresIn    int    `json:"expires_in"`              // Time in seconds until the token expires
	RefreshToken string `json:"refresh_token,omitempty"` // Refresh token for obtaining new access tokens
	Scope        string `json:"scope,omitempty"`         // Space-separated list of granted scopes
}
