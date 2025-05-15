// Package token provides functionality for OAuth token management.
package token

import (
	"time"
)

// AccessToken represents an OAuth access token stored in the database.
type AccessToken struct {
	ID        uint      `json:"id"`         // Primary key
	TokenID   string    `json:"token_id"`   // Unique identifier (UUID) for the token
	TokenHash string    `json:"-"`          // Hashed token value, not exposed in JSON
	ClientID  string    `json:"client_id"`  // OAuth client identifier
	UserID    uint      `json:"user_id"`    // User the token was issued to
	Scope     string    `json:"scope"`      // Space-separated list of OAuth scopes
	ExpiresAt time.Time `json:"expires_at"` // Expiration timestamp
	CreatedAt time.Time `json:"created_at"` // Creation timestamp
	IsRevoked bool      `json:"is_revoked"` // Whether the token has been revoked
}

// RefreshToken represents an OAuth refresh token stored in the database.
type RefreshToken struct {
	ID            uint      `json:"id"`              // Primary key
	TokenID       string    `json:"token_id"`        // Unique identifier (UUID) for the token
	TokenHash     string    `json:"-"`               // Hashed token value, not exposed in JSON
	AccessTokenID string    `json:"access_token_id"` // Related access token ID
	ClientID      string    `json:"client_id"`       // OAuth client identifier
	UserID        uint      `json:"user_id"`         // User the token was issued to
	Scope         string    `json:"scope"`           // Space-separated list of OAuth scopes
	ExpiresAt     time.Time `json:"expires_at"`      // Expiration timestamp
	CreatedAt     time.Time `json:"created_at"`      // Creation timestamp
	IsRevoked     bool      `json:"is_revoked"`      // Whether the token has been revoked
}
